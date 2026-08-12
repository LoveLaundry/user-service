"""
Synchronization service - replicates MAIN changes to the SECONDARY
database using a durable queue, and verifies each replication.

Design:
    - Writes land in MAIN and enqueue a job in MAIN.sync_queue.
    - A background worker claims due jobs, copies the raw encrypted
      document from MAIN to SECONDARY, then verifies versions.
    - Failed jobs are retried with exponential backoff up to a limit,
      then marked FAILED permanently (still diagnosable via sync_logs).
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..config import (
    SYNC_ENABLED,
    SYNC_RETRY_BASE_DELAY_SECONDS,
    SYNC_RETRY_MAX_ATTEMPTS,
    SYNC_WORKER_POLL_SECONDS,
)
from ..database.main_db import sync_logs_collection, sync_queue_collection
from ..repositories.entity_registry import effective_version, get_main_collection
from ..repositories.secondary_repository import upsert_document
from . import verification_service

logger = logging.getLogger(__name__)

SYNC_OPERATION = "MAIN_TO_SECONDARY"
MAX_ATTEMPTS = SYNC_RETRY_MAX_ATTEMPTS


def enqueue(entity: str, record_id: Any, version: int) -> None:
    """Durable enqueue - upserts a PENDING job in MAIN.sync_queue."""
    now = datetime.now(timezone.utc)
    sync_queue_collection.update_one(
        {"entity": entity, "record_id": str(record_id)},
        {
            "$set": {
                "entity": entity,
                "record_id": str(record_id),
                "version": version,
                "status": "PENDING",
                "attempts": 0,
                "next_attempt_at": now,
                "updated_at": now,
            },
            "$setOnInsert": {"created_at": now},
        },
        upsert=True,
    )


def write_sync_log(
    operation: str,
    entity: Optional[str],
    record_id: Optional[str],
    status: str,
    started_at: datetime,
    completed_at: Optional[datetime] = None,
    error: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    entry = {
        "operation": operation,
        "entity": entity,
        "record_id": record_id,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "error": error,
        "created_at": datetime.now(timezone.utc),
    }
    if extra:
        entry.update(extra)
    sync_logs_collection.insert_one(entry)


def process_one(job: dict) -> str:
    """
    Replicate a single queued change from MAIN to SECONDARY and verify it.

    Returns "VERIFIED", "PENDING" (version mismatch), or raises so the
    caller can retry.
    """
    entity = job["entity"]
    record_id = job["record_id"]

    # 1. Read raw encrypted doc from MAIN
    main_collection = get_main_collection(entity)
    main_doc = main_collection.find_one({"_id": record_id})
    if main_doc is None:
        raise RuntimeError(f"Record {entity}/{record_id} no longer exists in MAIN")

    # 2. Copy to SECONDARY (raw copy preserves decryption metadata)
    upsert_document(entity, main_doc)

    # 3. Verify by version comparison
    main_version = effective_version(main_doc)
    return verification_service.verify_against_secondary(
        entity, record_id, main_version
    )


def attempt_job(job: dict) -> None:
    """Run/retry one job with backoff. Marks FAILED when attempts run out."""
    job_id = job.get("_id")
    entity = job["entity"]
    record_id = job["record_id"]
    attempts = int(job.get("attempts") or 0) + 1
    started_at = datetime.now(timezone.utc)

    verification_service.mark_syncing(entity, record_id, job.get("version") or 0)

    try:
        result_status = process_one(job)

        sync_queue_collection.delete_one({"_id": job_id})
        write_sync_log(
            operation=SYNC_OPERATION,
            entity=entity,
            record_id=record_id,
            status="SUCCESS",
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            error=None if result_status == "VERIFIED" else "Verified with version mismatch",
            extra={"result_status": result_status},
        )
    except Exception as exc:
        logger.warning("Sync failed for %s/%s (attempt %d): %s", entity, record_id, attempts, exc)

        if attempts >= MAX_ATTEMPTS:
            sync_queue_collection.update_one(
                {"_id": job_id},
                {"$set": {"status": "FAILED", "attempts": attempts, "updated_at": datetime.now(timezone.utc)}},
            )
            verification_service.mark_failed(
                entity, record_id, job.get("version") or 0, str(exc)
            )
            write_sync_log(
                operation=SYNC_OPERATION,
                entity=entity,
                record_id=record_id,
                status="FAILED",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error=str(exc),
                extra={"attempts": attempts},
            )
        else:
            backoff_seconds = SYNC_RETRY_BASE_DELAY_SECONDS * (2 ** (attempts - 1))
            sync_queue_collection.update_one(
                {"_id": job_id},
                {
                    "$set": {
                        "status": "PENDING",
                        "attempts": attempts,
                        "next_attempt_at": datetime.now(timezone.utc) + timedelta(seconds=backoff_seconds),
                        "error": str(exc),
                        "updated_at": datetime.now(timezone.utc),
                    }
                },
            )


def drain_due_jobs(limit: int = 50) -> int:
    """Process all jobs whose next_attempt_at has passed. Returns count processed."""
    cursor = (
        sync_queue_collection.find(
            {"status": "PENDING", "next_attempt_at": {"$lte": datetime.now(timezone.utc)}}
        )
        .sort("next_attempt_at", 1)
        .limit(limit)
    )

    processed = 0
    for job in cursor:
        attempt_job(job)
        processed += 1
    return processed


# ─── Background worker (thread-based, sync) ─────────────────────────────
_stop_event = threading.Event()
_worker_thread: Optional[threading.Thread] = None


def _worker_loop() -> None:
    """Background worker loop. Polls the durable queue and drains due jobs."""
    while not _stop_event.is_set():
        try:
            drain_due_jobs()
        except Exception as exc:
            logger.exception("Sync worker drain failed: %s", exc)
        time.sleep(SYNC_WORKER_POLL_SECONDS)


def start_worker() -> None:
    """Start the background sync worker thread (idempotent)."""
    global _worker_thread
    if not SYNC_ENABLED:
        return
    if _worker_thread is not None and _worker_thread.is_alive():
        return
    _stop_event.clear()
    _worker_thread = threading.Thread(target=_worker_loop, daemon=True, name="sync-worker")
    _worker_thread.start()


def stop_worker() -> None:
    """Stop the background sync worker thread."""
    global _worker_thread
    _stop_event.set()
    if _worker_thread is not None:
        _worker_thread.join(timeout=2)
        _worker_thread = None