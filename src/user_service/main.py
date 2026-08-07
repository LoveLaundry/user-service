from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Union

from .config import DB_TYPE, DatabaseType
from .repository import QuotationRepository
from .repository_factory import get_repository, close_connections
from .schemas import QuotationCreate, QuotationUpdate, QuotationResponse

app = FastAPI(title="User Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database schema for PostgreSQL/SQLite
if DB_TYPE in (DatabaseType.POSTGRESQL, DatabaseType.SQLITE):
    from .database import Base, engine
    if engine:
        Base.metadata.create_all(bind=engine)


@app.on_event("shutdown")
def shutdown_event():
    """Close database connections on shutdown"""
    close_connections()


@app.get("/")
def root():
    return {
        "message": "User Service API",
        "version": "1.0.0",
        "database": DB_TYPE.value
    }


@app.get("/quotations", response_model=list[QuotationResponse])
def get_all_quotations(repo: QuotationRepository = Depends(get_repository)):
    quotations = repo.get_all()
    return quotations


@app.get("/quotations/{quotation_id}", response_model=QuotationResponse)
def get_quotation(quotation_id: Union[int, str], repo: QuotationRepository = Depends(get_repository)):
    # MongoDB uses string IDs, PostgreSQL uses integers
    if DB_TYPE == DatabaseType.MONGODB:
        quotation = repo.get_by_id(str(quotation_id))
    else:
        quotation = repo.get_by_id(int(quotation_id))
    
    if not quotation:
        raise HTTPException(status_code=404, detail="Quotation not found")
    return quotation


@app.post("/quotations", response_model=QuotationResponse, status_code=201)
def create_quotation(payload: QuotationCreate, repo: QuotationRepository = Depends(get_repository)):
    line_items_data = [item.model_dump() for item in payload.line_items]
    
    quotation_data = {
        "client_name": payload.client_name,
        "quotation_title": payload.quotation_title,
        "line_items": line_items_data,
        "status": payload.status,
    }
    
    new_quotation = repo.create(quotation_data)
    return new_quotation


@app.put("/quotations/{quotation_id}", response_model=QuotationResponse)
def update_quotation(
    quotation_id: Union[int, str],
    payload: QuotationUpdate,
    repo: QuotationRepository = Depends(get_repository),
):
    # Convert quotation_id based on database type
    if DB_TYPE == DatabaseType.MONGODB:
        quotation_id = str(quotation_id)
    else:
        quotation_id = int(quotation_id)
    
    update_data = payload.model_dump(exclude_unset=True)
    
    if "line_items" in update_data and update_data["line_items"]:
        update_data["line_items"] = [
            item.model_dump() if hasattr(item, "model_dump") else item
            for item in update_data["line_items"]
        ]
    
    updated_quotation = repo.update(quotation_id, update_data)
    
    if not updated_quotation:
        raise HTTPException(status_code=404, detail="Quotation not found")
    
    return updated_quotation


@app.delete("/quotations/{quotation_id}")
def delete_quotation(quotation_id: Union[int, str], repo: QuotationRepository = Depends(get_repository)):
    # Convert quotation_id based on database type
    if DB_TYPE == DatabaseType.MONGODB:
        quotation_id = str(quotation_id)
    else:
        quotation_id = int(quotation_id)
    
    success = repo.delete(quotation_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Quotation not found")
    
    return {"message": "Quotation deleted successfully"}
