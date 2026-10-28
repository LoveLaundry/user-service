# Entity Model Design: Hotels and Shops

## Overview

This document defines the full entity model for hotels and shops, extending the existing laundry multi-tenant architecture to support hotel and shop entities as first-class entities with their own administrators.

## Architecture Principles

1. **Entity-Based Access Control**: Every administrator is explicitly associated with one entity (hotel, shop, or laundry)
2. **Tenant Isolation**: All entity-specific data is scoped to the entity_id from JWT claims
3. **Platform Admin Authority**: Only Platform Admins can create entity administrators
4. **Data Ownership**: Entity administrators can only access their entity's data
5. **Backward Compatibility**: Existing operational data using `client_name` strings will be migrated to entity IDs

## Entity Collections

### 1. Hotels Collection (`hotels`)

```python
{
  "_id": ObjectId,
  "hotel_id": str,  # Unique slug (e.g., "hilton-colombo")
  "name": str,  # Display name (e.g., "Hilton Colombo")
  "hotel_code": str | None,  # Optional internal code
  "location": str | None,
  "address": str | None,
  "contact_number": str | None,
  "email": str | None,
  "logo_url": str | None,
  "icon": str | None,
  "description": str | None,
  "subscription_plan": str | None,
  "plan_limits": str | None,
  "associated_laundry_id": str,  # Which laundry this hotel belongs to
  "status": str,  # ACTIVE, SUSPENDED, ARCHIVED
  "created_by": str,  # Platform admin auth_id
  "created_at": datetime,
  "updated_at": datetime
}
```

**Indexes:**
- Unique on `hotel_id`
- Index on `associated_laundry_id`
- Index on `status`
- Index on `name`

### 2. Shops Collection (`shops`)

```python
{
  "_id": ObjectId,
  "shop_id": str,  # Unique slug (e.g., "city-express-shop")
  "name": str,  # Display name (e.g., "City Express Shop")
  "shop_code": str | None,
  "location": str | None,
  "address": str | None,
  "contact_number": str | None,
  "email": str | None,
  "logo_url": str | None,
  "icon": str | None,
  "description": str | None,
  "subscription_plan": str | None,
  "plan_limits": str | None,
  "associated_laundry_id": str,  # Which laundry this shop belongs to
  "status": str,  # ACTIVE, SUSPENDED, ARCHIVED
  "created_by": str,  # Platform admin auth_id
  "created_at": datetime,
  "updated_at": datetime
}
```

**Indexes:**
- Unique on `shop_id`
- Index on `associated_laundry_id`
- Index on `status`
- Index on `name`

## User Entity Associations

### Staff Users (existing `users` collection)

Staff users will have extended membership structure:

```python
{
  "laundries": [
    {
      "id": "laundry-slug",
      "name": "Laundry Name",
      "role": "ADMIN" | "MANAGER" | "STAFF",
      "status": "ACTIVE"
    }
  ],
  "hotels": [  # NEW
    {
      "id": "hotel-slug",
      "name": "Hotel Name",
      "role": "HOTEL_ADMIN" | "HOTEL_MANAGER",
      "status": "ACTIVE"
    }
  ],
  "shops": [  # NEW
    {
      "id": "shop-slug",
      "name": "Shop Name",
      "role": "SHOP_ADMIN" | "SHOP_STAFF",
      "status": "ACTIVE"
    }
  ]
}
```

### Client Accounts (existing `client_accounts` collection)

Client accounts will be enhanced with entity reference:

```python
{
  "laundry_id": str,
  "client_type": "HOTEL" | "SHOP",
  "hotel_id": str | None,  # NEW: Reference to hotels collection
  "shop_id": str | None,  # NEW: Reference to shops collection
  "client_name": str,  # Kept for backward compatibility during migration
  # ... other existing fields
}
```

## JWT Claims Structure

### Staff User Token

```python
{
  "user_id": str,
  "auth_id": str,
  "user_name": str,
  "role": str,
  "status": str,
  "platform_admin": bool,
  "laundry_id": str,  # Active laundry
  "laundries": list,  # All laundry memberships
  "hotel_id": str,  # Active hotel (if applicable)
  "hotels": list,  # All hotel memberships
  "shop_id": str,  # Active shop (if applicable)
  "shops": list  # All shop memberships
}
```

### Client Account Token

```python
{
  "user_id": str,
  "auth_id": str,
  "user_name": str,
  "role": str,
  "platform_admin": False,
  "token_kind": "client",
  "client_scope": {
    "laundry_id": str,
    "hotel_id": str,  # NEW
    "shop_id": str,  # NEW
    "client_name": str,  # Kept for backward compatibility
    "client_type": "HOTEL" | "SHOP"
  }
}
```

## Access Control Matrix

| Role | Can Create | Can Manage | Scope |
|------|-----------|-----------|-------|
| PLATFORM_ADMIN | Laundries, Hotels, Shops | All entities | Platform-wide |
| LAUNDRY_ADMIN | Staff for their laundry | Laundry operations | Single laundry |
| HOTEL_ADMIN | Hotel staff for their hotel | Hotel operations | Single hotel (within laundry) |
| HOTEL_MANAGER | - | Hotel operations (read/write, no admin) | Single hotel |
| SHOP_ADMIN | Shop staff for their shop | Shop operations | Single shop (within laundry) |
| SHOP_STAFF | - | Shop operations (read/write, no admin) | Single shop |

## API Endpoints

### Entity Registry (Platform Admin only)

#### Hotels
- `GET /hotels` - List all hotels
- `GET /hotels/{hotel_id}` - Get hotel details
- `POST /hotels` - Create hotel
- `PUT /hotels/{hotel_id}` - Update hotel
- `POST /hotels/{hotel_id}/status` - Set hotel status
- `GET /hotels/{hotel_id}/members` - List hotel staff
- `POST /hotels/{hotel_id}/members` - Add staff to hotel
- `DELETE /hotels/{hotel_id}/members/{auth_id}` - Remove staff from hotel

#### Shops
- `GET /shops` - List all shops
- `GET /shops/{shop_id}` - Get shop details
- `POST /shops` - Create shop
- `PUT /shops/{shop_id}` - Update shop
- `POST /shops/{shop_id}/status` - Set shop status
- `GET /shops/{shop_id}/members` - List shop staff
- `POST /shops/{shop_id}/members` - Add staff to shop
- `DELETE /shops/{shop_id}/members/{auth_id}` - Remove staff from shop

### User Entity Management

#### Hotel Staff
- `POST /users/{user_id}/hotels` - Grant hotel membership
- `PATCH /users/{user_id}/hotels/{hotel_id}` - Set hotel membership status
- `DELETE /users/{user_id}/hotels/{hotel_id}` - Revoke hotel membership
- `POST /auth/switch-hotel` - Switch active hotel context

#### Shop Staff
- `POST /users/{user_id}/shops` - Grant shop membership
- `PATCH /users/{user_id}/shops/{shop_id}` - Set shop membership status
- `DELETE /users/{user_id}/shops/{shop_id}` - Revoke shop membership
- `POST /auth/switch-shop` - Switch active shop context

## Migration Strategy

### Phase 1: Schema Addition
1. Add `hotels` and `shops` collections
2. Add `hotels` and `shops` fields to `users` model
3. Add `hotel_id` and `shop_id` fields to `client_accounts`
4. Update database indexes

### Phase 2: Entity Creation
1. Platform Admin creates hotel entities from existing `client_name` values
2. Platform Admin creates shop entities from existing `client_name` values
3. Each entity is associated with its laundry via `associated_laundry_id`

### Phase 3: Staff Migration
1. Identify staff who should be hotel/shop admins
2. Create appropriate entity memberships
3. Issue new tokens with updated claims

### Phase 4: Operational Data Migration
1. Backfill `hotel_id` on records using `client_name` → entity lookup
2. Backfill `shop_id` on records using `client_name` → entity lookup
3. Update queries to use entity IDs instead of client_name strings
4. Keep `client_name` for reporting/display (backward compatibility)

### Phase 5: Deprecation
1. After validation, phase out `client_name` as primary key
2. Enforce entity_id on all new records
3. Update frontend to use entity IDs

## Security Considerations

1. **IDOR Prevention**: All entity access must validate user's entity membership
2. **Cross-Entity Access**: Users cannot access data from other entities
3. **Privilege Escalation**: Only Platform Admins can create entity admins
4. **Session Scope**: Tokens carry single active entity context
5. **Audit Trail**: All entity creation/modification is logged with `created_by`

## Validation Rules

### Hotel ID
- 1-32 characters
- Lowercase letters, digits, hyphens, underscores
- Must be unique across system
- Regex: `^[a-z0-9][a-z0-9_-]{0,31}$`

### Shop ID
- 1-32 characters
- Lowercase letters, digits, hyphens, underscores
- Must be unique across system
- Regex: `^[a-z0-9][a-z0-9_-]{0,31}$`

### Entity Association
- Hotel must have `associated_laundry_id`
- Shop must have `associated_laundry_id`
- Laundry must exist and be ACTIVE
