from datetime import datetime
from typing import Union
from pydantic import BaseModel, Field, field_serializer


class LineItemSchema(BaseModel):
    item_name: str
    category: str | None = None
    unit_price: float
    notes: str | None = None


class QuotationCreate(BaseModel):
    client_name: str
    quotation_title: str | None = None
    line_items: list[LineItemSchema] = Field(default_factory=list)
    status: str = "draft"


class QuotationUpdate(BaseModel):
    client_name: str | None = None
    quotation_title: str | None = None
    line_items: list[LineItemSchema] | None = None
    status: str | None = None


class QuotationResponse(BaseModel):
    id: Union[int, str]  # MongoDB uses string IDs, PostgreSQL uses integer IDs
    client_name: str
    quotation_title: str | None
    line_items: list[dict]
    status: str
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_serializer('created_at', 'updated_at')
    def serialize_datetime(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        return value.isoformat()

    model_config = {"from_attributes": True}
