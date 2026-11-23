"""HTTP layer: FastAPI routers, one per resource of the contract (hindama-docs/03-api/openapi.yaml).

Translates HTTP <-> services only: validates input with schemas, calls a service and returns an
output schema. No business rules and no database queries here."""
