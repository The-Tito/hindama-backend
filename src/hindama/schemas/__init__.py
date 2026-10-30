"""Pydantic input and output schemas of the API.

They mirror the contract exactly (ADR-016): a field that is not in the contract does not exist here.
They never expose SQLAlchemy models or encrypted fields (RN-11)."""
