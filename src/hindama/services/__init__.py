"""Business layer: use cases and rules (RF, RN).

Orchestrates repositories and external services. It knows nothing about HTTP (no Request, no status
codes): failures are raised as the domain exceptions in `hindama.core.errors`."""
