"""The test engine (`scanner`, ADR-012): an asyncio process that executes several runs at once,
each one as its own task, taking them from the Redis queue with SAQ."""
