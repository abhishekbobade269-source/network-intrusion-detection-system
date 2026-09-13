"""Per-IP rate limiting (slowapi/limits) for the control-plane endpoints.

Read endpoints (`GET /alerts`, `/stats`, `/ws/alerts`) are intentionally
left unlimited here — see `docs/threat_model.md`, they're meant to sit
behind your own auth/reverse proxy for anything but a private network.
What this closes is the previously-open gap of the *write* endpoints
(`/system/capture/start|stop`, `/alerts/{id}/acknowledge`) having an
API-key check but no throughput limit — a leaked/guessed key, or a
misbehaving client, could otherwise hammer capture start/stop or flood
the acknowledge endpoint with no backpressure at all.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# Deliberately generous — these are operator actions (starting a capture,
# acking an alert), not a high-frequency API; the point is to blunt abuse
# of a leaked key, not to constrain normal use.
CONTROL_RATE_LIMIT = "20/minute"
