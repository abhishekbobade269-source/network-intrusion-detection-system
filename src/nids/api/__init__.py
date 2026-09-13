"""FastAPI application: REST endpoints over the alert store plus a
websocket for the dashboard's live feed, and control endpoints to
start/stop the detection runner (live capture or pcap replay).
"""

from nids.api.main import create_app

__all__ = ["create_app"]
