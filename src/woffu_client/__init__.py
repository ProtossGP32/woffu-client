"""Woffu client: manage user's daily tasks in Woffu platform."""
from __future__ import annotations

from .stdrequests_session import HTTPResponse
from .stdrequests_session import Session
from .woffu_api_client import WoffuAPIClient

__all__ = ["HTTPResponse", "Session", "WoffuAPIClient"]
