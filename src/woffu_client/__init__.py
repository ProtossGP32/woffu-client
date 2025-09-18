"""
woffu_client: A Python client for interacting with the Woffu platform.

This module provides functionality for managing user tasks and accessing
data from the Woffu API.

Submodules:
    stdrequests_session:  Provides Session and HTTPResponse classes.
    woffu_api_client:  Provides the WoffuAPIClient class for interacting
                       with the Woffu API.

Public classes:
    HTTPResponse: Represents an HTTP response.
    Session:  A session for making HTTP requests.
    WoffuAPIClient: The main client class for interacting with the Woffu API.
"""
from __future__ import annotations

from .stdrequests_session import HTTPResponse
from .stdrequests_session import Session
from .woffu_api_client import WoffuAPIClient

__all__ = ["HTTPResponse", "Session", "WoffuAPIClient"]
