"""
all jwt related routes
"""

from fastapi import APIRouter, Response, Request
from fastapi.security import HTTPAuthorizationCredentials

from utility.Setting import settings
from security.jwt_provider import create_access_token, create_refresh_token
from security.schema import JWT_payload, AccessToken


def create_token_pair(access):
    