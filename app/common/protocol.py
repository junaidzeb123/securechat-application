"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel


class HelloMessage(BaseModel):
    type: str
    cert: str
    nonce: str
