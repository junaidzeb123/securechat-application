"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel


class HelloMessage(BaseModel):
    type: str
    cert: str
    nonce: str


class DH_P_Q_Client(BaseModel):
    type: str = "dh_client"
    g: str
    p: str
    A: str


class DH_Server_B(BaseModel):
    type: str = "dh_server"
    B: int


class RegisterMessage(BaseModel):
    type: str = "register"
    payload: dict[str, str]


class LoginMessage(BaseModel):
    type: str = "login"
    payload: dict[str, str]


class SecureMessage(BaseModel):
    payload: str
