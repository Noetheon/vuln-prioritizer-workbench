"""Authentication DTOs for the Workbench shell."""

from sqlmodel import SQLModel


class Token(SQLModel):
    """OAuth2 bearer token response."""

    access_token: str
    token_type: str = "bearer"
    csrf_token: str | None = None


class TokenPayload(SQLModel):
    """JWT payload accepted by the Workbench shell."""

    sub: str | None = None
    jti: str | None = None
