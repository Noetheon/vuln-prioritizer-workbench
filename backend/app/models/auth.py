"""Authentication DTOs for the template shell."""

from sqlmodel import SQLModel


class Token(SQLModel):
    """OAuth2 bearer token response."""

    access_token: str
    token_type: str = "bearer"


class TokenPayload(SQLModel):
    """JWT payload accepted by the template shell."""

    sub: str | None = None
