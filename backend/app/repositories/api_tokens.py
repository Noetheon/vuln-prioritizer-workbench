"""Scoped API token repository for template Workbench persistence."""

from __future__ import annotations

import uuid

from sqlmodel import Session, col, select

from app.models import ApiToken
from app.models.api_tokens import ApiTokenScope, scopes_payload
from app.models.base import get_datetime_utc


class ApiTokenRepository:
    """API token persistence helpers."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_api_token(
        self,
        *,
        name: str,
        token_hash: str,
        scopes: list[ApiTokenScope],
    ) -> ApiToken:
        token = ApiToken(
            name=name,
            token_hash=token_hash,
            scopes_json=scopes_payload(scopes),
        )
        self.session.add(token)
        self.session.flush()
        return token

    def get_api_token(self, token_id: uuid.UUID) -> ApiToken | None:
        return self.session.get(ApiToken, token_id)

    def get_active_api_token_by_hash(self, token_hash: str) -> ApiToken | None:
        statement = select(ApiToken).where(
            ApiToken.token_hash == token_hash,
            col(ApiToken.revoked_at).is_(None),
        )
        return self.session.exec(statement).first()

    def list_api_tokens(self) -> list[ApiToken]:
        statement = select(ApiToken).order_by(col(ApiToken.created_at).desc(), col(ApiToken.name))
        return list(self.session.exec(statement).all())

    def mark_api_token_used(self, token: ApiToken) -> None:
        token.last_used_at = get_datetime_utc()
        self.session.add(token)
        self.session.flush()

    def revoke_api_token(self, token: ApiToken) -> ApiToken:
        token.revoked_at = get_datetime_utc()
        self.session.add(token)
        self.session.flush()
        return token
