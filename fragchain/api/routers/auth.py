from __future__ import annotations

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.security import issue_jwt, verify_password
from fragchain.db.models import AuditLog, User
from fragchain.db.session import get_db

logger = structlog.get_logger(__name__)
router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: dict[str, str]


@router.post("/auth/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.hashed_password):
        logger.info("auth.login.failed", username=payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token, expires_at = issue_jwt(
        subject=str(user.id),
        claims={
            "username": user.username,
            "tier": user.tier,
            "clearance": user.clearance_level,
        },
    )

    user.last_login = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            entity_type="user",
            entity_id=user.id,
            action="login",
            actor=user.id,
            ip=(request.client.host if request.client else None),
        )
    )
    await db.commit()

    logger.info("auth.login.ok", username=user.username, user_id=str(user.id))

    return LoginResponse(
        access_token=token,
        expires_at=expires_at,
        user={
            "id": str(user.id),
            "username": user.username,
            "tier": user.tier,
            "clearance_level": user.clearance_level,
        },
    )
