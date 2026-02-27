from fastapi import APIRouter

from automunki.core.security import auth_backend, fastapi_users
from automunki.schemas.user import UserCreate, UserRead, UserUpdate

router = APIRouter(prefix="/auth", tags=["auth"])

router.include_router(fastapi_users.get_auth_router(auth_backend))
router.include_router(fastapi_users.get_register_router(UserRead, UserCreate))

users_router = APIRouter(prefix="/users", tags=["users"])
users_router.include_router(fastapi_users.get_users_router(UserRead, UserUpdate))
