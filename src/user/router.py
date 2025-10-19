from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import select, insert, delete, update 
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_async_session
from .models import User 
from .schemas import UserCreateSchema, UserReadSchema, UserUpdateSchema, AccessTokenSchema
from fastapi.exceptions import HTTPException
from .utils import Repository, make_token


router = APIRouter(tags=["users"], prefix="/users")
get_token = OAuth2PasswordBearer(tokenUrl="/users/login")


# Регистрация пользователя
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreateSchema, session=Depends(get_async_session),
                      repository: Repository = Depends()) -> None:
    await repository.create_user(user, session)

# Вывод всех пользователей
@router.get("/", status_code=status.HTTP_200_OK)
async def get_users(repository: Repository = Depends(), 
                    session = Depends(get_async_session)) -> list[UserReadSchema]:
    return await repository.get_users(session)

# Авторизация пользователя
@router.get("/login_user", status_code=status.HTTP_200_OK)
async def login_user(credentials: OAuth2PasswordRequestForm = Depends(), 
                     session: AsyncSession = Depends(get_async_session),
                     repository: Repository = Depends()) -> AccessTokenSchema:
    print(f"credentials  = {credentials}")
    user = await repository.get_user(credentials.login, credentials.password, session)
    token = make_token(user.id)
    return AccessTokenSchema(
        access_token=token,
        token_type="Bearer"
    )


