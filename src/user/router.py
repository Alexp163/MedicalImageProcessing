from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import select, insert, delete, update 
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_async_session
from .models import User 
from .schemas import UserCreateSchema, UserReadSchema, UserUpdateSchema, AccessTokenSchema
from fastapi.exceptions import HTTPException
from .utils import Repository, make_token, valid_and_decode_token


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
@router.post("/login", status_code=status.HTTP_200_OK)
async def login_user(credentials: OAuth2PasswordRequestForm = Depends(), 
                     session: AsyncSession = Depends(get_async_session),
                     repository: Repository = Depends()) -> AccessTokenSchema:
    user = await repository.get_user(credentials.username, credentials.password, session)
    token = make_token(user.id)
    return AccessTokenSchema(
        access_token=token,
        token_type="Bearer"
    )

# получение данных о пользователе по id
@router.get("/{user_id}", status_code=status.HTTP_200_OK)
async def get_user_by_id(user_id: int, session: AsyncSession = Depends(get_async_session),
                         repository: Repository = Depends()) -> UserReadSchema:
    return await repository.get_user_by_id(user_id, session)

# удаление пользователя по id 
@router.delete("{/user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_by_id(user_id: int, token: str = Depends(get_token),
                            session: AsyncSession = Depends(get_async_session),
                            repository: Repository = Depends()) -> None:
    token_user_id = valid_and_decode_token(token)
    if token_user_id == user_id:
        user = await repository.delete_user_by_id(user_id, session)
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Отказано в доступе")
    
# обновление данных пользователя по id 
@router.put("/{user_id}", status_code=status.HTTP_200_OK)
async def upgrade_user_by_id(user_id: int, user: UserUpdateSchema, token: str = Depends(get_token),
                             session = Depends(get_async_session),
                             repository: Repository = Depends()) -> UserReadSchema:
    token_user_id = valid_and_decode_token(token)
    if token_user_id == user_id:
        user_token = await repository.update_user_by_id(user_id, user, session)
        return user_token
    else: 
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="отказано в доступе"
        )
    
    

