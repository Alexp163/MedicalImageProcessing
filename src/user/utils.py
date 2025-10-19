import jwt
import hashlib
from random import choices 
from string import ascii_letters
from fastapi import HTTPException, status
from sqlalchemy import select, delete, update, insert 
from sqlalchemy.ext.asyncio import AsyncSession 

from user.schemas import UserCreateSchema, UserReadSchema, UserUpdateSchema
from .models import User 



secret_key = "k34GfsdMM77resbdd3zFwaPgCCv"
algorithm = "HS256"


def make_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
    }
    token = jwt.encode(payload, secret_key, algorithm)
    return token 


def valid_and_decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, secret_key, [algorithm])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                            detail="Срок действия токена истек")
    except Exception:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="отказано в доступе")


class Repository:

    def get_hash(self, password: str, salt: str) -> str:
        password_hash = hashlib.sha256(password.encode() + salt.encode()).hexdigest()
        return password_hash
    
    # Создание user
    async def create_user(self, user: UserCreateSchema, session: AsyncSession) -> UserReadSchema:
        statement = select(User).where(User.login == user.login)
        result = await session.scalar(statement)
        if result is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, 
                                detail="Такой пользователь уже есть")
        salt = "".join(choices(ascii_letters, k=16))
        password_hash = self.get_hash(user.password, salt)
        statement = insert(User).values(
            name=user.name,
            login=user.login,
            telephone=user.telephone,
            email=user.email,
            password_hash=password_hash,
            password_salt=salt,
        ).returning(User)
        result = await session.scalar(statement)
        await session.commit()
        return result 

    # вывод всех users
    async def get_users(self, session: AsyncSession) -> list[UserReadSchema]:
        statement = select(User)
        result = await session.scalars(statement)
        return result
    
    # получение одного пользователя по логину и паролю для авторизации
    async def get_user(self, login: str, password: str, session: AsyncSession) -> UserReadSchema:
        statement = select(User).where(User.login ==login)
        result = await session.scalar(statement)
        if result is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail="Неверный логин или пароль")
        password_hash = self.get_hash(password, result.password_salt)
        if result.password_hash == password_hash:
            return result 
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail="Неверный логин или пароль")
    
    # Получение данные о пользователе по id
    async def get_user_by_id(self, user_id: int, session: AsyncSession) -> UserReadSchema:
        statement = select(User).where(User.id == user_id)
        result = await session.scalar(statement)
        return result 
    
    # Удаление пользователя по id
    async def delete_user_by_id(self, user_id: int, session: AsyncSession) -> None:
        statement = select(User).where(User.id == user_id)
        user = await session.scalar(statement)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Такого пользователя нет")
        statement = delete(User).where(User.id == user_id)
        await session.execute(statement)
        await session.commit()

    # Обновление данных пользователя по id
    async def update_user_by_id(self, user_id: int, user: UserUpdateSchema,
                                session: AsyncSession) -> UserReadSchema:
        statement = select(User).where(User.id == user_id)
        result = await session.scalar(statement)
        if result is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Такого пользователя не существует")
        if result.id == user_id:
            salt = "".join(choices(ascii_letters, k=16))
            password_hash = self.get_hash(user.password, salt)
            statement = update(User).where(User.id == user_id).values(
                name=user.name,
                login=user.login,
                telephone=user.telephone,
                email=user.email,
                password_hash=password_hash,
                password_salt=salt,
            ).returning(User)
            result = await session.scalar(statement)
            await session.commit()
            return result 
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Отказано в доступе")

