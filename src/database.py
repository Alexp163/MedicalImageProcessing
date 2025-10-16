from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine 
from sqlalchemy.ext.declarative import declarative_base 
from sqlalchemy.orm import sessionmaker 


SQLALCHEMY_DATABASE_URI = "postgresql+asyncpg://alex:12345@172.18.0.1.:5432/medical_image_processing"
engine = create_async_engine(SQLALCHEMY_DATABASE_URI)
async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session 



