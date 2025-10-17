from datetime import datetime

from database import Base 
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func 

class User(Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(server_default="")  # имя
    login: Mapped[str] = mapped_column()  # логин
    telephone: Mapped[str] = mapped_column()  # телефон
    email: Mapped[str] = mapped_column()  # электронная почта
    password_hash: Mapped[str] = mapped_column()  # хэш-пароль
    password_salt: Mapped[str] = mapped_column()  # соль для пароля

    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"{self.id} {self.name} {self.login} {self.email} {self.data}"
    

