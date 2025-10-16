from database import Base 
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func 

class User(Base):
    __tablename__ = "user"

    