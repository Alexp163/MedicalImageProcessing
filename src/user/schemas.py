from pydantic import BaseModel
from datetime import datetime 

class UserReadSchema(BaseModel):
    id: int 
    name: str 
    login: str 
    telephone: str 
    email: str 
    created_at: datetime 
    updated_at: datetime 


class UserCreateSchema(BaseModel):
    name: str 
    login: str 
    telephone: str 
    email: str 
    password: str 


class UserUpdateSchema(BaseModel):
    name: str 
    login: str 
    telephone: str 
    email: str 
    password: str 


class AccessTokenSchema(BaseModel):
    access_token: str 
    token_type: str 

    
