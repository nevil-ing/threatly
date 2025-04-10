from typing import Optional
from pydantic import BaseModel  

#user schema

class UserBase(BaseModel):
    username: str
    email: str
    full_name: str
    is_active: Optional[bool]= True
    
class UserCreate(UserBase):
    passworrd: str    

class UserUpdate(UserBase):
    password: Optional[str] = None
    
class UserInDB(UserBase):
    id: int
    hashed_password: str
    
    class Config:
        from_attributes = True
        
 #returning user data
class User(UserBase):
     id: int
     
     class Config:
         from_attributes = True       

class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: Optional[str] = None                    