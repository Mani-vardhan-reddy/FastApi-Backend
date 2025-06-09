from pydantic import BaseModel,EmailStr
from typing import Optional,List


class User(BaseModel):
    username : str
    email : str
    password : str
    salary : float

    class Config():
        orm_mode = True

class UserUpdateModel(BaseModel):
    username : Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    salary : Optional[float] = None

    class Config():
        orm_mode = True

class Admin(BaseModel):
    admin_name : str
    email : str
    password : str
    salary :float

    class Config():
        orm_mode = True

class AdminUpdateModel(BaseModel):
    admin_name : Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    salary : Optional[float] = None

    class Config():
        orm_mode = True

class UserResponseModel(BaseModel):
    username : str
    email : str
    salary: float

    class Config():
        orm_mode = True


class AdminResponseModel(BaseModel):
    admin_name : str
    email : str
    salary: Optional[float] = None

    class Config():
        orm_mode = True


class UserLoginModel(BaseModel):
    username : str
    password : str


class EmailModel(BaseModel):
    addresses : List[EmailStr]