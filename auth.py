from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from config import settings




pwd_cxt = CryptContext(schemes=["bcrypt"],deprecated= "auto")

def hashed_password(password):
    return pwd_cxt.hash(password)

def verify_password(plain_password,hashed_password):
    return pwd_cxt.verify(plain_password,hashed_password)

def create_user_token(data : dict,expire_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow()+(expire_delta if expire_delta else timedelta(minutes=15))
    to_encode.update({'exp':expire})
    user_token = jwt.encode(to_encode,settings.USER_SECRET_KEY,algorithm=settings.ALGORITHM)
    return user_token

def decode_user_token(token: str):
    try:
        to_decode = jwt.decode(token,settings.USER_SECRET_KEY,algorithms=[settings.ALGORITHM])
        return to_decode
    except JWTError:
        return None


def create_admin_token(data: dict, expire_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow()+(expire_delta if expire_delta else timedelta(minutes=15))
    to_encode.update({'exp':expire})
    admin_token = jwt.encode(to_encode,settings.ADMIN_SECRET_KEY,algorithm=settings.ALGORITHM)
    return admin_token

def decode_admin_token(token: str):
    try:
        to_decode = jwt.decode(token,settings.ADMIN_SECRET_KEY,algorithms=[settings.ALGORITHM])
        return to_decode
    except JWTError:
        return None

def create_refresh_token_for_user(data:dict):
    expire = datetime.utcnow()+timedelta(days=7)
    to_encode = data.copy()
    to_encode.update({"exp":expire})
    token = jwt.encode(to_encode,settings.USER_SECRET_KEY,algorithm=settings.ALGORITHM)
    return token

def create_refresh_token_for_admin(data:dict):
    expire = datetime.utcnow()+timedelta(days=7)
    to_encode = data.copy()
    to_encode.update({"exp":expire})
    token = jwt.encode(to_encode,settings.ADMIN_SECRET_KEY,algorithm=settings.ALGORITHM)
    return token 