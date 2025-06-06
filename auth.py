from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError



USER_SECRET_KEY = '43b7ddbf6ea7d3a7e6fad4dd3163bc2de41943109eb5647e6108676b392fb795'
ADMIN_SECRET_KEY = 'e389058d477cd3cda95b1e6695fb0d9879f377ba8c189539a5d5dcd25910254f'
ALGORITHM ="HS256"
pwd_cxt = CryptContext(schemes=["bcrypt"],deprecated= "auto")

def hashed_password(password):
    return pwd_cxt.hash(password)

def verify_password(plain_password,hashed_password):
    return pwd_cxt.verify(plain_password,hashed_password)

def create_user_token(data : dict,expire_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow()+(expire_delta if expire_delta else timedelta(minutes=15))
    to_encode.update({'exp':expire})
    user_token = jwt.encode(to_encode,USER_SECRET_KEY,algorithm=ALGORITHM)
    return user_token

def decode_user_token(token: str):
    try:
        to_decode = jwt.decode(token,USER_SECRET_KEY,algorithms=[ALGORITHM])
        return to_decode
    except JWTError:
        return None


def create_admin_token(data: dict, expire_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow()+(expire_delta if expire_delta else timedelta(minutes=15))
    to_encode.update({'exp':expire})
    admin_token = jwt.encode(to_encode,ADMIN_SECRET_KEY,algorithm=ALGORITHM)
    return admin_token

def decode_admin_token(token: str):
    try:
        to_decode = jwt.decode(token,ADMIN_SECRET_KEY,algorithms=[ALGORITHM])
        return to_decode
    except JWTError:
        return None

def create_refresh_token_for_user(data:dict):
    expire = datetime.utcnow()+timedelta(days=7)
    to_encode = data.copy()
    to_encode.update({"exp":expire})
    token = jwt.encode(to_encode,USER_SECRET_KEY,algorithm=ALGORITHM)
    return token

def create_refresh_token_for_admin(data:dict):
    expire = datetime.utcnow()+timedelta(days=7)
    to_encode = data.copy()
    to_encode.update({"exp":expire})
    token = jwt.encode(to_encode,ADMIN_SECRET_KEY,algorithm=ALGORITHM)
    return token 