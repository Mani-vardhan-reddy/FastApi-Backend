from database import Base
from sqlalchemy import Column, Integer, String, Float


class UserModel(Base):
    __tablename__ = "user"
    id = Column(Integer,primary_key=True,autoincrement=True)
    username = Column(String,nullable=False)
    email = Column(String,nullable=False)
    password = Column(String,nullable=False)
    salary = Column(Float,nullable=True, default=20000.00)
    
   
class AdminModel(Base):
    __tablename__ = "admin"
    id = Column(Integer,primary_key=True,autoincrement=True)
    admin_name = Column(String,nullable=False)
    email = Column(String,nullable=False)
    password = Column(String,nullable=False)
    salary = Column(Float)
