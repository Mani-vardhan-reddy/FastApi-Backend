from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base,sessionmaker

engine = create_engine("postgresql+psycopg2://postgres:3377@localhost:5432/sample",echo=True)

Base = declarative_base()

SessionLocal = sessionmaker(bind=engine,autoflush=False,autocommit=False)