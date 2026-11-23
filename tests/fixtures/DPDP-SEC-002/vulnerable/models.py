from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Traveller(Base):
    __tablename__ = "travellers"
    id = Column(Integer, primary_key=True)
    passport_no = Column(String(9), nullable=False)
    diagnosis = Column(String)
