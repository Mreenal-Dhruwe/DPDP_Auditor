from sqlalchemy import Column, Integer, LargeBinary
from sqlalchemy.orm import declarative_base
from sqlalchemy_utils import EncryptedType

Base = declarative_base()


class Traveller(Base):
    __tablename__ = "travellers"
    id = Column(Integer, primary_key=True)
    passport_no = Column(EncryptedType, nullable=False)
    diagnosis = Column(LargeBinary)
