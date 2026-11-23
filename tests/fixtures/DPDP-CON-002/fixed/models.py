from pydantic import BaseModel
from sqlalchemy import Boolean, Column, Integer


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    marketing_consent = Column(Boolean, default=False, nullable=False)


class SignupForm(BaseModel):
    email: str
    newsletter_opt_in: bool = False
    remember_me: bool = True
