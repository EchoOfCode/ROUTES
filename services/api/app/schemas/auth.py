import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


def check_password_strength(v: str) -> str:
    if v.strip() != v or len(set(v)) < 5:
        raise ValueError("Choose a longer, less repetitive password without leading or trailing spaces.")
    return v


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=256)
    display_name: str = Field(default="", max_length=120)

    @field_validator("password")
    @classmethod
    def _strength(cls, v: str) -> str:
        return check_password_strength(v)

    @field_validator("display_name")
    @classmethod
    def _name(cls, v: str) -> str:
        return " ".join(v.split())


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    display_name: str
    created_at: datetime


class UpdateProfileRequest(BaseModel):
    display_name: str = Field(max_length=120)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)

    @field_validator("new_password")
    @classmethod
    def _strength(cls, v: str) -> str:
        return check_password_strength(v)


class SessionOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    user_agent: str
    current: bool
