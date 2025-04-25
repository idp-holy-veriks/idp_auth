from pydantic import BaseModel


# --- Token Schema ---
class Token(BaseModel):
    access_token: str
    token_type: str


class UserLogin(BaseModel):
    name: str
    password: str


class UserCreate(UserLogin):
    email: str
