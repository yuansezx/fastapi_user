from datetime import datetime

from pydantic import BaseModel


class CurrentUser(BaseModel):
    token: str
    payload: dict
    user_id: int
    username: str


"""路由层schemas"""
class UserLoginResSchema(BaseModel):
    username: str
    last_login_at: datetime | None