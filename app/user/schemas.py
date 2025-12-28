from datetime import datetime

from pydantic import BaseModel



"""服务层schemas"""
class CreateUserInSchema(BaseModel):
    username: str
    nickname: str | None = None
    password: str
    is_active: bool = False
    role_ids: list[int] | None = None



"""路由层schemas"""


class UserLoginResSchema(BaseModel):
    id: int
    username: str
    last_login_at: datetime | None
    roles: list
    permissions: list

class CreateUserReqSchema(CreateUserInSchema):
    pass

class CreateUserResSchema(BaseModel):
    user_id: int