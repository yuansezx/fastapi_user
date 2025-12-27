from datetime import datetime

from pydantic import BaseModel



"""服务层schemas"""




"""路由层schemas"""


class UserLoginResSchema(BaseModel):
    id: int
    username: str
    last_login_at: datetime | None
    roles: list
    permissions: list
