from pydantic import BaseModel

"""服务层schema"""


class RegisterResourceIn_PermissionsSchema(BaseModel):
    code: str
    name: str
    description: str | None = None


class RegisterResourceInSchema(BaseModel):
    code: str
    name: str
    description: str | None = None
    permissions: list[RegisterResourceIn_PermissionsSchema]


"""路由层schemas"""


class FailResSchema(BaseModel):
    detail: str
