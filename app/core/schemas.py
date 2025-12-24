
from pydantic import BaseModel


"""服务层schema"""
class RegisterModuleIn_PermissionsSchema(BaseModel):
    code: str
    name: str
    description: str | None = None

class RegisterModuleInSchema(BaseModel):
    code: str
    name: str
    description: str | None = None
    permissions:list[RegisterModuleIn_PermissionsSchema]

"""路由层schemas"""
class FailResSchema(BaseModel):
    detail: str
