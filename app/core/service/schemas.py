"""core 服务层schema"""
from pydantic import BaseModel

class RegisterModuleIn_PermissionsSchema(BaseModel):
    code: str
    name: str
    description: str | None = None

class RegisterModuleInSchema(BaseModel):
    code: str
    name: str
    description: str | None = None
    permissions:list[RegisterModuleIn_PermissionsSchema]
