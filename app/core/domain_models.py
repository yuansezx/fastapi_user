from pydantic import BaseModel


class ResourceDM(BaseModel):
    id: int
    code: str
    name: str
    description: str | None


class PermissionDM(BaseModel):
    id: int
    code: str
    name: str
    description: str | None
    resource_code: str
