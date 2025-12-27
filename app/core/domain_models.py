from pydantic import BaseModel


class ModuleDM(BaseModel):
    id: int
    code: str
    name: str
    description: str | None

class PermissionDM(BaseModel):
    id: int
    code: str
    name: str
    description: str | None
    module_code: str