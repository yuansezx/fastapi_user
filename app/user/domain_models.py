from datetime import datetime

from pydantic import BaseModel

from app.core.domain_models import PermissionDM, ModuleDM


class RoleDM(BaseModel):
    id: int
    name: str
    description: str | None

class CurrentUserDM(BaseModel):
    token: str
    id: int
    username: str
    last_login_at: datetime
    is_system: bool
    roles: list[RoleDM]
    permissions: list[PermissionDM]
    modules: list[ModuleDM]

    def has_permission(self, module_code:str,permission_code:str) -> bool:
        if module_code and permission_code:
            for permission in self.permissions:
                if permission.module_code == module_code and permission.code == permission_code:
                    return True
        else:
            return True