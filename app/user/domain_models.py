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
    last_login_at: datetime | None
    is_system: bool
    roles: list[RoleDM]
    permissions: list[PermissionDM]
    modules: list[ModuleDM]

    def has_permission(self, permission_dict:dict[str,str]) -> bool:
        for module_code,permission_code in permission_dict.items():
            if module_code and permission_code:
                for permission in self.permissions:
                    if permission.module_code == module_code and permission.code == permission_code:
                        return True
            else:
                return True