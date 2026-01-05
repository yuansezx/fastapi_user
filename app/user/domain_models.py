from datetime import datetime

from pydantic import BaseModel

from app.core.domain_models import PermissionDM, ResourceDM


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
    resources: list[ResourceDM]

    def has_permission(self, permission_dict: dict[str, str]) -> bool:
        for resource_code, permission_code in permission_dict.items():
            if resource_code and permission_code:
                for permission in self.permissions:
                    if permission.resource_code == resource_code and permission.code == permission_code:
                        return True
            else:
                return True
