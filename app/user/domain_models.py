from datetime import datetime

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

    def has_permission(self, *need_permissions: dict[str, str]) -> bool:
        # 判断是否为空
        if need_permissions:
            # 列表元素之间或关系，列表内的字典的元素与关系
            or_list = []
            for permission_dict in need_permissions:
                and_list = []
                for resource_code, permission_code in permission_dict.items():
                    skip = False
                    # 判断是否为空
                    if resource_code and permission_code:
                        for permission in self.permissions:
                            if permission.resource_code == resource_code and permission.code == permission_code:
                                and_list.append(True)
                                skip = True
                                break
                    else:
                        and_list.append(True)
                        skip = True

                    if skip:
                        continue
                    and_list.append(False)
                or_list.append(all(and_list))
            return any(or_list)
        else:
            return True
