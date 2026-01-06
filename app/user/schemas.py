from datetime import datetime

from pydantic import BaseModel, Field

"""服务层schemas"""


class CreateUserInSchema(BaseModel):
    username: str = Field(max_length=20)
    nickname: str | None = Field(None, max_length=20)
    password: str
    is_active: bool = False
    role_ids: list[int] | None = None


class UserDataOutSchema(BaseModel):
    id: int
    username: str
    nickname: str
    created_at: datetime
    updated_at: datetime | None
    is_active: bool
    is_system: bool
    last_login_at: datetime | None
    created_by_id: int
    updated_by_id: int | None


class GetUsersOutSchema(BaseModel):
    total: int
    total_pages: int
    page: int
    page_size: int
    order_by: list[str]
    data: list[UserDataOutSchema]


class CreateRoleInSchema(BaseModel):
    name: str = Field(max_length=20)
    description: str = Field(max_length=100)
    permission_ids: list[int] | None = None


class UpdateUserInSchema(BaseModel):
    username: str | None = Field(None, max_length=20)
    nickname: str | None = Field(None, max_length=20)
    password: str | None = None
    is_active: bool | None = None
    role_ids: list[int] | None = None

class RoleDataOutSchema(BaseModel):
    id: int
    name: str
    description: str | None
    is_system: bool
    created_at: datetime
    created_by_id: int

class GetRolesOutSchema(GetUsersOutSchema):
    data: list[RoleDataOutSchema]


class GetRolePermissionOut_Resource_PermissionSchema(BaseModel):
    id:int
    code: str
    name: str
    description: str | None

class GetRolePermissionOut_ResourceSchema(BaseModel):
    id: int
    code: str
    name: str
    description: str | None
    permissions: list[GetRolePermissionOut_Resource_PermissionSchema]

class GetRolePermissionsOutSchema(BaseModel):
    resources: list[GetRolePermissionOut_ResourceSchema]

class UpdateRoleInSchema(BaseModel):
    name: str | None = None
    description: str | None = None

class GetAllPermissionsOut_Resource_PermissionSchema(BaseModel):
    id: int
    code: str
    name: str
    description: str | None = None

class GetAllPermissionsOut_ResourceSchema(BaseModel):
    id: int
    code: str
    name: str
    description: str | None = None
    permissions: list[GetAllPermissionsOut_Resource_PermissionSchema]

class GetAllPermissionsOutSchema(BaseModel):
    resources: list[GetAllPermissionsOut_ResourceSchema]

"""路由层schemas"""


class UserLoginResSchema(BaseModel):
    id: int
    username: str
    last_login_at: datetime | None
    roles: list
    permissions: list


class CreateUserReqSchema(CreateUserInSchema):
    pass


class CreateUserResSchema(BaseModel):
    user_id: int


class GetUsersResSchema(GetUsersOutSchema):
    pass


class CreateRoleReqSchema(CreateRoleInSchema):
    pass


class UpdateUserReqSchema(UpdateUserInSchema):
    pass

class GetRolesResSchema(GetUsersOutSchema):
    pass

class GetRolePermissionsResSchema(GetRolePermissionsOutSchema):
    pass

class UpdateRoleReqSchema(UpdateRoleInSchema):
    pass