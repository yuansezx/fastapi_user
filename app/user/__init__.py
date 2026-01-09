"""
用户模块初始化，注册资源
"""
from app.user.schemas import RegisterResourceIn_PermissionsSchema, RegisterResourceInSchema
from app.user.service import user_service

# 注册资源
async def register_resources():
    # users
    permissions = [RegisterResourceIn_PermissionsSchema(code='read', name='查看用户'),
                   RegisterResourceIn_PermissionsSchema(code='create', name='创建用户'),
                   RegisterResourceIn_PermissionsSchema(code='update', name='更改用户信息'),
                   RegisterResourceIn_PermissionsSchema(code='delete', name='删除用户')]
    data = RegisterResourceInSchema(code='users', name='用户数据', description='', permissions=permissions)
    await user_service.register_resource(data)

    # roles
    permissions = [RegisterResourceIn_PermissionsSchema(code='read', name='查看角色'),
                   RegisterResourceIn_PermissionsSchema(code='create', name='创建角色'),
                   RegisterResourceIn_PermissionsSchema(code='update', name='更改角色信息'),
                   RegisterResourceIn_PermissionsSchema(code='delete', name='删除角色')]
    data = RegisterResourceInSchema(code='roles', name='角色数据', description='', permissions=permissions)
    await user_service.register_resource(data)


# 初始化超级管理员
async def init_superadmin():
    await user_service.init_superadmin()
