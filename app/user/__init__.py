from app.core.service.schemas import RegisterModuleIn_PermissionsSchema, RegisterModuleInSchema
from app.core.service.service import module_service
from app.user.service.service import user_service


# 注册模块
async def register_module():
    permissions = [RegisterModuleIn_PermissionsSchema(code='read', name='查看用户'),
                   RegisterModuleIn_PermissionsSchema(code='create', name='创建用户'),
                   RegisterModuleIn_PermissionsSchema(code='update', name='更改用户信息'),
                   RegisterModuleIn_PermissionsSchema(code='delete', name='删除用户')]
    data=RegisterModuleInSchema(code='user',name='用户模块',description='用户管理、角色及权限管理',permissions=permissions)

    await module_service.register_module(data)

# 初始化超级管理员
async def init_superadmin():
    await user_service.init_superadmin()