from loguru import logger

from app.core.service.service import module_service
from app.user.models import User, Role, User_Role, Role_Permission
from app.user.utils.password_hash import PasswordHash


class UserService:
    def __init__(self):
        self.User = User
        self.Role = Role
        self.User_Role = User_Role
        self.Role_Permission = Role_Permission
        self.module_service = module_service

    async def init_superadmin(self):
        # 创建超级管理员用户
        user, _ = await self.User.update_or_create({
                                                    'nickname': 'superadmin',
                                                    'password': PasswordHash.hash_password('password'),
                                                    'is_active': True,
                                                    'is_system': True,
                                                    'created_by_id': 1}, username='superadmin')
        # 创建超级管理员角色
        role, _ = await self.Role.update_or_create({'is_system':True, 'created_by':user},name='superadmin')
        # 连接超管用户和角色
        await self.User_Role.update_or_create(user=user, role=role)
        # 获取所有模块
        modules = await module_service.get_all_modules_with_permissions()
        for module in modules:
            # 获取模块所有权限
            permissions = await module.permissions.all()
            for permission in permissions:
                # 将权限依次赋予给超管角色
                await self.Role_Permission.update_or_create(role=role, permission=permission)
        logger.info('初始化超级管理员 完成。')


user_service = UserService()
