from datetime import datetime

from loguru import logger
from pytz import timezone

from app.core.redis_manager import redis_manager
from app.core.settings import GLOBAL_SETTINGS
from app.core.service import module_service
from app.user.exceptions import UserNotFoundError, UserPasswordIncorrectError, UserInactiveError
from app.user.models import User, Role, User_Role, Role_Permission
from app.user.schemas import CurrentUser
from app.user.utils import password_hash
from app.user.utils.jwt_wrapper import jwt_wrapper


class UserService:
    def __init__(self):
        self.User = User
        self.Role = Role
        self.User_Role = User_Role
        self.Role_Permission = Role_Permission
        self.module_service = module_service
        self.redis_conn = redis_manager.redis_pool

    async def init_superadmin(self):
        # 创建超级管理员用户
        user, _ = await self.User.update_or_create({
            'nickname': 'superadmin',
            'password': password_hash.hash_password('password'),
            'is_active': True,
            'is_system': True,
            'created_by_id': 1}, username='superadmin')
        # 创建超级管理员角色
        role, _ = await self.Role.update_or_create({'is_system': True, 'created_by': user}, name='superadmin')
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

    async def verify_permission(self, user_id: int, module_code: str, permission_code: str) -> bool:
        """
        核查权限
        :param user_id: 用户id
        :param module_code: 模块码
        :param permission_code: 权限码
        :return:
        """
        # 构造查询语句
        queryset = self.User.filter(id=user_id,
                                    role_assignments__role__permission_assignments__permission__module__code=module_code,
                                    role_assignments__role__permission_assignments__permission__code=permission_code)
        return await queryset.exists()

    async def login(self,username:str,password:str)->tuple[str, datetime]:
        """
        用户登录
        :param username: 用户名
        :param password: 密码
        :return: token和last_login_at上一次登录的时间
        :raise UserNotFoundError: 用户不存在
        :raise UserPasswordIncorrectError: 用户密码错误
        :raise UserInactiveError: 用户被锁定，禁止登录
        """
        user = await self.User.get_or_none(username=username)
        if user:
            # 是否被禁止登录
            if user.is_active:
                # 验证密码
                if password_hash.verify_password(password, user.password):
                    # 记录登录时间
                    last_login_at = user.last_login_at
                    user.last_login_at = datetime.now(timezone('UTC'))
                    await user.save(update_fields=['last_login_at'])
                    logger.info(f'id: {user.id} 用户名: {user.username} 登录成功')
                    return jwt_wrapper.create_token({'user_id': user.id,'username': user.username}),last_login_at
                else:
                    logger.info(f'id: {user.id} 用户名: {user.username} 登录失败 密码错误')
                    raise UserPasswordIncorrectError
            else:
                logger.info(f'id: {user.id} 用户名: {user.username} 登录失败 用户账号不可用')
                raise UserInactiveError

        else:
            logger.info(f'用户名: {username} 登录失败 用户名不存在')
            raise UserNotFoundError

    async def logout(self,current_user:CurrentUser):
        # 路由层会通过依赖检查token是否有效，不会出现token已在黑名单却仍可以进行注销的操作
        await self.redis_conn.set(current_user.token,'注销',GLOBAL_SETTINGS.redis_key_token_ex)



user_service = UserService()
