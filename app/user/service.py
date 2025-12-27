
from datetime import datetime

from loguru import logger
from pytz import timezone

from app.core.domain_models import PermissionDM, ModuleDM
from app.core.redis_manager import redis_manager
from app.core.settings import GLOBAL_SETTINGS
from app.core.service import module_service
from app.user.domain_models import RoleDM, CurrentUserDM
from app.user.exceptions import UserNotFoundError, UserPasswordIncorrectError, UserInactiveError
from app.user.models import User, Role, User_Role, Role_Permission
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

    # 初始化超级管理员
    async def init_superadmin(self):
        # 判断超管账号是否存在
        if not await self.User.filter(username="superadmin").exists():
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
        # 赋予超管所有权限，因为模块权限可能会随更新变化，所以每次启动都需要运行
        role_id=await self.Role.get(name='superadmin').values_list('id',flat=True)
        # 获取所有权限
        permission_ids = await module_service.get_all_permission_ids()
        await self.grant_permissions_to_role_by_ids(role_id, permission_ids)
        logger.info('初始化超级管理员 完成。')

    # 赋予角色权限
    async def grant_permissions_to_role_by_ids(self, role_id,permission_ids:list[int]):
        old_permission_ids = set(await self.Role_Permission.filter(role_id=role_id).values_list('permission_id',flat=True))
        target_permission_ids =set(permission_ids)
        to_add_ids = target_permission_ids - old_permission_ids
        to_remove_ids = old_permission_ids - target_permission_ids
        if to_remove_ids:
            await self.Role_Permission.filter(role_id=role_id,permission_id__in=to_remove_ids).delete()
        if to_add_ids:
            new_assignments = [Role_Permission(role_id=role_id,permission_id=permission_id) for permission_id in to_add_ids]
            await self.Role_Permission.bulk_create(new_assignments)


    # 读取user拥有的所有角色
    async def get_roles_by_user(self, user: User):
        roles = await self.Role.filter(user_assignments__user=user).all()
        return roles

    # 通过数据库核查权限
    async def verify_permission_by_db(self, user_id: int, module_code: str, permission_code: str) -> bool:
        """
        通过数据库核查权限
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
    # 登录
    async def login(self, username: str, password: str) -> CurrentUserDM:
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
                    roles = await self.get_roles_by_user(user)
                    permissions = await self.module_service.get_permissions_with_modules_by_roles(roles)
                    # modules去重
                    modules_dict = {permission.module.id: permission.module for permission in permissions}
                    modules = list(modules_dict.values())
                    # 转为DM
                    role_dms = [RoleDM(**role.to_dict()) for role in roles]
                    permissions_dms = [PermissionDM(**permission.to_dict(), module_code=permission.module.code) for
                                       permission in permissions]
                    modules_dms = [ModuleDM(**module.to_dict()) for module in modules]
                    # 记录登录时间
                    last_login_at = user.last_login_at
                    user.last_login_at = datetime.now(timezone('UTC'))
                    await user.save(update_fields=['last_login_at'])
                    logger.info(f'id: {user.id} 用户名: {user.username} 登录成功')
                    # 生成DM对象
                    current_user = CurrentUserDM(
                        token=jwt_wrapper.create_token({'user_id': user.id, 'username': user.username}),
                        id=user.id,
                        username=user.username,
                        last_login_at=last_login_at,
                        is_system=user.is_system,
                        roles=role_dms,
                        permissions=permissions_dms,
                        modules=modules_dms)
                    # 记录到redis
                    await self.redis_conn.set(current_user.token,current_user.model_dump_json(),ex=GLOBAL_SETTINGS.redis_key_token_ex)
                    return current_user
                else:
                    logger.info(f'id: {user.id} 用户名: {user.username} 登录失败 密码错误')
                    raise UserPasswordIncorrectError
            else:
                logger.info(f'id: {user.id} 用户名: {user.username} 登录失败 用户账号不可用')
                raise UserInactiveError

        else:
            logger.info(f'用户名: {username} 登录失败 用户名不存在')
            raise UserNotFoundError

    # 登出
    async def logout(self, current_user: CurrentUserDM):
        # 路由层会通过依赖检查token是否有效，不会出现token已失效却仍可以进行注销的操作
        await self.redis_conn.delete(current_user.token)


user_service = UserService()
