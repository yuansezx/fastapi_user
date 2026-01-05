from datetime import datetime

from loguru import logger
from pytz import timezone

from app.core.domain_models import PermissionDM, ResourceDM
from app.core.redis_manager import redis_manager
from app.core.settings import GLOBAL_SETTINGS
from app.core.service import resource_service
from app.user.domain_models import RoleDM, CurrentUserDM
from app.user.exceptions import UserNotFoundError, UserPasswordIncorrectError, UserInactiveError, UsernameExistedError, \
    RoleNameExistedError, SystemUserProtectionError, SystemRoleProtectionError, RoleNotFoundError
from app.user.models import User, Role, User_Role, Role_Permission
from app.user.schemas import CreateUserInSchema, UserDataOutSchema, GetUsersOutSchema, CreateRoleInSchema, \
    UpdateUserInSchema, RoleDataOutSchema, GetRolesOutSchema, GetRolePermissionOut_ResourceSchema, \
    GetRolePermissionOut_Resource_PermissionSchema, GetRolePermissionsOutSchema
from app.user.utils import password_hash
from app.user.utils.jwt_wrapper import jwt_wrapper


class UserService:
    def __init__(self):
        self.User = User
        self.Role = Role
        self.User_Role = User_Role
        self.Role_Permission = Role_Permission
        self.resource_service = resource_service
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
        # 赋予超管所有权限，因为资源权限可能会随更新变化，所以每次启动都需要运行
        # 获取超管角色id
        role_id = await self.Role.get(name='superadmin').values_list('id', flat=True)
        # 获取所有权限id
        permission_ids = await resource_service.get_all_permission_ids()
        await self.update_role_permissions_by_ids(role_id, permission_ids)
        logger.info('初始化超级管理员 完成。')

    # 通过id更新角色权限
    async def update_role_permissions_by_ids(self, role_id, permission_ids: list[int]) -> None:
        """
        通过id赋予角色权限
        Args:
            role_id: 角色id
            permission_ids: 权限id列表

        Returns:

        """
        # 角色旧权限id列表
        old_permission_ids = set(
            await self.Role_Permission.filter(role_id=role_id).values_list('permission_id', flat=True))
        # 角色目标权限id列表
        target_permission_ids = set(permission_ids)
        # 计算需呀增加和移除的权限
        to_add_ids = target_permission_ids - old_permission_ids
        to_remove_ids = old_permission_ids - target_permission_ids
        if to_remove_ids:
            await self.Role_Permission.filter(role_id=role_id, permission_id__in=to_remove_ids).delete()
        if to_add_ids:
            new_assignments = [self.Role_Permission(role_id=role_id, permission_id=permission_id) for permission_id in
                               to_add_ids]
            await self.Role_Permission.bulk_create(new_assignments)

    # 读取user拥有的所有角色
    async def get_roles_by_user(self, user: User):
        roles = await self.Role.filter(user_assignments__user=user).all()
        return roles

    # 通过id更新用户拥有的角色
    async def update_user_roles_by_ids(self, user_id: int, role_ids: list[int]) -> None:
        """
        通过id更新用户拥有的角色
        Args:
            user_id: 用户id
            role_ids: 目标角色id列表

        Returns:

        """
        old_role_ids = set(await self.User_Role.filter(user_id=user_id).values_list('role_id', flat=True))
        target_role_ids = set(role_ids)
        to_add_ids = target_role_ids - old_role_ids
        to_remove_ids = old_role_ids - target_role_ids
        if to_remove_ids:
            await self.User_Role.filter(user_id=user_id, role_id__in=to_remove_ids).delete()
        if to_add_ids:
            new_assignments = [self.User_Role(user_id=user_id, role_id=role_id) for role_id in to_add_ids]
            await self.User_Role.bulk_create(new_assignments)

    # 通过数据库核查权限
    async def verify_permission_by_db(self, user_id: int, resource_code: str, permission_code: str) -> bool:
        """

        Args:
            user_id: 用户id
            resource_code: 资源码
            permission_code: 权限码

        Returns:

        """
        # 构造查询语句
        queryset = self.User.filter(id=user_id,
                                    role_assignments__role__permission_assignments__permission__resource__code=resource_code,
                                    role_assignments__role__permission_assignments__permission__code=permission_code)
        return await queryset.exists()

    # 登录
    async def login(self, username: str, password: str) -> CurrentUserDM:
        """
        用户登录
        Args:
            username: 用户名
            password: 密码

        Returns:
            current_user当前用户

        Raises:
            UserNotFoundError: 用户不存在
            UserPasswordIncorrectError: 用户密码错误
            UserInactiveError: 用户被锁定，禁止登录

        """
        user = await self.User.get_or_none(username=username)
        if user:
            # 是否被禁止登录
            if user.is_active:
                # 验证密码
                if password_hash.verify_password(password, user.password):
                    roles = await self.get_roles_by_user(user)
                    permissions = await self.resource_service.get_permissions_with_resources_by_role_ids(
                        [role.id for role in roles])
                    # resource去重
                    resource_dict = {permission.resource.id: permission.resource for permission in permissions}
                    resources = list(resource_dict.values())
                    # 转为DM
                    role_dms = [RoleDM(**role.to_dict()) for role in roles]
                    permissions_dms = [PermissionDM(**permission.to_dict(), resource_code=permission.resource.code) for
                                       permission in permissions]
                    resources_dms = [ResourceDM(**resource.to_dict()) for resource in resources]
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
                        resources=resources_dms)
                    # 记录到redis
                    await self.redis_conn.hset(f'app:user:current_user:{current_user.id}', current_user.token,
                                               current_user.model_dump_json())
                    await self.redis_conn.expire(f'app:user:current_user:{current_user.id}',
                                                 GLOBAL_SETTINGS.redis_key_token_ex)
                    # await self.redis_conn.set(current_user.token, current_user.model_dump_json(),
                    #                           ex=GLOBAL_SETTINGS.redis_key_token_ex)
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
        await self.redis_conn.hdel(f'app:user:current_user:{current_user.id}', current_user.token)

    # 创建用户
    async def create_user(self, data: CreateUserInSchema, current_user: CurrentUserDM) -> int:
        """
        创建用户
        Args:
            data: 用户数据
            current_user: 当前用户

        Returns:
            创建成功的用户id
        Raises:
            UsernameExistedError: 用户名已存在
        """
        # 昵称默认=username
        if not data.nickname:
            data.nickname = data.username
        # 判断username是否存在
        if await self.User.exists(username=data.username):
            raise UsernameExistedError
        # password加密
        data.password = password_hash.hash_password(data.password)
        user = await self.User.create(**data.model_dump(exclude={'role_ids'}), created_by_id=current_user.id)
        logger.info(
            f'用户【id:{current_user.id} username:{current_user.username}】创建用户【id:{user.id} username:{user.username}】')
        # 连接角色
        if data.role_ids:
            for role_id in data.role_ids:
                await self.User_Role.create(user=user, role_id=role_id)
            logger.info(
                f'用户【id:{current_user.id} username:{current_user.username}】分配用户【id:{user.id} username:{user.username}】角色【ids:{data.role_ids}】')
        return user.id

    # 删除多个用户
    async def delete_users(self, user_ids: set[int], current_user: CurrentUserDM) -> None:
        """
        删除多个用户
        Args:
            user_ids: 需要删除的用户们的id集合
            current_user: 当前用户

        Returns:
        """
        # 去掉删除自己的情况
        user_ids_new = user_ids - {current_user.id}
        # 删除非系统角色
        res = await self.User.filter(id__in=user_ids_new, is_system=False).delete()
        logger.info(
            f'用户【id:{current_user.id} username:{current_user.username}】尝试删除用户【ids:{user_ids}】，成功删除{res}个用户。')

    # 查看用户（分页）
    async def get_users(self, page: int, page_size: int, order_by: list[str]) -> GetUsersOutSchema:
        """
        查看用户（分页）
        Args:
            page: 第几页
            page_size: 每页显示的数据量
            order_by: 排序方式

        Returns:

        """
        total = await self.User.all().count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size
        users = await self.User.all().offset(offset).limit(page_size).order_by(*order_by)

        result = []
        for user in users:
            result.append(UserDataOutSchema(**user.to_dict()))

        return GetUsersOutSchema(total=total, total_pages=total_pages, page=page, page_size=page_size,
                                 order_by=order_by,
                                 data=result)

    # 修改用户信息
    async def update_user(self, user_id: int, data: UpdateUserInSchema, current_user: CurrentUserDM) -> None:
        """
        修改用户信息
        Args:
            user_id: 用户id
            data: 修改的用户信息
            current_user: 当前用户

        Returns:
        Raises:
            UserNotFoundError 用户不存在或用户为系统保留用户。
        """
        # 判断是否为系统保留用户
        if await self.User.filter(id=user_id, is_system=False).exists():
            # password加密
            if data.password:
                data.password = password_hash.hash_password(data.password)
            # 更改写入用户表
            await self.User.filter(id=user_id).update(**data.model_dump(exclude_unset=True),
                                                      updated_at=datetime.now(timezone('UTC')),
                                                      updated_by_id=current_user.id)
            # 如果用户在线则踢下线
            await self.redis_conn.delete(f'app:user:current_user:{user_id}')
        else:
            raise UserNotFoundError('用户不存在或用户为系统保留用户。')

    # 修改用户拥有的角色
    async def update_user_roles(self, user_id: int, role_ids: list[int]):
        """
        修改用户拥有的角色
        Args:
            user_id: 用户id
            role_ids: 角色id列表

        Returns:
        Raises:
            RoleNotFoundError('角色不存在或角色为系统保留角色。')
            UserNotFoundError('用户不存在或用户为系统保留用户。')
        """
        # 判断是否为系统保留用户
        if await self.User.filter(id=user_id, is_system=False).exists():
            # 挑选出有效role_id
            if valid_role_ids := await self.Role.filter(id__in=role_ids, is_system=False).values_list('id', flat=True):
                # 更改写入user_role表
                await self.update_user_roles_by_ids(user_id, valid_role_ids)
                # 如果用户在线则踢下线
                await self.redis_conn.delete(f'app:user:current_user:{user_id}')
            else:
                raise RoleNotFoundError('角色不存在或角色为系统保留角色。')
        else:
            raise UserNotFoundError('用户不存在或用户为系统保留用户。')

    # 创建角色
    async def create_role(self, data: CreateRoleInSchema, current_user: CurrentUserDM) -> int:
        """
        创建角色
        Args:
            data: 角色数据
            current_user: 当前用户

        Returns:
            角色id

        Raises:
            RoleNameExistedError 角色名已存在

        """
        if await self.Role.exists(name=data.name):
            raise RoleNameExistedError
        role = await self.Role.create(**data.model_dump(exclude={'permission_ids'}), created_by_id=current_user.id)
        # 赋予权限
        if data.permission_ids:
            await self.update_role_permissions_by_ids(role_id=role.id, permission_ids=data.permission_ids)
        logger.info(
            f'用户【id:{current_user.id} username:{current_user.username}】 创建角色【id:{role.id} name:{role.name}】')
        return role.id

    # 查看角色（分页）
    async def get_roles(self, page: int, page_size: int, order_by: list[str]) -> GetRolesOutSchema:
        """
        查看角色（分页）
        Args:
            page: 第几页
            page_size: 每页显示的数据量
            order_by: 排序方式

        Returns:

        """
        total = await self.Role.all().count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size
        roles = await self.Role.all().offset(offset).limit(page_size).order_by(*order_by)

        result = []
        for role in roles:
            result.append(RoleDataOutSchema(**role.to_dict()))

        return GetRolesOutSchema(total=total, total_pages=total_pages, page=page, page_size=page_size,
                                 order_by=order_by,
                                 data=result)

    # 查看角色所有权限
    async def get_role_permissions(self, role_id: int)-> GetRolePermissionsOutSchema:
        """
        查看角色的所有权限，输出按照resource归类，并且permission按照id排序
        Args:
            role_id: 角色id

        Returns:

        """
        permissions = await self.resource_service.get_permissions_with_resources_by_role_ids([role_id])
        # 格式化输出
        resources_dict: dict[int, GetRolePermissionOut_ResourceSchema] = {}
        for permission in permissions:
            resource = permission.resource
            # 若resource不在字典中，则初始化该resource
            if resource.id not in resources_dict:
                resources_dict[resource.id] = GetRolePermissionOut_ResourceSchema(**resource.to_dict(), permissions=[])
            # 将permission加入resource
            resources_dict[resource.id].permissions.append(
                GetRolePermissionOut_Resource_PermissionSchema(id=permission.id,
                                                               code=permission.code,
                                                               name=permission.name,
                                                               description=permission.description))
        resources=list(resources_dict.values())
        # permissions排一下序
        for resource in resources:
            resource.permissions.sort(key=lambda p: p.id)
        return GetRolePermissionsOutSchema(resources=resources)


user_service = UserService()
