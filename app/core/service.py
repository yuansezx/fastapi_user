from loguru import logger

from app.core.models import Resource, Permission
from app.core.schemas import RegisterResourceInSchema


class ResourceService:
    def __init__(self):
        self.Resource = Resource
        self.Permission = Permission

    async def register_resource(self, data: RegisterResourceInSchema) -> None:
        # 最好改为删除并重写,因为如果模块code/权限code修改，会直接新建条目，废弃的条目不会被删除

        # 往数据库写入资源数据
        resource, _ = await self.Resource.update_or_create(data.model_dump(exclude={'permissions', 'code'}),
                                                           code=data.code)
        # 往数据库写入权限数据
        for permission in data.permissions:
            await self.Permission.update_or_create(permission.model_dump(exclude={'code'}), resource=resource,
                                                   code=permission.code)
        logger.info(f'注册资源【{resource.name}】 完成。')

    async def get_all_permission_ids(self) -> list[int]:
        """获取所有权限数据"""
        return await self.Permission.all().values_list('id', flat=True)

    async def get_all_resources_with_permissions(self) -> list[Resource]:
        """获取所有资源数据及其所有权限"""
        return await self.Resource.all().prefetch_related('permissions')

    async def get_permissions_with_resources_by_role_ids(self, role_ids: list) -> list[Permission]:
        """
        查找目标角色们的所有权限，附带可调用的resource（资源表模型对象）
        Args:
            role_ids:

        Returns:

        """
        return await self.Permission.filter(role_assignments__role_id__in=role_ids).select_related(
            'resource').distinct().all()

resource_service = ResourceService()
