from loguru import logger

from app.core.models import Module, Permission
from app.core.service.schemas import RegisterModuleInSchema


class ModuleService:
    def __init__(self):
        self.Module = Module
        self.Permission = Permission

    async def register_module(self, data: RegisterModuleInSchema) -> None:
        # 最好改为删除并重写,因为如果模块code/权限code修改，会直接新建条目，废弃的条目不会被删除

        # 往数据库写入模块数据
        module , _= await self.Module.update_or_create(data.model_dump(exclude={'permissions','code'}),code=data.code)
        # 往数据库写入权限数据
        for permission in data.permissions:
            await self.Permission.update_or_create(permission.model_dump(exclude={'code'}), module=module,code=permission.code)
        logger.info(f'注册{module.name} 完成。')

    async def get_all_modules_with_permissions(self) -> list[Module]:
        return await self.Module.all().prefetch_related('permissions')


module_service = ModuleService()
