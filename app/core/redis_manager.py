from loguru import logger
from redis import asyncio as aioredis

from app.core.settings import GLOBAL_SETTINGS


class RedisManager:
    def create_pool(self):
        self.redis_pool = aioredis.Redis(**GLOBAL_SETTINGS.redis_config)
        logger.info('redis连接池初始化完成。')

    async def close_pool(self):
        await self.redis_pool.close()
        logger.info('关闭redis连接池。')



redis_manager = RedisManager()