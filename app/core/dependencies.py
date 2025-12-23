# 依赖注入
from redis import asyncio as aioredis
from fastapi import Request


class AppCache:
    # 获取redis连接池
    @staticmethod
    def get_redis_conn(request: Request) -> aioredis.Redis:
        return request.app.state.redis_pool
