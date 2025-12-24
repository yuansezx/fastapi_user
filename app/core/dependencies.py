# 依赖注入
from redis import asyncio as aioredis

from app.core.redis_manager import redis_manager

"""基础层依赖"""
def get_redis_conn() -> aioredis.Redis:
    return redis_manager.redis_pool
