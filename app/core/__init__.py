import sys

from aerich import Command
from loguru import logger
from tortoise import Tortoise

from app.core.settings import GLOBAL_SETTINGS
from app.core.redis_manager import redis_manager



# 初始化loguru
def init_logger():
    GLOBAL_SETTINGS.logs_path.mkdir(parents=True, exist_ok=True)
    # 移除原生控制台输出
    logger.remove()
    # 添加控制台输出
    logger.add(sys.stderr, colorize=True, level="INFO",
               format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}  - {message}")
    # 所有模块的log写入app.log
    logger.add(GLOBAL_SETTINGS.logs_path / 'app.log',
               level='INFO',
               format='{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}  - {message}',
               encoding='utf-8',
               enqueue=True  # 异步
               )
    # error级别log单独写入error.log
    logger.add(GLOBAL_SETTINGS.logs_path / 'error.log',
               level='ERROR',
               format='{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}  - {message}',
               encoding='utf-8',
               enqueue=True)
    logger.info('日志初始化完成。')


# 初始化数据库
async def init_db() -> None:
    # 创建command实例，传入tortoise-orm配置
    command = Command(tortoise_config=GLOBAL_SETTINGS.tortoise_orm_config)
    # shell中aerich init-db操作     safe=True 仅当表不存在时才创建
    try:
        await command.init_db(safe=True)
    # 忽略迁移目录已存在的报错
    except FileExistsError:
        pass
    logger.info('orm初始化 完成。')
    logger.info('数据库表初始化 完成。')


# 初始化资源
async def register_resources() -> None:
    from app import user
    await user.register_resources()

# 启动
async def start() -> None:
    """app启动的初始化准备"""
    # 初始化日志
    init_logger()
    # 判断是否需要初始化数据库表
    if GLOBAL_SETTINGS.need_init_db:
        await init_db()
    # 否则手动初始化orm
    else:
        await Tortoise.init(config=GLOBAL_SETTINGS.tortoise_orm_config)
        logger.info('orm初始化 完成。')
    # 初始化redis连接池
    redis_manager.create_pool()
    # 注册模块
    await register_resources()
    # 初始化超管
    from app import user
    await user.init_superadmin()

# 关闭
async def stop() -> None:
    """app关闭的收尾工作"""
    # 关闭redis连接池
    await redis_manager.close_pool()
    # 关闭数据库连接
    await Tortoise.close_connections()
    logger.info('关闭orm数据库连接。')
