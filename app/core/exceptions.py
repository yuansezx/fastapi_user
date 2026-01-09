from fastapi import status,Request
from fastapi.responses import JSONResponse
from loguru import logger



# 兜底
async def global_exception_handler(request:Request,exception:Exception):
    logger.error(exception)
    return JSONResponse({'detail':'服务器错误'},status.HTTP_500_INTERNAL_SERVER_ERROR)