"""main_app初始化"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.exceptions import global_exception_handler
from app.core.settings import GLOBAL_SETTINGS
from app import core


# fastapi 生命周期管理
@asynccontextmanager
async def lifespan(app: FastAPI):
    await core.start()

    # 挂载路由
    from app.user.router import user_router
    app.include_router(user_router, prefix="/api")

    yield

    await core.stop()


def create_app():
    app = FastAPI(title='基于角色的权限管理', lifespan=lifespan, docs_url=GLOBAL_SETTINGS.docs_url,
                  redoc_url=GLOBAL_SETTINGS.redoc_url)
    # 注册全局异常处理函数
    app.add_exception_handler(Exception, global_exception_handler)

    # cors
    app.add_middleware(CORSMiddleware, allow_origins=GLOBAL_SETTINGS.cors_allowed_origins, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])

    return app


main_app = create_app()
