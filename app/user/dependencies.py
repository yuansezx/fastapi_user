import jwt
from fastapi import Cookie, Depends, HTTPException

from app.core.dependencies import get_redis_conn
from app.user.domain_models import CurrentUserDM
from app.user.utils.jwt_wrapper import jwt_wrapper

"""路由层依赖"""


# 权限验证
def get_current_user(module_code: str, permission_code: str):
    async def inner(token: str = Cookie(None), redis_conn=Depends(get_redis_conn)) -> CurrentUserDM:
        if token:
            try:
                payload = jwt_wrapper.get_payload(token)
            except jwt.InvalidTokenError:
                raise HTTPException(401, '无效凭证，请重新登录。')
            # 加载token对应的缓存
            data_json = await redis_conn.get(token)
            # 判断token是否被拉黑
            if data_json:
                current_user = CurrentUserDM.model_validate_json(data_json)
                # 检查权限
                if current_user.has_permission(module_code, permission_code):
                    return current_user
                else:
                    raise HTTPException(403, '权限不足。')
            else:
                raise HTTPException(401, '无效凭证，请重新登录。')
        else:
            raise HTTPException(401, '未登录。')

    return inner
