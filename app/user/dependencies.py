import jwt
from fastapi import Cookie, Depends, HTTPException

from app.core.dependencies import get_redis_conn
from app.user.service import user_service
from app.user.schemas import CurrentUser
from app.user.utils.jwt_wrapper import jwt_wrapper

"""路由层依赖"""


# 权限验证
def get_current_user(module_code: str, permission_code: str):
    async def inner(token: str = Cookie(None), redis_conn=Depends(get_redis_conn)) -> CurrentUser | None:
        if token:
            try:
                payload = jwt_wrapper.get_payload(token)
            except jwt.InvalidTokenError:
                raise HTTPException(401, '无效凭证，请重新登录。')
            # 判断token是否被拉黑
            result = await redis_conn.get(token)
            if result:
                raise HTTPException(401, '无效凭证，请重新登录。')
            # 检查权限
            if module_code and permission_code:
                has_permission = await user_service.verify_permission(payload['user_id'], module_code, permission_code)
            else:
                has_permission = True
            if has_permission:
                return CurrentUser(token=token, payload=payload, user_id=payload['user_id'],
                                   username=payload['username'])
            else:
                raise HTTPException(403, '权限不足。')
        else:
            raise HTTPException(401, '未登录。')

    return inner
