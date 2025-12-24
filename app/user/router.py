from fastapi import APIRouter, Response, Body, HTTPException
from fastapi.params import Depends

from app.core.schemas import FailResSchema
from app.user.service import user_service
from app.user.dependencies import get_current_user
from app.user.exceptions import UserInactiveError, UserPasswordIncorrectError, UserNotFoundError
from app.user.schemas import UserLoginResSchema

user_router = APIRouter()


@user_router.post("/login", summary='用户登录', response_model=UserLoginResSchema,
                  responses={401: {'model': FailResSchema, 'description': 'detail="用户名或密码错误。"'},
                             403: {'model': FailResSchema, 'description': 'detail="用户账号不可用，请联系管理员。"'}})
async def login(response: Response, username: str = Body(), password: str = Body()):
    try:
        token, last_login_at = await user_service.login(username, password)
    except UserInactiveError:
        raise HTTPException(403, '用户账号不可用，请联系管理员。')
    except UserNotFoundError or UserPasswordIncorrectError:
        raise HTTPException(401, '用户名或密码错误。')
    # 设置cookie
    response.set_cookie('token', token, samesite='none', secure=True)
    return UserLoginResSchema(username=username, last_login_at=last_login_at)


@user_router.post('/logout',summary='用户注销',status_code=204)
async def logout(response: Response,current_user=Depends(get_current_user('user',''))):
    await user_service.logout(current_user)
    response.delete_cookie('token')