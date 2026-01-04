from fastapi import APIRouter, Response, Body, HTTPException, status, Query
from fastapi.params import Depends

from app.core.schemas import FailResSchema
from app.user.service import user_service
from app.user.dependencies import get_current_user
from app.user.exceptions import UserInactiveError, UserPasswordIncorrectError, UserNotFoundError, UsernameExistedError
from app.user.schemas import UserLoginResSchema, CreateUserReqSchema, CreateUserResSchema

user_router = APIRouter()


# 用户登录
@user_router.post("/login", summary='用户登录',
                  responses={200: {'model': UserLoginResSchema},
                             401: {'model': FailResSchema, 'description': 'detail="用户名或密码错误。"'},
                             403: {'model': FailResSchema, 'description': 'detail="用户账号不可用，请联系管理员。"'}})
async def login(response: Response, username: str = Body(), password: str = Body()):
    try:
        current_user = await user_service.login(username, password)
    except UserInactiveError:
        raise HTTPException(403, '用户账号不可用，请联系管理员。')
    except UserNotFoundError or UserPasswordIncorrectError:
        raise HTTPException(401, '用户名或密码错误。')
    # 设置cookie
    response.set_cookie('token', current_user.token, samesite='none', secure=True)
    return UserLoginResSchema(**current_user.model_dump())


# 用户注销
@user_router.post('/logout', summary='用户注销', status_code=204)
async def logout(response: Response, current_user=Depends(get_current_user({'user':''}))):
    await user_service.logout(current_user)
    response.delete_cookie('token')


# 创建用户
@user_router.post('', summary='创建用户', status_code=status.HTTP_201_CREATED,
                  responses={201: {'model': CreateUserResSchema},
                             400: {'model': FailResSchema, 'description': "detail:'用户名已存在。'"}})
async def create_user(data: CreateUserReqSchema, current_user=Depends(get_current_user({'user':'create'}))):
    try:
        user_id = await user_service.create_user(data, current_user)
    except UsernameExistedError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, '用户名已存在。')
    return CreateUserResSchema(user_id=user_id)

# # 查看所有用户(分页)
# @user_router.get('',summary='查看所有用户（分页）')
# async def get_users(page:int = Query(1, gt=0,description='请求第几页的数据'),
#                     page_size:int=Query(20,gt=0,le=100,description='每页显示多少条数据'),
#                     order_by:list[str]=Query('id'),description='排序方式',
#                     current_user=Depends(get_current_user({'user':'get'}))):


# 删除用户
@user_router.delete('/{user_id}', summary='删除单个用户', status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: int, current_user=Depends(get_current_user({'user':'delete'}))):
    await user_service.delete_users([user_id], current_user)


# 删除多个用户
@user_router.delete('', summary='删除多个用户', status_code=status.HTTP_204_NO_CONTENT)
async def delete_users(user_ids: set[int] = Body(), current_user=Depends(get_current_user({'user':'delete'}))):
    await user_service.delete_users(user_ids, current_user)



@user_router.post('/test', summary='测试')
async def test(current_user=Depends(get_current_user({'user':'read'}))):
    return current_user
