from fastapi import APIRouter, Response, Body, HTTPException, status, Query
from fastapi.params import Depends

from app.core.schemas import FailResSchema
from app.user.service import user_service
from app.user.dependencies import get_current_user
from app.user.exceptions import UserInactiveError, UserPasswordIncorrectError, UserNotFoundError, UsernameExistedError, \
    RoleNotFoundError
from app.user.schemas import UserLoginResSchema, CreateUserReqSchema, CreateUserResSchema, GetUsersResSchema, \
    CreateRoleReqSchema, UpdateUserReqSchema, UpdateUserInSchema, GetRolesResSchema, GetRolePermissionsResSchema, \
    UpdateRoleReqSchema

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
async def logout(response: Response, current_user=Depends(get_current_user({'users': ''}))):
    await user_service.logout(current_user)
    response.delete_cookie('token')


# 创建用户
@user_router.post('/users', summary='创建用户', status_code=status.HTTP_201_CREATED,
                  responses={201: {'model': CreateUserResSchema},
                             400: {'model': FailResSchema, 'description': "detail:'用户名已存在。'"}})
async def create_user(data: CreateUserReqSchema, current_user=Depends(get_current_user({'users': 'create'}))):
    try:
        user_id = await user_service.create_user(data, current_user)
    except UsernameExistedError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, '用户名已存在。')
    return CreateUserResSchema(user_id=user_id)


# 查看所有用户(分页)
@user_router.get('/users', summary='查看所有用户（分页）', responses={200: {'model': GetUsersResSchema}})
async def get_users(page: int = Query(1, gt=0, description='请求第几页的数据'),
                    page_size: int = Query(20, gt=0, le=100, description='每页显示多少条数据'),
                    order_by: list[str] = Query(['id'], description='排序方式'),
                    current_user=Depends(get_current_user({'users': 'read'}))):
    users = await user_service.get_users(page, page_size, order_by)
    return users


# 修改用户信息
@user_router.patch('/users/{user_id}', summary='更改用户信息', status_code=status.HTTP_204_NO_CONTENT)
async def update_user(user_id: int, data: UpdateUserReqSchema,
                      current_user=Depends(get_current_user({'users': 'update'}))):
    try:
        await user_service.update_user(user_id, data, current_user)
    except UserNotFoundError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))


# 修改用户拥有的角色
@user_router.put('/user/{user_id}/roles', summary='更改用户拥有的角色', status_code=status.HTTP_204_NO_CONTENT)
async def update_user_roles(user_id: int, role_ids: list[int] = Body(),
                            current_user=Depends(get_current_user({'users': 'update'}))):
    try:
        await user_service.update_user_roles(user_id, role_ids)
    except UserNotFoundError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    except RoleNotFoundError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))


# 删除用户
@user_router.delete('/users/{user_id}', summary='删除单个用户', status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: int, current_user=Depends(get_current_user({'users': 'delete'}))):
    await user_service.delete_users([user_id], current_user)


# 删除多个用户
@user_router.delete('/users', summary='删除多个用户', status_code=status.HTTP_204_NO_CONTENT)
async def delete_users(user_ids: set[int] = Body(), current_user=Depends(get_current_user({'users': 'delete'}))):
    await user_service.delete_users(user_ids, current_user)


# 创建角色
@user_router.post('/roles', summary='创建角色', status_code=status.HTTP_201_CREATED)
async def create_role(data: CreateRoleReqSchema, current_user=Depends(get_current_user({'roles': 'create'}))):
    role_id = await user_service.create_role(data, current_user)
    return {'role_id': role_id}


# 查看角色（分页）
@user_router.get('/roles', summary='查看角色（分页）', responses={200: {'model': GetRolesResSchema}})
async def get_roles(page: int = Query(1, gt=0, description='请求第几页的数据'),
                    page_size: int = Query(20, gt=0, le=100, description='每页显示多少条数据'),
                    order_by: list[str] = Query(['id'], description='排序方式'),
                    current_user=Depends(get_current_user({'roles': 'read'}))):
    result = await user_service.get_roles(page, page_size, order_by)
    return result


# 查看角色的所有权限
@user_router.get('/roles/{role_id}/permissions', summary='查看角色的所有权限',
                 responses={200: {'model': GetRolePermissionsResSchema}})
async def get_role_permissions(role_id: int, current_user=Depends(get_current_user({'roles': 'read'}))):
    result = await user_service.get_role_permissions(role_id)
    return result


# 更改角色信息
@user_router.patch('/roles/{role_id}', summary='更改角色信息', status_code=status.HTTP_204_NO_CONTENT)
async def update_role(role_id: int, data: UpdateRoleReqSchema,
                      current_user=Depends(get_current_user({'roles': 'update'}))):
    try:
        await user_service.update_role(role_id, data, current_user)
    except RoleNotFoundError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))


# 更改角色拥有的权限
@user_router.put('/roles/{role_id}/permissions', summary='更改角色拥有的权限', status_code=status.HTTP_204_NO_CONTENT)
async def update_role_permissions(role_id: int, data: list[int] = Body(),current_user=Depends(get_current_user({'roles': 'update'}))):
    try:
        await user_service.update_role_permissions(role_id, data, current_user)
    except RoleNotFoundError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))

# 查看所有权限



@user_router.post('/test', summary='测试')
async def test(current_user=Depends(get_current_user({'users': 'read'}))):
    return current_user
