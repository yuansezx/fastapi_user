from tortoise import Model, fields


class Resource(Model):
    """资源表"""
    id = fields.IntField(pk=True)
    code = fields.CharField(max_length=20, unique=True)
    name = fields.CharField(max_length=20)
    description = fields.CharField(max_length=100, null=True)

    def to_dict(self):
        return {
            "id": self.id,
            "code": self.code,
            "name": self.name,
            "description": self.description
        }



class Permission(Model):
    """权限表"""
    id = fields.IntField(pk=True)
    code = fields.CharField(max_length=20)
    name = fields.CharField(max_length=20)
    description = fields.CharField(max_length=100, null=True)
    resource = fields.ForeignKeyField("models.Resource", on_delete=fields.CASCADE, related_name="permissions")

    class Meta:
        unique_together = ("resource", "code")

    def to_dict(self):
        return {
            "id": self.id,
            "code": self.code,
            "name": self.name,
            "description": self.description,
            "resource_id": self.resource_id
        }


class User(Model):
    """用户表"""
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=20, unique=True)
    nickname = fields.CharField(max_length=20)
    password = fields.CharField(max_length=60)
    created_at = fields.DatetimeField(auto_now_add=True)
    # 更改last_login_at字段不更改updated_at
    updated_at = fields.DatetimeField(null=True)
    # 是否允许登录
    is_active = fields.BooleanField(default=False)
    # 是否为系统保留用户
    is_system = fields.BooleanField(default=False)
    last_login_at = fields.DatetimeField(null=True)
    # create_by外键指向自身,on_delete设置为受限模式
    created_by = fields.ForeignKeyField('models.User', null=True, on_delete=fields.SET_NULL,
                                        related_name='created_users', )
    updated_by = fields.ForeignKeyField('models.User', null=True, on_delete=fields.RESTRICT,
                                        related_name='updated_users')

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'nickname': self.nickname,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'is_active': self.is_active,
            'is_system': self.is_system,
            'last_login_at': self.last_login_at,
            'created_by_id': self.created_by_id,
            'updated_by_id': self.updated_by_id
        }

    async def to_dict_with_roles(self):
        """
        带有角色
        需要先使用预加载用于减少数据库查询 prefetch_related('role_assignments__role')
        Returns:

        """
        await self.fetch_related('role_assignments__role')
        role_dicts = [assignment.role.to_dict() for assignment in self.role_assignments]
        data_dict = self.to_dict()
        data_dict['roles'] = role_dicts
        return data_dict


class Role(Model):
    """角色表"""
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=20, unique=True)
    description = fields.CharField(max_length=100, null=True)
    # 记录是否为系统内置/保留角色
    is_system = fields.BooleanField(default=False)
    created_at = fields.DatetimeField(auto_now_add=True)
    created_by = fields.ForeignKeyField('models.User', on_delete=fields.RESTRICT, related_name='created_roles')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_system': self.is_system,
            'created_at': self.created_at,
            'created_by_id': self.created_by_id
        }


class User_Role(Model):
    """用户-角色关系表"""
    id = fields.IntField(pk=True)
    user = fields.ForeignKeyField('models.User', on_delete=fields.CASCADE, related_name='role_assignments')
    role = fields.ForeignKeyField('models.Role', on_delete=fields.CASCADE, related_name='user_assignments')

    class Meta:
        unique_together = ('user', 'role')


class Role_Permission(Model):
    """角色-权限关系表"""
    id = fields.IntField(pk=True)
    role = fields.ForeignKeyField('models.Role', on_delete=fields.CASCADE, related_name='permission_assignments')
    permission = fields.ForeignKeyField('models.Permission', on_delete=fields.CASCADE, related_name='role_assignments')

    class Meta:
        unique_together = ('role', 'permission')
