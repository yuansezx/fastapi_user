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
