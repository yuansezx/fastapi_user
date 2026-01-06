from pydantic import BaseModel

"""服务层schema"""



"""路由层schemas"""


class FailResSchema(BaseModel):
    detail: str
