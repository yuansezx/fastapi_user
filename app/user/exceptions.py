"""user模块 exceptions"""


class UserNotFoundError(Exception):
    def __init__(self, msg: str = '用户不存在'):
        super().__init__(msg)


class UserPasswordIncorrectError(Exception):
    pass


class UserInactiveError(Exception):
    pass


class UsernameExistedError(Exception):
    pass


class RoleNameExistedError(Exception):
    pass


class SystemUserProtectionError(Exception):
    def __init__(self, msg: str = '用户为系统保留用户，不可变更。') -> None:
        super().__init__(msg)


class SystemRoleProtectionError(Exception):
    def __init__(self, msg: str = '角色为系统保留角色，不可变更。'):
        super().__init__(msg)


class RoleNotFoundError(Exception):
    def __init__(self, msg='角色不存在'):
        super().__init__(msg)

