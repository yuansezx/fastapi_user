"""user模块 exceptions"""


class UserNotFoundError(Exception):
    pass

class UserPasswordIncorrectError(Exception):
    pass

class UserInactiveError(Exception):
    pass

class UsernameExistedError(Exception):
    pass

class RoleNameExistedError(Exception):
    pass