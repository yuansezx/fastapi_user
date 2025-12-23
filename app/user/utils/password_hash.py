import bcrypt

class PasswordHash:
    # 哈希加密
    @staticmethod
    def hash_password(password:str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    # 验证密码
    @staticmethod
    def verify_password(password:str, password_hashed:str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'),password_hashed.encode('utf-8'))
