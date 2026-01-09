from datetime import datetime,timedelta
import jwt
from pytz import timezone

from app.core.settings import GLOBAL_SETTINGS

class JWTWrapper:
    def __init__(self,secret_key:str,algorithm:str='HS256',token_expire_minutes:int=30):
        self.__secret_key = secret_key
        self.__algorithm = algorithm
        self.__token_expire_minutes = token_expire_minutes

    def create_token(self,data:dict) -> str:
        # 浅拷贝
        payload = data.copy()
        payload.update({'exp':datetime.now(timezone('UTC'))+timedelta(minutes=self.__token_expire_minutes)})
        token=jwt.encode(payload, self.__secret_key, self.__algorithm)
        return token

    def get_payload(self,token:str) -> dict:
        """
        获取payload
        :param token:
        :return:
        :raise jwt.ExpiredSignatureError: jwt.InvalidTokenError的子类，token过期
        :raise jwt.InvalidTokenError: token无效
        """
        payload = jwt.decode(token, self.__secret_key, [self.__algorithm])
        return payload

jwt_wrapper = JWTWrapper(GLOBAL_SETTINGS.jwt_secret_key,GLOBAL_SETTINGS.jwt_algorithm,GLOBAL_SETTINGS.jwt_token_expire_minutes)