# 全局配置,包括数据库配置,jwt配置
import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict, PydanticBaseSettingsSource, YamlConfigSettingsSource


class GlobalSettings(BaseSettings):
    model_config = SettingsConfigDict(
        # 配置文件config.yaml
        yaml_file=['config_dev.yaml', 'config_prod.yaml'],
        yaml_file_encoding='utf-8',
        extra='ignore'
    )

    # hook,配置 '配置源' 及其优先级
    @classmethod
    def settings_customise_sources(
            cls,
            settings_cls: type[BaseSettings],
            init_settings: PydanticBaseSettingsSource,
            env_settings: PydanticBaseSettingsSource,
            dotenv_settings: PydanticBaseSettingsSource,
            file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        yaml_settings = YamlConfigSettingsSource(settings_cls)
        return yaml_settings, init_settings, env_settings, dotenv_settings, file_secret_settings

    # docs url
    docs_url : str = None
    redoc_url : str = None

    # cors
    cors_allowed_origins : list[str] | None = None

    # jwt配置
    jwt_secret_key: str | None = None
    jwt_algorithm: str = 'HS256'
    jwt_token_expire_minutes: int = 30

    # 是否需要初始化数据库
    need_init_db: bool = True

    # log文件位置
    logs_path: Path = Path('./logs')

    # orm配置
    tortoise_orm_config: dict | None = None

    # redis配置
    redis_config: dict | None = None
    # redis中token键值的过期时间 秒
    redis_key_token_ex: int | None = None


    def __init__(self):
        super().__init__()
        # orm默认配置
        if not self.tortoise_orm_config:
            self.tortoise_orm_config = {
                'connections': {
                    'default': 'sqlite://db.sqlite3'
                },
                'apps': {
                    'models': {
                        'models': ['app.user.models', 'aerich.models'],
                        'default_connection': 'default',
                    }
                },
                'use_tz': True,  # 是否使用时区
                'timezone': 'Asia/Shanghai',  # 默认时区
                'db_pool': {
                    'max_size': 10,
                    'min_size': 1,
                    'idle_timeout': 30  # 空闲连接超时
                }
            }
        # redis_key_ex默认配置
        if self.redis_key_token_ex is None:
            self.redis_key_token_ex = self.jwt_token_expire_minutes * 60
        # jwt默认配置
        if self.jwt_secret_key is None:
            self.jwt_secret_key = secrets.token_hex(32)

GLOBAL_SETTINGS = GlobalSettings()
