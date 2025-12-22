from pathlib import Path
from decouple import config  # Библиотека для управления переменными окружения

# Определяем базовую директорию проекта
BASE_DIR = Path(__file__).resolve().parent.parent

# Секретный ключ приложения, считываемый из переменных окружения
SECRET_KEY = config('SECRET_KEY')

# Секретный ключ JWT, считываемый из переменных окружения
JWT_SECRET = config('SECRET_JWT_KEY')

# Режим отладки: включается/выключается через переменные окружения
DEBUG = config('DEBUG', default=False, cast=bool)

# Разрешенные хосты для развертывания проекта
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='').split(',')

# Список приложений Django (встроенные)
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

# Локальные приложения проекта (созданные пользователем)
LOCAL_APPS = [
    'app',
]

# Сторонние приложения, установленные через pip
THIRD_PARTY_APPS = [
    'rest_framework',
    'drf_yasg',
]

# Полный список установленных приложений
INSTALLED_APPS = DJANGO_APPS + LOCAL_APPS + THIRD_PARTY_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# Корневая конфигурация URL
ROOT_URLCONF = "test_em.urls"

# Настройки шаблонов Django
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / 'templates']
        ,
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# WSGI-приложение
WSGI_APPLICATION = "test_em.wsgi.application"

# Настройки базы данных (SQLite по умолчанию, PostgreSQL через переменные окружения)
if config('USE_POSTGRESQL', default=False, cast=bool):
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': config('POSTGRES_DB'),
            'USER': config('POSTGRES_USER'),
            'PASSWORD': config('POSTGRES_PASSWORD'),
            'HOST': config('POSTGRES_HOST', default='localhost'),
            'PORT': config('POSTGRES_PORT', default='5432'),
        }
    }
else:
    db_path = BASE_DIR / "db.sqlite3"

    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            # "NAME": BASE_DIR / "db.sqlite3",
            "NAME": db_path,
        }
    }

# Валидаторы паролей
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Язык и часовой пояс проекта
LANGUAGE_CODE = "ru-ru"
TIME_ZONE = "UTC"

# Включение интернационализации и поддержки часовых зон
USE_I18N = True
USE_TZ = True

# Настройки для статических файлов
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "static"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# Автоматическое поле первичного ключа по умолчанию
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ===== Настройки DRF =====
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        'app.backends.JWTAuthentication',

    ],
    "DEFAULT_PERMISSION_CLASSES": [
        'rest_framework.permissions.IsAuthenticated',
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",  # Удалить в проде
    ],
    "UNAUTHENTICATED_USER": None,
    "UNAUTHENTICATED_TOKEN": None,
}

# Настройки для BCrypt
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

# Настройки пользовательской модели пользователя
AUTH_USER_MODEL = 'app.User'

# Настройки для SWAGGER
SWAGGER_SETTINGS = {
    'USE_SESSION_AUTH': False,
    'API_URL': '/api/',  # базовый URL для вашего API
    'DOC_EXPANSION': 'none',  # Сворачивает все эндпоинты по умолчанию
    'VALIDATOR_URL': None,  # Отключает валидацию Swagger
    'OPERATIONS_SORTER': 'alpha',
    'TAGS_SORTER': 'alpha',
    'SHOW_REQUEST_HEADERS': True,  # Показывает заголовки запроса
    'SUPPORTED_SUBMIT_METHODS': ['get', 'post', 'put', 'delete', 'patch'],
    'SECURITY': [{'sessionAuth': []}],
    'PERSIST_AUTH': True,  # Сохраняет авторизацию между запросами
    'SECURITY_DEFINITIONS': {
        'sessionAuth': {
            'type': 'apiKey',
            'description': (
                'Токен для авторизации. Передавайте его в заголовке `Authorization` в формате `Bearer <token>`'),
            'name': 'Authorization',
            'in': 'header'
        }
    },
}
