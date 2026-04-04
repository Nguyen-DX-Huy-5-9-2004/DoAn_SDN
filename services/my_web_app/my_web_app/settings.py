#services/my_web_app/my_web_app/settings.py
import os
from pathlib import Path

# Đường dẫn gốc của dự án
BASE_DIR = Path(__file__).resolve().parent.parent

# --- CẤU HÌNH BẢO MẬT (Dùng cho Lab) ---
SECRET_KEY = 'django-insecure-sdn-lab-uneti-key-12345'
DEBUG = True
# Cho phép tất cả các Host trong mạng SDN (h60, h1, ...) truy cập
ALLOWED_HOSTS = ['*']
CSRF_TRUSTED_ORIGINS = [
    "https://10.0.0.10",
    "https://127.0.0.1:8443",
    "http://10.0.0.11",
]

# --- CÁC ỨNG DỤNG HỆ THỐNG ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Nếu bạn đã tạo app 'core' thì thêm vào đây:
    # 'core', 
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware', # Tắt CSRF để normal.py dễ dàng mô phỏng POST request
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'my_web_app.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'my_web_app' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'my_web_app.wsgi.application'

# --- CẤU HÌNH DATABASE (Đúng như bạn yêu cầu) ---
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'postgres',
        'USER': 'postgres',
        'PASSWORD': 'root',    # Khớp với POSTGRES_PASSWORD trong system.py
        'HOST': '10.0.0.20',   # IP của máy db1 trong Mininet
        'PORT': '5432',
    }
}

# --- CÁC CẤU HÌNH KHÁC ---
AUTH_PASSWORD_VALIDATORS = [] # Tắt kiểm tra pass cho nhẹ máy Lab

LANGUAGE_CODE = 'vi-vn'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'