#services/my_web_app/my_web_app/wsgi.py
import os
from django.core.wsgi import get_wsgi_application

# Khai báo môi trường settings cho Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'my_web_app.settings')

# Đây là biến mà Docker đang tìm kiếm và báo lỗi thiếu:
application = get_wsgi_application()