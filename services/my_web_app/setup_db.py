import os
import sys
import django
import time
from psycopg2 import OperationalError

# Khai báo môi trường settings cho Django giống với manage.py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'my_web_app.settings')

# Khởi tạo Django
django.setup()

from django.core.management import call_command
from django.contrib.auth.models import User
from django.db import connections

def wait_for_db():
    """Hàm này giúp web1 đợi cho đến khi PostgreSQL trên db1 sẵn sàng"""
    db_conn = connections['default']
    print("⏳ Đang chờ PostgreSQL (10.0.0.20:5432) khởi động...")
    for i in range(10):
        try:
            db_conn.ensure_connection()
            print("✅ Database đã sẵn sàng!")
            return True
        except OperationalError:
            print(f"  Thử lại lần {i+1}/10...")
            time.sleep(2)
    return False

def main():
    if not wait_for_db():
        print("Lỗi: Không thể kết nối đến Database. Hủy khởi tạo!")
        sys.exit(1)

    # 1. Chạy lệnh migrate để tạo cấu trúc 100% các bảng
    print("Đang tạo cấu trúc các bảng dữ liệu...")
    call_command('migrate', interactive=False)

    # 2. Tự động tạo tài khoản Superuser (để đăng nhập)
    print("Đang tạo tài khoản Admin...")
    if not User.objects.filter(username='admin').exists():
        User.objects.create_superuser('admin', 'admin@uneti.edu.vn', 'admin')
        print("Đã tạo tài khoản: admin / admin")
    else:
        print("Tài khoản admin đã tồn tại.")

    # 3. Tự động "bơm" dữ liệu giả (Dummy Data)
    print("Đang gieo mầm dữ liệu ảo (Seeding)...")
    for i in range(1, 6):
        username = f'uneti_user_{i}'
        if not User.objects.filter(username=username).exists():
            User.objects.create_user(username=username, password='password123')
            print(f"   + Tạo thành công: {username}")

    print("HOÀN TẤT KHỞI TẠO CƠ SỞ DỮ LIỆU!")

if __name__ == '__main__':
    main()