#services/my_web_app/my_web_app/urls.py
from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse

# Hàm xử lý trang chủ
def home(request):
    if request.user.is_authenticated:
        return HttpResponse(f"""
            <body style='font-family: sans-serif; text-align: center; padding-top: 50px;'>
                <h1 style='color: #2c3e50;'>Chào mừng, {request.user.username}!</h1>
                <p style='font-size: 1.2em;'>Hệ thống Web Đồ án SDN - UNETI</p>
                <p>Trạng thái: <span style='color: #27ae60;'>Đang hoạt động ổn định</span></p>
                <hr style='width: 50%;'>
                <p>Địa chỉ IP Server: 10.0.0.10</p>
                <p>Cơ sở dữ liệu: PostgreSQL (10.0.0.20)</p>
                <a href='/accounts/logout/'>Đăng xuất</a>
            </body>
        """)
    else:
        return HttpResponse("""
            <body style='font-family: sans-serif; text-align: center; padding-top: 50px;'>
                <h1 style='color: #2c3e50;'>Hệ thống Web Đồ án SDN - UNETI</h1>
                <p style='font-size: 1.2em;'>Vui lòng <a href='/accounts/login/'>đăng nhập</a> để tiếp tục.</p>
                <hr style='width: 50%;'>
                <p>Địa chỉ IP Server: 10.0.0.10</p>
                <p>Cơ sở dữ liệu: PostgreSQL (10.0.0.20)</p>
            </body>
        """)

urlpatterns = [
    path('admin/', admin.site.urls), 
    path('', home),
    path('accounts/', include('django.contrib.auth.urls')),
]