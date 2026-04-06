from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse, JsonResponse
import os
import psutil
from django.contrib.auth.hashers import make_password
import json
from django.views.decorators.csrf import csrf_exempt
global_memory_hog = []
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

def system_status(request):
    import os
    import psutil
    import traceback
    from django.http import JsonResponse

    debug_info = []
    ram_percent = 0.0
    mem_usage_str = "N/A"

    # 1. ĐỌC RAM TỪ CGROUP (Cách chuẩn xác nhất khi ở trong Docker)
    try:
        # Thử Cgroup v2 (Phổ biến trên các bản Ubuntu mới)
        if os.path.exists('/sys/fs/cgroup/memory.current'):
            debug_info.append("Using Cgroup v2")
            with open('/sys/fs/cgroup/memory.current', 'r') as f:
                used = int(f.read().strip())
            with open('/sys/fs/cgroup/memory.max', 'r') as f:
                max_val = f.read().strip()
                # Nếu không giới hạn RAM, lấy tổng RAM máy
                limit = int(max_val) if max_val != 'max' else psutil.virtual_memory().total
            
            ram_percent = (used / limit) * 100
            mem_usage_str = f"{used // (1024*1024)}MB / {limit // (1024*1024)}MB"

        # Thử Cgroup v1 (Hệ thống cũ hơn)
        elif os.path.exists('/sys/fs/cgroup/memory/memory.usage_in_bytes'):
            debug_info.append("Using Cgroup v1")
            with open('/sys/fs/cgroup/memory/memory.usage_in_bytes', 'r') as f:
                used = int(f.read().strip())
            with open('/sys/fs/cgroup/memory/memory.limit_in_bytes', 'r') as f:
                limit = int(f.read().strip())
            
            ram_percent = (used / limit) * 100
            mem_usage_str = f"{used // (1024*1024)}MB / {limit // (1024*1024)}MB"
            
        else:
            # Rất hiếm khi xảy ra nếu chạy bằng Containernet
            debug_info.append("No cgroup found - Using Host Fallback")
            ram_percent = psutil.virtual_memory().percent
            mem_usage_str = "Fallback to Host"
            
    except Exception as e:
        debug_info.append(f"Cgroup Error: {str(e)}")
        ram_percent = psutil.virtual_memory().percent

    # 2. XỬ LÝ CPU VÀ CONNECTIONS
    cpu_percent = psutil.cpu_percent(interval=0.1)
    
    try:
        # Lọc ra các kết nối thực sự đang diễn ra (ESTABLISHED) vào container
        conns = len([c for c in psutil.net_connections(kind="tcp") if c.status == "ESTABLISHED"])
    except Exception as e:
        debug_info.append(f"Net Error: {str(e)}")
        conns = 0

    # 3. GHI LOG ĐỂ KIỂM TRA
    print(f"\n--- [SYSTEM STATUS DEBUG] ---")
    print(f"Log: {debug_info}")
    print(f"RAM: {ram_percent:.2f}% ({mem_usage_str}) | CPU: {cpu_percent}% | Conns: {conns}")
    print(f"-----------------------------\n")

    return JsonResponse({
        "cpu_percent": round(cpu_percent, 2),
        "ram_percent": round(ram_percent, 2),
        "hostname": os.uname().nodename,
        "mem_usage": mem_usage_str,
        "connections": conns,
        "debug": debug_info # Trả về thẳng UI để dễ inspect trên trình duyệt
    })
# --- CÁC HÀM MỒI NHỬ TẤN CÔNG L7 ---
@csrf_exempt 
def api_hash_login(request):
    if request.method == 'POST':
        raw_password = request.POST.get('password', '')
        hashed_password = make_password(raw_password)
        return JsonResponse({'status': 'hashed', 'length': len(raw_password)})
    return JsonResponse({'error': 'Chỉ chấp nhận phương thức POST'}, status=405)

# Mảng chứa bộ nhớ bị rò rỉ
memory_leaks = []

@csrf_exempt
def api_process_json(request):
    global memory_leaks
    
    if request.method == 'POST':
        try:
            chunk_size = 15 * 1024 * 1024 # 15 MB
            
            # CHỈ CẤP PHÁT THÊM NẾU CHƯA CHẠM NGƯỠNG NGUY HIỂM (dưới 15 cục)
            if len(memory_leaks) < 15:
                memory_leaks.append('X' * chunk_size)
            
            # (XÓA BỎ lệnh if len > 15: memory_leaks.clear() cũ)

            return JsonResponse({
                'status': 'RAM is at maximum capacity' if len(memory_leaks) >= 15 else 'RAM is expanding', 
                'current_chunks': len(memory_leaks),
                'ram_leaked_mb': len(memory_leaks) * 15
            })
        except Exception as e:
            return JsonResponse({'error': f'Lỗi: {str(e)}'}, status=400)
            
    return JsonResponse({'error': 'Chỉ chấp nhận phương thức POST'}, status=405)
urlpatterns = [
    path('admin/', admin.site.urls), 
    path('', home),
    path('api/system_status', system_status),
    path('accounts/', include('django.contrib.auth.urls')),
    path('api/hash_login', api_hash_login),
    path('api/process_json', api_process_json),
]
