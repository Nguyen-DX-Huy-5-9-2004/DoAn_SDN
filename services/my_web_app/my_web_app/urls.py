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

# --- 9 MỚI ENDPOINTS: WEBSITE HOÀN THIỆN ---

def index_html(request):
    """Trang index (static/index.html) - bảng điều khiển chính"""
    return HttpResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>SDN Dashboard</title></head>
        <body style='font-family: sans-serif; margin: 20px;'>
            <h1>🎯 SDN Network Dashboard</h1>
            <div style='border: 1px solid #ddd; padding: 20px; border-radius: 5px;'>
                <h2>Network Status</h2>
                <table border='1' cellpadding='10'>
                    <tr><td>Status</td><td style='color: #27ae60;'>✓ Online</td></tr>
                    <tr><td>Switches</td><td>6/6</td></tr>
                    <tr><td>Hosts</td><td>33/33</td></tr>
                    <tr><td>Flows</td><td>142</td></tr>
                </table>
                <p><a href='/dashboard/'>Go to Dashboard</a></p>
            </div>
        </body>
        </html>
    """)

def favicon(request):
    """Favicon endpoint - trả về icon nhỏ (1x1 GIF transparent)"""
    return HttpResponse(
        b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b',
        content_type='image/gif'
    )

def dashboard(request):
    """Dashboard - chỉ cho user đã login"""
    if not request.user.is_authenticated:
        return HttpResponse("<h1>Access Denied</h1><p>Please <a href='/accounts/login/'>login</a></p>", status=403)
    
    return HttpResponse(f"""
        <!DOCTYPE html>
        <html>
        <head><title>Dashboard</title></head>
        <body style='font-family: sans-serif; margin: 20px;'>
            <h1>📊 Dashboard</h1>
            <h2>Welcome, {request.user.username}!</h2>
            <div style='border: 1px solid #ddd; padding: 15px; margin: 10px 0;'>
                <h3>System Metrics</h3>
                <ul>
                    <li>CPU Usage: <strong>23.4%</strong></li>
                    <li>Memory Usage: <strong>45.2%</strong></li>
                    <li>Network Traffic: <strong>124 Mbps</strong></li>
                    <li>Active Connections: <strong>187</strong></li>
                </ul>
            </div>
            <p><a href='/profile/'>Profile</a> | <a href='/settings/'>Settings</a> | <a href='/accounts/logout/'>Logout</a></p>
        </body>
        </html>
    """)

def profile(request):
    """User profile page - chỉ cho user đã login"""
    if not request.user.is_authenticated:
        return HttpResponse("<h1>Access Denied</h1><p>Please <a href='/accounts/login/'>login</a></p>", status=403)
    
    return HttpResponse(f"""
        <!DOCTYPE html>
        <html>
        <head><title>Profile</title></head>
        <body style='font-family: sans-serif; margin: 20px;'>
            <h1>👤 User Profile</h1>
            <div style='border: 1px solid #ddd; padding: 15px;'>
                <p><strong>Username:</strong> {request.user.username}</p>
                <p><strong>Email:</strong> {request.user.email or 'N/A'}</p>
                <p><strong>First Name:</strong> {request.user.first_name or 'N/A'}</p>
                <p><strong>Last Name:</strong> {request.user.last_name or 'N/A'}</p>
                <p><strong>Last Login:</strong> {request.user.last_login or 'Never'}</p>
                <p><strong>Member Since:</strong> {request.user.date_joined}</p>
            </div>
            <p><a href='/dashboard/'>Back to Dashboard</a></p>
        </body>
        </html>
    """)

def settings(request):
    """Settings page - chỉ cho user đã login"""
    if not request.user.is_authenticated:
        return HttpResponse("<h1>Access Denied</h1><p>Please <a href='/accounts/login/'>login</a></p>", status=403)
    
    return HttpResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>Settings</title></head>
        <body style='font-family: sans-serif; margin: 20px;'>
            <h1>⚙️ Settings</h1>
            <form style='border: 1px solid #ddd; padding: 15px; max-width: 500px;'>
                <h3>Notification Preferences</h3>
                <label><input type='checkbox' checked> Email Notifications</label><br>
                <label><input type='checkbox' checked> Alert on Attack Detection</label><br>
                <label><input type='checkbox'> Weekly Reports</label><br>
                <h3>Network Settings</h3>
                <label>Threshold: <input type='number' value='85' style='width: 80px;'>%</label><br>
                <label>Monitor Interval: <input type='number' value='5' style='width: 80px;'> seconds</label><br>
                <button type='submit'>Save Settings</button>
            </form>
            <p><a href='/dashboard/'>Back to Dashboard</a></p>
        </body>
        </html>
    """)

def search(request):
    """Search results page"""
    query = request.GET.get('q', 'network security')
    return HttpResponse(f"""
        <!DOCTYPE html>
        <html>
        <head><title>Search: {query}</title></head>
        <body style='font-family: sans-serif; margin: 20px;'>
            <h1>🔍 Search Results</h1>
            <p>Query: <strong>{query}</strong></p>
            <div style='border: 1px solid #ddd; padding: 15px;'>
                <h3>Documentation</h3>
                <ul>
                    <li><a href='#'>SDN Architecture Guide</a> - Network fundamentals</li>
                    <li><a href='#'>DDoS Detection Methods</a> - Attack recognition patterns</li>
                    <li><a href='#'>Network Monitoring</a> - Real-time traffic analysis</li>
                    <li><a href='#'>Security Best Practices</a> - Firewall configuration</li>
                </ul>
            </div>
            <p><a href='/'>Home</a></p>
        </body>
        </html>
    """)

@csrf_exempt
def api_metrics(request):
    """API v1 - Metrics endpoint (JSON)"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        ram_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').percent
        
        return JsonResponse({
            "timestamp": str(os.popen('date -Iseconds').read().strip()),
            "system": {
                "cpu_percent": round(cpu_percent, 2),
                "memory_percent": round(ram_percent, 2),
                "disk_percent": round(disk_percent, 2),
                "uptime_seconds": int(os.popen('uptime -p | grep -oE "[0-9]+" | head -1').read().strip() or 0)
            },
            "network": {
                "packets_sent": psutil.net_io_counters().packets_sent,
                "packets_recv": psutil.net_io_counters().packets_recv,
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv
            },
            "connections": len([c for c in psutil.net_connections(kind="tcp") if c.status == "ESTABLISHED"])
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

def contact(request):
    """Contact/Support page"""
    if request.method == 'POST':
        return HttpResponse("""
            <h1>✓ Message Sent!</h1>
            <p>Thank you for contacting us. We'll get back to you soon.</p>
            <p><a href='/'>Home</a></p>
        """)
    
    return HttpResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>Contact Us</title></head>
        <body style='font-family: sans-serif; margin: 20px;'>
            <h1>📧 Contact Us</h1>
            <form method='POST' style='border: 1px solid #ddd; padding: 15px; max-width: 500px;'>
                <label>Name: <input type='text' name='name' required></label><br><br>
                <label>Email: <input type='email' name='email' required></label><br><br>
                <label>Subject: <input type='text' name='subject' required></label><br><br>
                <label>Message:<br><textarea name='message' rows='5' cols='40' required></textarea></label><br><br>
                <button type='submit'>Send Message</button>
            </form>
            <p><a href='/'>Home</a></p>
        </body>
        </html>
    """)

def about(request):
    """About page"""
    return HttpResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>About</title></head>
        <body style='font-family: sans-serif; margin: 20px;'>
            <h1>ℹ️ About Us</h1>
            <div style='border: 1px solid #ddd; padding: 15px;'>
                <h2>SDN-Based DDoS Detection System</h2>
                <p><strong>Project:</strong> Graduation Thesis - UNETI</p>
                <p><strong>Version:</strong> 2.0 (Production)</p>
                <p><strong>Description:</strong></p>
                <p>An advanced AI-powered DDoS detection system using Software-Defined Networking (SDN) 
                with Contrastive Autoencoders for anomaly detection and Parallel Fusion CNN-GRU for 
                attack classification.</p>
                <h3>Key Features</h3>
                <ul>
                    <li>Real-time DDoS attack detection</li>
                    <li>Multiple attack type classification (UDP Flood, SYN Flood, HTTP Flood, Slowloris)</li>
                    <li>Adaptive threshold learning</li>
                    <li>Zero-day attack detection</li>
                    <li>Sub-100ms latency processing</li>
                    <li>96-98% detection accuracy</li>
                </ul>
                <h3>Technology Stack</h3>
                <ul>
                    <li>PyTorch - Deep Learning Framework</li>
                    <li>ONOS - SDN Controller</li>
                    <li>Containernet/Mininet - Network Emulation</li>
                    <li>NFStream - Network Flow Analysis</li>
                    <li>Django - Web Framework</li>
                </ul>
            </div>
            <p><a href='/'>Home</a></p>
        </body>
        </html>
    """)

urlpatterns = [
    path('admin/', admin.site.urls),
    # Core pages
    path('', home),
    path('static/index.html', index_html),
    path('favicon.ico', favicon),
    # Dashboard & User pages (require auth)
    path('dashboard/', dashboard),
    path('profile/', profile),
    path('settings/', settings),
    # Search
    path('search/', search),
    # Contact & About
    path('contact/', contact),
    path('about/', about),
    # API endpoints
    path('api/system_status', system_status),
    path('api/v1/metrics', api_metrics),
    path('api/hash_login', api_hash_login),
    path('api/process_json', api_process_json),
    # Django auth
    path('accounts/', include('django.contrib.auth.urls')),
]
