# Tên file: nfstream_inspector.py
from nfstream import NFStreamer
import time
import os
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

# 🎯 Optimized for s6-eth1 (L3 backbone capture point)
PREFERRED_INTERFACE = "s6-eth1"
FALLBACK_INTERFACES = ["s6-eth4", "h82-eth1", "any"]

def detect_interface():
    """Auto-detect best capture interface"""
    try:
        nets = set(os.listdir("/sys/class/net"))
    except:
        nets = set()
    
    if PREFERRED_INTERFACE in nets:
        return PREFERRED_INTERFACE
    
    for iface in FALLBACK_INTERFACES:
        if iface in nets:
            return iface
    
    return "any"

INTERFACE = detect_interface()  # Auto-detect instead of hardcoded
MAX_ROWS = 15     # Số lượng dòng hiển thị trên màn hình
PKT_THRESHOLD = 500 # Ngưỡng cảnh báo đỏ (Gói/giây)

console = Console()

def generate_table(flows_data):
    table = Table(title="📡 SDN Real-time Traffic Inspector", expand=True)
    table.add_column("Time", style="cyan", justify="center")
    table.add_column("Source IP:Port", style="white")
    table.add_column("Dest IP:Port", style="white")
    table.add_column("Proto", style="magenta", justify="center")
    table.add_column("App (L7)", style="green")
    table.add_column("Pkt/s", justify="right")
    table.add_column("Status", justify="center")

    for f in flows_data:
        # Cảnh báo màu đỏ nếu tốc độ quá cao
        pkt_style = "bold red" if f['pps'] > PKT_THRESHOLD else "white"
        status = "[bold red]🚨 HIGH[/bold red]" if f['pps'] > PKT_THRESHOLD else "[green]OK[/green]"
        
        table.add_row(
            f['time'], f['src'], f['dst'], f['proto'], f['app'],
            f"[{pkt_style}]{f['pps']:.1f}[/{pkt_style}]", status
        )
    return table

def start_inspector():
    console.print(Panel(Text("SDN X-RAY MONITOR\nDeep Packet Inspection Engine", justify="center", style="bold blue")))
    
    recent_flows = []
    try:
        streamer = NFStreamer(source=INTERFACE, idle_timeout=1, statistical_analysis=True)
        
        with Live(generate_table([]), refresh_per_second=2) as live:
            for flow in streamer:
                # Lọc traffic nội bộ rác
                if flow.src_ip.startswith('127.') or ':' in flow.src_ip: continue

                dur = flow.bidirectional_duration_ms / 1000.0 if flow.bidirectional_duration_ms > 0 else 0.1
                new_flow = {
                    'time': time.strftime("%H:%M:%S"),
                    'src': f"{flow.src_ip}:{flow.src_port}",
                    'dst': f"{flow.dst_ip}:{flow.dst_port}",
                    'proto': 'TCP' if flow.protocol == 6 else 'UDP' if flow.protocol == 17 else 'OTH',
                    'app': str(flow.application_name).upper(),
                    'pps': flow.bidirectional_packets / dur
                }

                recent_flows.insert(0, new_flow) # Đưa luồng mới lên đầu
                recent_flows = recent_flows[:MAX_ROWS] # Giữ tối đa 15 dòng
                live.update(generate_table(recent_flows))

    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] Stopped.[/bold yellow]")

if __name__ == "__main__":
    start_inspector()




'''nfstream_inspector.py bắt lấy luồng mạng và "dịch" nó ra ngôn ngữ con người một cách đẹp mắt. Nó phân tích 3 tầng quan trọng nhất:

Tầng Giao vận (L3/L4): Cho bạn biết chính xác IP và Cổng (Port) nào đang nói chuyện với nhau, bằng giao thức TCP hay UDP.

Chỉ số AI (Khối lượng & Tốc độ): Nó tự động tính toán ra pkt_rate (số gói/giây) và byte_rate (số byte/giây). Đây là 2 chỉ số "sống còn" để nhận diện DDoS. Nhìn vào đây, bạn sẽ thấy ngay một cuộc tấn công UDP Flood vọt lên hàng chục ngàn gói/giây như thế nào.

Phép màu của Tầng 7 (L7 nDPI): Đây là sức mạnh cốt lõi của thư viện nfstream. Khác với các công cụ bắt gói tin thông thường chỉ nhìn được mã hóa hay không, nó dùng công nghệ DPI (Deep Packet Inspection) để biết được bên trong luồng đó là ứng dụng gì (Ví dụ: HTTP, TLS/HTTPS, DNS).

2. Ứng dụng thực tế: Bạn nên dùng nó khi nào?
Trong quá trình bảo vệ đồ án hoặc test lỗi, bạn hãy bật file này lên (sudo python3 nfstream_inspector.py) trong các kịch bản sau:

A. Kiểm chứng kịch bản tấn công (Attack Verification)
Làm sao bạn biết file slowloris.py của bạn thực sự hoạt động "chậm và ngâm" như thiết kế?
-> Bật Inspector lên. Bắn Slowloris. Bạn sẽ nhìn thấy trên màn hình: Giao thức là HTTP, thời gian Duration_Sec kéo rất dài (ví dụ 10s, 20s), nhưng số lượng Bytes lại cực kỳ nhỏ xíu. Lúc này bạn có thể tự tin khẳng định với hội đồng: "Đây chính là đặc trưng của Slowloris".

B. Gỡ lỗi "Bắt trượt" mục tiêu (Interface Debugging)
Bạn còn nhớ sự cố Nhãn 4 Slowloris bị đứng im không thu được data chứ? Đó là do nhầm cổng nghe lén (s6-eth4 vs s6-eth5).
-> Nếu lúc đó bạn mở Inspector và trỏ vào cổng s6-eth5, bạn sẽ thấy màn hình trống trơn không có luồng HTTP nào bay qua. Bạn sẽ nhận ra ngay lập tức là mình đang đứng nhầm chỗ, tiết kiệm được cả tiếng đồng hồ ngồi đợi file CSV.

C. Biểu diễn (Demo) trước hội đồng
Thay vì chỉ mở file run_onos.py lên và chờ AI in ra chữ "Đã chặn", bạn có thể chia màn hình Ubuntu làm 2:

Bên trái: Mở Inspector để hội đồng nhìn thấy các gói tin đang bay qua bay lại bình thường (Nhãn 0).

Bên phải: Bấm lệnh tấn công Flood.

Kết quả: Màn hình Inspector bên trái sẽ lập tức bị "ngập lụt" bởi hàng loạt dòng chữ in ra với Packet_Rate đỏ lòm, sau đó khựng lại (do bị ONOS chặn). Đây là một hiệu ứng thị giác cực kỳ thuyết phục để chứng minh hệ thống của bạn thực sự chạy Real-time.

3. Sự khác biệt "tế nhị" so với batPack.py
Nếu bạn để ý kỹ code của nfstream_inspector.py:

Python
idle_timeout=2,       # Luồng nào im lặng 2s là chốt sổ in ra
# Không dùng active_timeout
Ở đây, chúng ta bỏ hẳn active_timeout và để idle_timeout=2. Mục đích là để luồng mạng chạy trọn vẹn từ đầu đến cuối rồi mới in ra màn hình 1 lần duy nhất cho bạn dễ đọc toàn cảnh. Trong khi đó, batPack.py phải ép active_timeout=1 (cắt vụn luồng mạng mỗi giây) để AI có dữ liệu mà phản ứng ngay lập tức.

Tóm lại, batPack.py là bộ giáp cho máy móc (nhanh, thô, liên tục), còn nfstream_inspector.py là ống nhòm cho kỹ sư (đẹp, toàn cảnh, dễ hiểu). Hãy giữ nó như một "bảo bối" rà soát lỗi mạng cực xịn cho đồ án nhé!'''