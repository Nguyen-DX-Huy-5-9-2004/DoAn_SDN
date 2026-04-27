CHƯƠNG 2: PHÂN TÍCH, THIẾT KẾ VÀ XÂY DỰNG MÔ HÌNH HỆ THỐNG
2.1. Phân tích đánh giá các hướng nghiên cứu liên quan đến đề tài
2.1.1. Các nghiên cứu trên thế giới
-	Giai đoạn đầu (Thống kê & Entropy): Các nghiên cứu ban đầu tập trung vào phương pháp thống kê (như tính toán Entropy của IP đích). Ưu điểm là nhẹ, nhưng nhược điểm là khó phát hiện các tấn công DDoS cường độ thấp hoặc chậm (Low-rate DDoS).
-	Giai đoạn Machine Learning (ML): Các tác giả đã áp dụng SVM, K-Nearest Neighbors, Random Forest. Kết quả tốt hơn thống kê, nhưng vẫn phụ thuộc nhiều vào việc con người phải tự tay trích xuất đặc trưng (Feature Engineering), tốn thời gian và dễ bỏ sót thông tin.
-	Giai đoạn hiện tại (Deep Learning): Các nghiên cứu gần đây (từ 2019-nay) chuyển hướng sang CNN, LSTM, GRU. Ví dụ: Nghiên cứu của Tác giả A (năm 2022) sử dụng CNN-LSTM đạt độ chính xác 98% nhưng thời gian huấn luyện còn lâu.
2.1.2. Các nghiên cứu trong nước
-	Tại Việt Nam, các nghiên cứu chủ yếu tập trung vào việc so sánh hiệu năng giữa các bộ điều khiển (ONOS, ODL) khi chịu tải tấn công.
-	Một số đồ án/luận văn gần đây đã bắt đầu tích hợp AI, nhưng đa phần dừng lại ở mô phỏng phát hiện (Detection) mà chưa chú trọng nhiều vào cơ chế giảm thiểu (Mitigation) tự động hoặc tối ưu hóa thời gian thực.
2.1.3. Khoảng trống nghiên cứu (Research Gap)
-	Hầu hết các nghiên cứu tập trung vào độ chính xác (Accuracy) mà bỏ qua yếu tố thời gian trễ (Latency). Trong SDN, nếu phát hiện chậm, Controller sẽ bị sập trước khi kịp chặn tấn công. Đây là điểm mà đề tài này sẽ tập trung cải thiện.

2.1.4. Phân tích đặc thù 4 loại tấn công DDoS mục tiêu

Trước khi thiết kế hệ thống, nhóm đã phân tích sâu về taxonomy của DDoS attacks để chọn 4 loại đại diện cho toàn bộ spectrum:

```
┌─────────────────┬─────────────────┬─────────────────┐
│  Volumetric     │  Protocol       │  Application    │
│  (Layer 3)      │  (Layer 4)      │  (Layer 7)      │
├─────────────────┼─────────────────┼─────────────────┤
│  UDP Flood      │  SYN Flood      │  HTTP Flood     │
│  ICMP Flood     │  Ping of Death  │  Slowloris      │
│  DNS Amplify    │  Smurf          │  RUDY           │
└─────────────────┴─────────────────┴─────────────────┘

4 Loại được chọn ĐẠI DIỆN:
• UDP Flood    → Volumetric (ăn băng thông)
• SYN Flood    → Protocol (ăn connection table)
• HTTP Flood   → Application (ăn CPU/DB resources)
• Slowloris    → Slow Application (khó phát hiện nhất)
```

**1. UDP Flood - Volumetric Attack (Layer 3)**
- **Cơ chế:** UDP là connectionless, attacker gửi packets kích thước lớn (65,507 bytes) không cần chờ response. Target là băng thông mạng và CPU xử lý packets.
- **Biểu hiện:** Network Interface RX errors tăng vọt, CPU system load cao, kernel buffer đầy, bandwidth 100% utilization.
- **Tại sao khó phát hiện:** UDP traffic là hợp lệ, có thể spoof source IP, không có connection state để track.
- **Chữ ký V4:** Packet_Rate > 30,000 pps, Byte_Rate > 100MB/s, Port_Entropy ≈ 0 (fixed port), nDPI: "Unknown" protocol.

**2. SYN Flood - Protocol Attack (Layer 4)**
- **Cơ chế:** Khai thác TCP 3-way handshake. Attacker gửi SYN → Server allocates resources → Không gửi ACK → Connection half-open → Server chờ timeout (75 giây) → Connection table đầy.
- **Biểu hiện:** netstat -an: SYN_RECV connections hàng ngàn, kernel "TCP: out of memory", ứng dụng không accept được connection mới.
- **Tại sao KHÓ PHÁT HIỆN hơn UDP:** SYN packets là hợp lệ TCP, có thể spoof IP, traffic volume thấp hơn UDP nhưng hiệu quả hơn, trông giống "busy server" hơn "attack".
- **Chữ ký V4:** Conn_State = 0 (half-open), SYN packets >> ACK packets (ratio > 10:1), Short Duration (< 1s per attempt), Src_IP entropy cao (spoofed).

**3. HTTP Flood - Application Attack (Layer 7)**
- **Cơ chế:** Attacker gửi HTTP requests HỢP LỆ, GET/POST đến URLs tốn nhiều resources (ví dụ: /search?q=test). Mỗi request kích hoạt: Nginx → WSGI → Database → Response.
- **Biểu hiện:** Nginx worker processes 100% CPU, Database connection pool exhausted, Application response time > 30 giây, "504 Gateway Timeout".
- **Tại sao CỰC KỲ KHÓ PHÁT HIỆN:** Requests là hợp lệ (valid HTTP/1.1), headers đầy đủ, không có signature đặc biệt, có thể rotate qua nhiều IPs (botnet), Cloudflare/WAF thường không block.
- **Chữ ký V4:** Request rate >> Normal user (100x), No think time (0s between requests), URL entropy cao (random paths), nDPI: "HTTP" protocol detected, Temporal pattern không có "bursts" như normal.

**4. Slowloris - Slow Application Attack (Layer 7)**
- **Cơ chế:** Attacker mở HTTP connection, gửi request từng phần dần dần, giữ connection sống bằng headers rác định kỳ, không bao giờ kết thúc request (không gửi \r\n\r\n) → Server giữ connection mở chờ request hoàn chỉnh.
- **Biểu hiện:** Nginx "upstream timed out" errors, netstat: ESTABLISHED connections hàng trăm từ 1 IP, Server đạt max connections nhưng traffic thấp, "Cannot connect to server".
- **Tại sao ĐỘC NHẤT và KHÓ PHÁT HIỆN NHẤT:** Không cần nhiều bandwidth (1KB/s đủ), không cần nhiều packets (10-20 phút), trông giống "user chậm" hơn "attacker", Firewalls/WAF thường không phát hiện (traffic thấp), cần timeout đặc biệt để detect (30s+), **KHÔNG CÓ TRONG CÁC DATASET CÔNG KỘNG!**
- **Chữ ký V4:** Duration >> Normal (300-600s vs 5-30s), Byte_Rate << Normal (1-5KB/s vs 100KB/s), Packet_Rate thấp (10-20 packets/min), Connections max out nhưng bandwidth thấp.

**So Sánh Tổng Hợp:**
| Đặc điểm | UDP Flood | SYN Flood | HTTP Flood | Slowloris |
|----------|-----------|-----------|------------|-----------|
| **Layer** | 3 (Network) | 4 (Transport) | 7 (Application) | 7 (Application) |
| **Target** | Bandwidth | Connection Table | CPU/DB | Connection Pool |
| **Speed** | Very Fast | Fast | Medium | Very Slow |
| **Volume** | High (GB/s) | Medium (MB/s) | Low (MB/s) | Very Low (KB/s) |
| **Detection** | Easy | Medium | Hard | Very Hard |
| **Dataset** | Có sẵn | Có sẵn | Có sẵn | **KHÔNG CÓ** |

→ **Lý do chọn 4 loại:** Đại diện cho toàn bộ spectrum DDoS, từ dễ đến khó, đặc biệt Slowloris là độc nhất và không có trong bất kỳ dataset public nào.

2.2. Thực trạng có liên quan đến KLTN
2.2.1. Hoạt động quản lý và vận hành mạng SDN
-	Trong mô hình hiện tại, Quản trị viên sử dụng Controller để định tuyến tập trung.
-	Cơ chế hoạt động: Khi có gói tin mới (New Flow), Switch gửi thông điệp Packet-In lên Controller để hỏi đường đi. Controller tính toán và gửi lệnh Flow-Mod xuống. Đây là quy trình tiêu chuẩn nhưng tốn tài nguyên xử lý.
2.2.2. Hoạt động giám sát và bảo mật hiện hành
-	Các hệ thống hiện tại thường sử dụng Ngưỡng cố định (Static Threshold). Ví dụ: "Nếu 1 IP gửi quá 1000 gói tin/giây thì chặn".
-	Hệ thống IPS/IDS truyền thống hoạt động độc lập, không giao tiếp sâu với Controller của SDN, dẫn đến phản ứng chậm chạp khi cấu trúc mạng thay đổi.
2.3. Đánh giá thực trạng
2.3.1.  Những kết quả đạt được (Ưu điểm của mô hình hiện tại)
-	Kiến trúc SDN giúp quản lý mạng linh hoạt, dễ dàng thay đổi cấu hình mà không cần chạm vào từng thiết bị phần cứng.
-	Các phương pháp phát hiện dựa trên ngưỡng đơn giản, dễ triển khai, tốn ít tài nguyên tính toán.
2.3.2. Những hạn chế và Nguyên nhân
-	Hạn chế 1: Tỷ lệ báo động giả (False Positive) cao.
o	Nguyên nhân: Do sử dụng ngưỡng cố định. Trong các đợt Flash Crowd (ví dụ: lượng truy cập tăng đột biến ngày Black Friday), lưu lượng hợp lệ tăng cao giống hệt tấn công, hệ thống cũ sẽ chặn nhầm người dùng thật.
-	Hạn chế 2: Điểm yếu chí mạng tại Controller (Saturation Attack).
o	Nguyên nhân: Khi tấn công DDoS xảy ra, hàng triệu gói tin lạ khiến Switch gửi hàng triệu tin Packet-In lên Controller. Controller bị quá tải (CPU 100%) và treo, khiến toàn bộ mạng tê liệt.
-	Hạn chế 3: Không phát hiện được tấn công chưa biết (Zero-day).
o	Nguyên nhân: Các hệ thống dựa trên chữ ký (Signature-based) chỉ chặn được những gì đã biết trong cơ sở dữ liệu.
2.4. Đề xuất giải pháp để giải quyết vấn đề
Dựa trên các phân tích trên, KLTN đề xuất giải pháp: "Hệ thống phòng thủ cộng tác giữa SDN và Deep Learning".
2.4.1. Kiến trúc giải pháp tổng thể
Mô hình đề xuất gồm 3 module chính hoạt động theo vòng khép kín:
1.	Module Thu thập (Traffic Collector):
o	Sử dụng API của Onos Controller để định kỳ trích xuất thống kê (Flow Statistics) từ các Switch kết hợp với kỹ thuật Nfstream tiên tiến để bóc tách lưu lượng tầng 7 (thay vì bắt toàn bộ gói tin gây nặng máy).
2.	Module Phân tích (Deep Learning Engine):
o	Sử dụng mạng nơ-ron (CNN-GRU) đã huấn luyện để phân tích dữ liệu thống kê vừa thu thập.
o	Phân loại lưu lượng: 0 (Bình thường) - 1 (Tấn công), nâng cao hơn là sẽ phân loại cụ thể các tấn công.
3.	Module Ngăn chặn (Mitigation):
o	Nếu phát hiện tấn công (Nhãn 1), lập tức tạo luật (dựa vào độ tin cậy của dự đoán mà có quyết định linh động với kẻ tấn công) và đẩy xuống Switch thông qua OpenFlow. 
o	Cơ chế chặn theo IP nguồn hoặc cổng tấn công để không ảnh hưởng người dùng khác.
2.4.2. Giải pháp cải thiện các hạn chế
-	Giải quyết vấn đề Báo động giả: Deep Learning học được các mẫu hành vi phức tạp (phi tuyến tính), phân biệt được đâu là tấn công thật, đâu là lượng truy cập tăng cao hợp lệ → Tăng độ chính xác.
-	Giải quyết vấn đề Quá tải Controller: Hệ thống phát hiện sớm và đẩy luật chặn ngay tại Switch (Data Plane). Các gói tin tấn công sau đó sẽ bị Switch loại bỏ ngay tại cửa ngõ, không còn cơ hội gửi lên làm phiền Controller nữa.
2.4.3. Thiết kế mô hình hệ thống (System Design)
2.4.3.1. Kiến trúc tổng thể (High-level Architecture)
Em xin mô tả lại kiến trúc SDN tổng thể ứng với đề tài trước khi đưa vào triển khai, kiến trúc được bao gồm 3 lớp được xác định cụ thể như sau:
a.	Lớp dữ liệu (Data Plane): Bao gồm các Switch, các host được xây dựng trong hệ thống mạng được quản lí chặt chẽ bởi Onos Controller, chúng có nhiệm vụ đẩy gói tin đi theo luồng được thiết lập sẵn.
b.	Lớp điều khiển (Control Plane): Trong đề tài này, chúng em lựa chọn Onos Controller bởi các ưu điểm vượt trội:
-	Khả năng chịu lỗi: do được thiết kế dưới dạng một Cluster (nhiều máy chủ cùng điều khiển một lúc) nên khi một Controller bị sập, các Controller khác trong cụm sẽ thay thế mà không làm gián đoạn hệ thống mạng.
-	Khả năng trực quan: Onos cho chúng ta thấy được trực tiếp sơ đồ mạng biểu diễn thông qua trang wep, các luồng đi của gói tin hay sự quá tải băng thông mạng bằng các đường báo đỏ.
-	Hệ thống API của Onos được chuẩn hóa giúp dễ dàng tích hợp các ứng dụng bên ngoài (như Python AI, Web Dashboard).
c.	Lớp ứng dụng (Application Plane): Bao gồm các ứng dụng đảm nhiệm các chức năng cụ thể trong dự án:
-	Hiển thị cho người dùng thấy được hệ thống mạng thông qua Dashboard V14.
-	Chứa mô hình AI đã được tích hợp để phân tích, thực hiện dự đoán tấn công DDos trong hệ thống mạng.
-	Cuối cùng là thực thi kịch bản phòng thủ. Khi xác định được đó là tấn công, lớp này sẽ ra lệnh cho Onos (Lớp điều khiển) viết các luật chặn không cho gói tin đi đến Server.
2.4.3.2. Thiết kế Topology mạng giả lập
Trong quá trình xây dựng hạ tầng thực nghiệm, nhóm đã chủ động loại bỏ hoàn toàn mô hình mạng L2 (MAC-based) truyền thống để chuyển dịch sang kiến trúc mạng L3 (IP-based Routing) chuyên nghiệp. Quyết định này xuất phát từ thực tế rằng mạng L2 thường bộc lộ những hạn chế nghiêm trọng khi mô phỏng số lượng lớn thiết bị, đặc biệt là hiện tượng bão mạng và rủi ro tràn bảng địa chỉ MAC, gây mất ổn định cho hệ thống.
Bằng cách áp dụng định tuyến lớp 3, hệ thống đã thực hiện phân tách rõ ràng các phân vùng mạng con (Subnets) dựa trên chức năng, bao gồm: dải 10.0.1.0/24 dành riêng cho phân vùng Botnet (Attacker), 10.0.2.0/24 cho người dùng hợp lệ (Client) và 10.0.0.0/24 cho khu vực trung tâm dữ liệu. Kiến trúc này cho phép bộ điều khiển SDN Controller quản lý và điều phối các luồng dữ liệu trực tiếp dựa trên địa chỉ IP, giúp tối ưu hóa khả năng giám sát và thực thi các chính sách bảo mật. 
a.	Lớp lõi (Core Layer): Core Switch, đây là trung tâm điều phối lưu lượng toàn mạng, kết nối trực tiếp đến Controller và các Switch phân phối.
b.	Lớp phân phối (Distribution Layer):
-	Botnet Distribution: Quản lý phân vùng lưu lượng từ các nút tấn công.
-	Client Distribution: Quản lý lưu lượng từ các người dùng hợp lệ.
-	Datacenter Fabric: Phân phối dữ liệu cho phân vùng máy chủ.
c.	Lớp truy cập (Access Layer):
-	Botnet Access: Điểm tập kết của các Botnet node.
-	Web Server Switch: Kết nối trực tiếp các máy chủ dịch vụ.
Hệ thống được phân chia thành 3 phân vùng logic để phục vụ các kịch bản tấn công và phòng thủ DDos:
Phân vùng	Đối tượng bao gồm	Kịch bản mô phỏng
Tấn công	Host h1 đến h20	Mô phỏng mạng Botnet quy mô lớn thực hiện tấn công Flood.
Người dùng	Host h60 đến h65	Mô phỏng người dùng hợp lệ truy cập dịch vụ.
Dịch vụ	web1, db1, h70-h82, proxy (mạng hiện đại thực tế)	Đối tượng nạn nhân chịu tải và cần được bảo vệ
Bảng 2.1. Bảng phân vùng hệ thống mạng
Để đảm bảo tính thực tế, các host được gán dải IP riêng biệt theo từng khu vực:
-	Mạng Botnet (Subnet 10.0.1.0/24): Gồm 20 node từ 10.0.1.1 - 10.0.1.20.
-	Mạng người dùng (Subnet 10.0.2.0/24): Gồm các node từ 10.0.2.60.
Hệ thống Máy chủ (Server Farm):
-	Web Server (web1): 10.0.0.11 
-	Database Server (db1): 10.0.0.20.
-	Proxy: 10.0.0.10
-	(h70-h82): Phục vụ các dịch vụ nội bộ khác.
 
Hình 2.2. Mô hình thiết kế mạng

2.4.3.3. Hành Trình Tiến Hóa Dataset và Mô Hình AI (V0 → V7)

Quá trình xây dựng hệ thống AI phát hiện DDoS không phải là một bước nhảy vọt duy nhất, mà là một hành trình tiến hóa qua 7 phiên bản dataset và 4 phiên bản AI (V1-V4), với nhiều thử nghiệm, thất bại và cải tiến liên tục.

**A. Giai đoạn Dataset V0 - V1: Thử nghiệm với dữ liệu Internet**

Ban đầu, nhóm đã tổng hợp các bộ dữ liệu DDoS được chia sẻ trên mạng (CICDDoS2019, NSL-KDD, UNSW-NB15) với tổng dung lượng hơn 64GB dữ liệu thô. Sau khi lọc, xử lý dựa vào bảng ánh xạ 20 đặc trưng có thể thu thập từ hệ thống (sử dụng Zeek để xác định), còn lại hơn 800MB với 20 trường dữ liệu.

[CHÈN ẢNH: bangAnhXa20DacTrungBanDau.png - Tiêu đề: Bảng ánh xạ 20 đặc trưng ban đầu (Dataset V1)]

Tuy nhiên, khi đưa vào thử nghiệm thực tế trên Mininet, độ chính xác sụt giảm thảm hại từ 84% xuống chỉ 37%, với tỷ lệ báo động giả (False Positive) tăng vọt lên 60%. Nguyên nhân cốt lõi là hiện tượng lệch phân phối (Distribution Shift): dữ liệu từ các nguồn khác nhau không đồng nhất format, thiếu flow-based sequences cần thiết cho CNN-GRU, và không phản ánh đặc thù của môi trường SDN với giao thức OpenFlow.

[CHÈN ẢNH: dataset_v0_report.png - Tiêu đề: Báo cáo phân tích Dataset V0 (46GB+ thu thập từ Internet)]

→ **Bài học quan trọng:** Dataset phải được thu thập trực tiếp từ môi trường mục tiêu (Mininet + ONOS), không thể dùng dataset có sẵn từ Internet.

**B. Giai đoạn Dataset V2 - V7: Tự thu thập và tinh chỉnh**

Nhóm quyết định loại bỏ hoàn toàn bộ dữ liệu 46GB từ Internet và tự phát triển module auto_dataset_generator.py để thu thập dữ liệu trực tiếp. Mỗi phiên bản dataset đại diện cho một bước cải tiến:

| Phiên bản | Đặc điểm | Kết quả |
|-----------|----------|---------|
| **V2** | 13 đặc trưng gốc, thu thập thủ công | Chưa ổn định, nhiều nhiễu |
| **V3** | Cải thiện nhãn dữ liệu, thêm đặc trưng DNS | Tốt hơn nhưng còn thiếu thông tin thời gian |
| **V4** | **Breakthrough:** Thêm 13 đặc trưng biến thiên (Differential Features) | Tổng 26 đặc trưng, phát hiện được Slowloris |
| **V5** | Tinh chỉnh cân bằng dữ liệu | Giảm overfitting |
| **V6** | Tối ưu Timeout cho từng loại tấn công | Thu thập chính xác hơn |
| **V7** (Final) | 75.000 mẫu cân bằng hoàn hảo (15.000 mỗi nhãn) | **F1-Score 0.96** |

[CHÈN ẢNH: tienTrinhHutDataChoAI.png - Tiêu đề: Tiến trình thu thập dữ liệu cho AI (NFStream flow capture)]

[CHÈN ẢNH: thuThapDatasetV6.png - Tiêu đề: Thu thập Dataset V6]

[CHÈN ẢNH: thuThapDatasetV7.png - Tiêu đề: Thu thập Dataset V7 (Phiên bản cuối cùng)]

**C. Tiến hóa kiến trúc AI: Từ V1 đến V4**

| Phiên bản | Kiến trúc | Đặc điểm | Vấn đề gặp phải |
|-----------|-----------|----------|-----------------|
| **V1** | Random Forest + 20 features | Nhẹ, nhanh | Chỉ phân tích điểm, không thấy chuỗi thời gian |
| **V2** | CNN đơn giản | Bắt được pattern không gian | Không thấy nhịp điệu tấn công theo thời gian |
| **V3** | CNN-LSTM tuần tự | Kết hợp không gian + thời gian | LSTM quá nặng, chậm; CNN làm nhiễu GRU |
| **V4** (Final) | **Parallel CNN-GRU + Attention + Autoencoder** | Song song, nhẹ, nhanh, 2-Shield | **Tối ưu cho SDN real-time** |

→ **Quyết định quan trọng:** Chuyển từ kiến trúc tuần tự (CNN rồi đến GRU) sang kiến trúc **Song song (Parallel Fusion)**, giúp CNN và GRU hoạt động độc lập không làm nhiễu thông tin nhau.

**D. Triết Lý Phát Triển: "3 Lớp Bảo Vệ" (Three-Layer Defense Philosophy)**

Sau hành trình đầy thử thách từ V0 đến V7 và từ V1 đến V4 AI, nhóm đúc kết ra triết lý cốt lõi: **"AI không thể tin tưởng mù quáng"**. Hệ thống phải được xây dựng theo kiến trúc "Dual-Shield" với 3 lớp bảo vệ liên hoàn:

```
┌─────────────────────────────────────────────────────────────────┐
│ Lớp 1: Dữ Liệu (Data Cleansing)                                  │
│ • Cắt bỏ port số → Dùng Shannon Entropy                         │
│ • Thêm Differential Features → Nhìn "gia tốc" không chỉ "vận tốc"│
│ • Lọc Subnet thông minh → Bảo vệ Normal user (10.0.2.x)         │
└─────────────────────────────────────────────────────────────────┘
                                    ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ Lớp 2: Khiên 1 - Autoencoder (Anomaly Detection)                │
│ • Contrastive Learning → Ép Normal/Attack xa nhau             │
│ • Margin = 2.0 (siết chặt ranh giới)                            │
│ • Threshold Adaptive (EMA) → Thích ứng với Flash Crowd          │
│ • → Phát hiện Zero-day (89.3% biến thể mới)                    │
└─────────────────────────────────────────────────────────────────┘
                                    ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ Lớp 3: Khiên 2 - Classifier (CNN-GRU)                          │
│ • CNN (Spatial) + GRU (Temporal) → Song song (Parallel)         │
│ • Attention (Temporal + Spatial) → Chỉ thị flow bất thường      │
│ • Feature Weighting x2.0 → Duration/Packet_Rate quan trọng      │
│ • → Phân biệt 5 loại attack rõ ràng                             │
└─────────────────────────────────────────────────────────────────┘
                                    ⬇️
┌─────────────────────────────────────────────────────────────────┐
│ Lớp 4: Vận Hành (Runtime)                                       │
│ • Veto Power (>80% Normal = TIN) → Không chặn người dùng vô căn cứ│
│ • Temporal Consistency (5 chuỗi) → Attack thật = 3/5 đồng ý     │
│ • Garbage Collector → Xóa 20% IP cũ khi RAM gần cạn             │
│ • Rate Limiting + DROP → 2 lệnh, 2 mức độ                       │
└─────────────────────────────────────────────────────────────────┘
```

**Giải thích chi tiết từng lớp:**

**Lớp 1 - Làm sạch từ gốc (Data Cleansing):**
Thay vì dùng dữ liệu thô, nhóm đã áp dụng nhiều kỹ thuật tiền xử lý để "làm sạch" dữ liệu trước khi đưa vào AI. Việc loại bỏ port number và thay bằng Entropy giúp tránh hiện tượng "học vẹt" theo cổng dịch vụ. Thêm Differential Features cho phép AI nhìn thấy sự thay đổi (gia tốc) của luồng mạng, không chỉ giá trị tuyệt đối.

**Lớp 2 - Khiên bất thường (Anomaly Detection):**
Autoencoder được huấn luyện chỉ trên dữ liệu Normal (học không giám sát). Mô hình học cách nén và giải nén các luồng dữ liệu hợp lệ. Khi gặp bất kỳ luồng nào có pattern khác (kể cả Zero-day chưa từng thấy), reconstruction error sẽ tăng vọt và vượt ngưỡng. Đây là lớp phòng thủ đầu tiên, có khả năng bắt mọi dạng tấn công bất thường.

**Lớp 3 - Khiên phân loại (Classifier):**
Khi Khiên 1 phát hiện bất thường, Khiên 2 (CNN-GRU-Attention) sẽ định danh chính xác loại tấn công. Kiến trúc Parallel giúp CNN học pattern không gian và GRU học pattern thời gian độc lập, không làm nhiễu nhau. Attention mechanism giúp AI tập trung vào các bước thời gian quan trọng nhất.

**Lớp 4 - Kiểm soát thực tế (Runtime):**
Để tránh chặn nhầm người dùng thật, hệ thống tích hợp Veto Power. Nếu Classifier khẳng định >80% là Normal (dù Autoencoder nghi ngờ), hệ thống sẽ "tin" Classifier và cho phép đi qua. Garbage Collector giúp quản lý RAM khi bị tấn công IP spoofing quy mô lớn.

→ **Kết quả:** Triết lý này giúp giảm False Positive từ 60% (V1) xuống chỉ còn 3% (V4), đồng thời đạt 89.3% phát hiện Zero-day.

**E. Bài Học Qua Các Phiên Bản (Lessons Learned)**

Hành trình từ V1 đến V4 không chỉ là quá trình cải tiến kỹ thuật mà còn là quá trình học hỏi từ thất bại. Dưới đây là những bài học quý giá nhất:

| Giai Đoạn | Sai Lầm | Bài Học | Cải Tiến Chính |
|-----------|---------|---------|----------------|
| **V1** | Dùng dataset CIC-IDS2019 công cộng | ❌ Dataset phải từ target domain | Chuyển sang thu thập dữ liệu tự động từ Mininet |
| **V1** | Random Forest với 20 features | ❌ Chỉ phân tích điểm, không thấy chuỗi thời gian | Chuyển sang CNN + GRU để bắt pattern không gian và thời gian |
| **V2** | Dataset 46GB từ nhiều nguồn | ❌ Dataset quality > quantity | Xây dựng pipeline thu thập riêng, tự kiểm định |
| **V2** | Giữ port number làm feature | ❌ Port thay đổi ngẫu nhiên → dùng Entropy | Thay src_port bằng Src_Port_Entropy |
| **V3** | Autoencoder đơn giản (MSE loss) | ❌ Cần Spatial + Temporal (CNN-GRU) | Thêm Parallel CNN-GRU + Attention |
| **V3** | Threshold tĩnh (0.5) | ❌ Không thích ứng với flash crowd | Chuyển sang EMA adaptive threshold |
| **V4** | CNN rồi đến GRU (tuần tự) | ❌ CNN làm nhiễu thông tin GRU | Chuyển sang Parallel Fusion (CNN || GRU) |
| **V4** | Thiếu cơ chế chặn nhầm | ❌ Cần "quyền phủ quyết" | Thêm Veto Power (>80% Normal = tin) |

**Những Insight Quan Trọng:**

1. **Dataset Quality > Quantity:** 800MB curated từ môi trường thực tế (V7) tốt hơn 46GB raw từ Internet (V0).

2. **Feature Engineering là chìa khóa:** Việc thay port number bằng Shannon Entropy giúp giải quyết triệt để vấn đề IP spoofing và port randomization.

3. **Kiến trúc Parallel thay vì Sequential:** CNN và GRU hoạt động độc lập (không nối tiếp) giúp tăng accuracy từ 0.89 lên 0.96.

4. **Adaptive Threshold thay vì Static:** EMA giúp hệ thống tự động nới lỏng ngưỡng vào giờ cao điểm, tránh báo động giả.

5. **Dual-Shield kiểm duyệt chéo:** Sự kết hợp Autoencoder + Classifier giúp giảm False Positive từ 60% xuống 3%.

6. **Tự động hóa kiểm định:** Xây dựng `check_data.py` để kiểm tra class balance, Slowloris presence, feature distribution trước khi train là bắt buộc.

Kiến trúc Web của hệ thống cũng được thiết kế theo mô hình phân lớp đặc trưng của SDN, phân tách rõ ràng giữa giao diện điều khiển và máy chủ thực thi:
-	Lớp Ứng dụng: Tập trung các logic quản lý và Dashboard giám sát, giúp quản trị viên tương tác với tầng điều khiển ONOS để thực thi các chính sách bảo mật.
-	Lớp dữ liệu: Triển khai trực tiếp các thành phần máy chủ (Web Server, PostgreSQL) để xử lý các truy vấn thực tế từ người dùng.
Được triển khai trên nền tảng giao thức HTTPS bảo mật và kết nối trực tiếp với cơ sở dữ liệu PostgreSQL, trang web không chỉ phục vụ các truy vấn tương tác dữ liệu thực tế của người dùng mà còn cung cấp các endpoint API để tiếp nhận và lưu trữ nhật ký phản vệ từ tác tử AI.
 
 
Hình 2.3. Mô hình Web của hệ thống
Hệ thống này đóng vai trò kép: vừa là đối tượng mục tiêu trực tiếp của các cuộc tấn công tầng ứng dụng (như HTTP Flood, Slowloris), vừa là trung tâm điều hành cho phép quản trị viên giám sát trạng thái mạng theo thời gian thực.
2.4.3.4. Thiết kế Module AI (Deep Learning Model)
Trong kiến trúc mạng SDN, lưu lượng tấn công DDoS hiện đại (Pulse Wave DDoS hay Low-rate DDoS) thường được ngụy trang tinh vi dưới dạng các xung lưu lượng có quy luật. Các phương pháp Machine Learning truyền thống thường chỉ phân tích dữ liệu tại một thời điểm, dẫn đến việc bỏ sót các hành vi mang tính chu kỳ. Do đó, chúng em xác định Module AI sẽ được thiết kế dựa trên sự kết hợp giữa mạng thần kinh tích chập (CNN) và đơn vị cổng lặp (GRU) để tạo ra một hệ thống IDS có khả năng phân tích đa chiều.
Lý do cân nhắc lựa chọn CNN + GRU kết hợp với cơ chế Attention trong rất nhiều kiến trúc deep (GNN, LSTM, Tran,…) . Vấn đề tốc độ, mô hình AI cần nhận diện được tấn công Ddos nhanh chóng và chính xác để tránh bộ não (mục tiêu bảo vệ) bị quá tải trước khi ngăn chặn được tấn công. Kiến trúc cũng phải tối ưu để không chiếm dụng quá nhiều tài nguyên của hệ thống mạng, nhằm đảm bảo tính riêng biệt về tài nguyên và cấu trúc mạng. Thực tế Ddos cũng có những phương thức tinh vi, khó nhận biết nếu chỉ nhìn vào các dữ liệu nhỏ rời rạc như các cuộc tấn công lowloris nên cần lựa chọn kiến trúc xử lý được dữ liệu theo thời gian.
Cấu trúc tổng thể của mô hình bao gồm các khối chức năng sau:
a. Khối đầu vào và Đặc trưng biến thiên (Input Layer) Thay vì đọc từng gói tin đơn lẻ, mạng AI được cung cấp cái nhìn toàn cảnh về "quá khứ gần" của mạng thông qua cơ chế Cửa sổ trượt (Sliding Window) với độ dài 10 bước thời gian. Điểm đột phá trong kiến trúc đầu vào là việc sử dụng ma trận đặc trưng 26 chiều. Trí tuệ nhân tạo không chỉ học 13 đặc trưng gốc tĩnh (như tổng số byte, số lượng gói tin) mà còn được cung cấp thêm 13 đặc trưng biến thiên (Differential Features). Đây là các giá trị đo lường gia tốc thay đổi lưu lượng giữa giây trước và giây sau. Đặc trưng biến thiên giúp mô hình nhận diện được các cuộc tấn công siêu chậm mà nếu chỉ nhìn vào con số tuyệt đối sẽ tưởng lầm là người dùng bình thường.
b. Lớp khiên thứ nhất: Mạng tự mã hóa tương phản - Đây là lớp khiên phòng thủ đầu tiên, hoạt động theo cơ chế học không giám sát.
-	Chức năng: Lớp này đóng vai trò là một bộ lọc dị thường (Anomaly Detector). Mô hình học cách nén và giải nén các luồng dữ liệu hợp lệ. Khi một luồng dữ liệu đi qua, hệ thống sẽ tính toán mức độ sai số tái tạo.
-	Mục đích thiết kế: Kiến trúc này được sử dụng làm chốt chặn phát hiện các cuộc tấn công chưa từng biết đến (Zero-day Attacks). Bất kể kẻ tấn công dùng phương thức mới nào, chỉ cần cấu trúc gói tin làm sai lệch kết quả tái tạo vượt quá ngưỡng cho phép, lớp khiên này sẽ đánh dấu là dị thường.
c. Lớp khiên thứ hai: Kiến trúc kết hợp song song (Parallel CNN-GRU-Attention) Nếu Lớp khiên 1 phát hiện có sự bất thường, luồng dữ liệu sẽ được chuyển sang Lớp khiên 2 để định danh chính xác loại hình tấn công (Normal, UDP Flood, SYN Flood, HTTP Flood hay Slowloris). Thay vì xử lý nối tiếp như các nghiên cứu cũ, đề tài thiết kế các mạng nơ ron chạy song song và độc lập để không làm nhiễu thông tin của nhau:
-	Khối tích chập không gian (CNN): Chuyên trách việc tìm kiếm quy luật không gian tại một thời điểm (Ví dụ: sự kết hợp giữa tốc độ gói tin tăng vọt và độ hỗn loạn của các cổng mạng),.
-	Khối ghi nhớ thời gian (GRU): Chuyên trách theo dõi sự thay đổi theo chiều dài thời gian của cửa sổ trượt. GRU giúp hệ thống nhận diện được nhịp điệu của các đợt tấn công kéo dài,.
-	Cơ chế tập trung (Attention): Đóng vai trò như một kính lúp, tự động dồn trọng số đánh giá vào những khoảng thời gian có dấu hiệu khả nghi nhất trong chuỗi 10 bước, giúp mô hình không bị xao nhãng bởi các gói tin hợp lệ xen ngang.
d. Khối tổng hợp và Quyền phủ quyết: Kết quả trích xuất từ mạng CNN và GRU được tổng hợp lại tại một lớp dày đặc để đưa ra xác suất phân loại cuối cùng. Tuy nhiên, để loại bỏ hoàn toàn các báo động giả (False Positive) khi lưu lượng mạng tăng đột biến vào giờ cao điểm, khối quyết định được tích hợp Quyền phủ quyết (Veto Power). Nếu khối phân loại (Lớp 2) nhận diện là tấn công, nhưng bộ lọc dị thường (Lớp 1) đánh giá cấu trúc luồng vẫn nằm trong ngưỡng an toàn của người dùng hợp lệ, hệ thống sẽ dùng quyền phủ quyết để đánh giá đây là luồng bình thường và không thực hiện chặn.

2.4.3.5. Thiết kế Module xử lý tại Controller (Onos Application)
Trong kiến trúc mạng SDN, bộ điều khiển ONOS đóng vai trò là "bộ não" trung tâm nhưng cũng chính là điểm yếu chí mạng (Single Point of Failure). Các hệ thống phòng thủ truyền thống thường hoạt động theo cơ chế tuần tự: đợi Controller nhận bản tin, trích xuất qua API, phân tích rồi mới chặn. Điều này tạo ra độ trễ lớn và dễ khiến hệ thống bị sập trước khi kịp ngăn chặn tấn công. Để giải quyết triệt để điểm nghẽn này, nhóm chúng em đã tái thiết kế Module xử lý theo kiến trúc bất đồng bộ (Asynchronous) và chia thành 3 khối chức năng cốt lõi:
a. Khối luồng thu thập và Tiền xử lý tốc độ cao (High-Performance Data Pipeline) Thay vì để Controller bị động chờ thiết bị gửi bản tin Packet-In lên, hệ thống áp dụng kiến trúc giám sát ngoại tuyến (Out-of-Band) với 4 tầng xử lý dữ liệu tốc độ cao:
-	Tầng 1 (Sao chép luồng): Hệ thống thiết kế một cổng giám sát riêng bằng kỹ thuật Port Mirroring tại Switch trung tâm (Gateway). Mọi luồng dữ liệu đi qua sẽ được nhân bản (Mirror) để AI phân tích mà không can thiệp hay làm chậm băng thông thực tế của người dùng.
-	Tầng 2 (Bóc tách sâu): Dữ liệu nhân bản được bóc tách bằng lõi phân tích mạng tốc độ cao. Khối này chịu trách nhiệm "nhìn thấu" gói tin từ tầng mạng (Layer 3) đến tận tầng ứng dụng (Layer 7) để bắt các dấu hiệu tấn công ngụy trang (như Slowloris, HTTP Flood) mà vẫn đảm bảo tiêu thụ tối thiểu tài nguyên CPU.
-	Tầng 3 (Ống truyền tải IPC): Để hệ thống đạt tốc độ thời gian thực, dữ liệu sau khi bóc tách được chuyển trực tiếp thẳng vào RAM thông qua cơ chế Ống dẫn (Named Pipes - FIFO). Thiết kế này loại bỏ hoàn toàn độ trễ do các thao tác đọc/ghi ổ cứng truyền thống.
-	Tầng 4 (Tính toán không gian/thời gian): Dữ liệu được tính toán thành Tensor 26 chiều (bao gồm 13 đặc trưng gốc và 13 đặc trưng biến thiên đo gia tốc chênh lệch gói tin). Các Tensor này được đóng gói thành Cửa sổ trượt (Sliding Window), cung cấp cho AI góc nhìn về "quá khứ gần" của mạng.
b. Khối logic ra quyết định Hai lớp khiên (Dual-Shield Decision Logic) Khối này đóng vai trò như một "tòa án kiểm duyệt chéo", kết hợp sức mạnh của 2 mạng nơ-ron AI (Autoencoder và CNN-GRU) thông qua một bảng chân lý thay vì sử dụng các ngưỡng chặn tĩnh cứng nhắc:
-	Ngưỡng thích nghi (Adaptive Threshold - EMA): Thay vì đặt một mức cảnh báo cố định, ngưỡng phát hiện bất thường của hệ thống tự động co giãn theo thời gian thực. Bằng việc sử dụng thuật toán Trung bình trượt hàm mũ (EMA), hệ thống tự động nới lỏng ngưỡng vào các giờ cao điểm và siết chặt vào giờ thấp điểm.
-	Cơ chế Quyền phủ quyết (Veto Power): Đây là chốt chặn quan trọng nhất để bảo vệ trải nghiệm của người dùng. Trong kịch bản người dùng hợp lệ bật cùng lúc nhiều tab trình duyệt, lớp phân loại có thể bị đánh lừa và báo động là tấn công HTTP Flood. Tuy nhiên, nếu lớp phân tích cấu trúc tổng thể đánh giá sai số vẫn nằm trong ngưỡng an toàn, hệ thống sẽ kích hoạt "Quyền phủ quyết" để bỏ qua lệnh chặn, từ đó triệt tiêu tỷ lệ báo động giả (False Positive).
c. Khối thực thi phòng vệ và Quản lý tài nguyên (Mitigation & Resource Management) Một khi hệ thống AI ra phán quyết cuối cùng là có tấn công, khối thực thi sẽ làm việc trực tiếp với giao diện lập trình (REST API) của ONOS để bảo vệ hạ tầng:
•	Hành động ngăn chặn linh hoạt: Tùy theo loại tấn công mà hệ thống gọi cấu trúc luật dòng chảy (Flow Rule) tương ứng. Lệnh DROP (hủy bỏ) được dùng với kẻ tấn công Flood rác, hoặc lệnh RATE_LIMIT (giới hạn băng thông) được thiết lập để cách ly an toàn các luồng nghi ngờ.
•	Bộ thu dọn rác (Garbage Collector): Đối mặt với các đợt tấn công SYN Flood làm giả hàng vạn địa chỉ IP ngẫu nhiên (IP Spoofing), bộ nhớ của Switch và Controller rất dễ bị tràn. Do đó, module được thiết kế tích hợp một tiến trình dọn rác chạy ngầm, liên tục quét và giải phóng các địa chỉ IP ảo ra khỏi bộ nhớ định kỳ, đảm bảo hệ thống phòng thủ có thể tự phục hồi và đứng vững trong dài hạn.

d. Các cơ chế nâng cao (Advanced Mechanisms)

Ngoài các khối chức năng chính, hệ thống còn tích hợp nhiều cơ chế nâng cao để đảm bảo hiệu suất và độ tin cậy:

•	Honeypot Integration (Decoy System): Hệ thống triển khai một Decoy IP (10.0.0.201) chạy Cowrie SSH Honeypot để thu hút attacker. Traffic đến honeypot được mirror sang IDS để phân tích, giúp thu thập IoC (Indicators of Compromise) mới và phát hiện Zero-day. Đây là "mồi nhử" bảo vệ các dịch vụ thật (web1:10.0.0.10).

•	WhiteList & BlackList Mechanism: Để tránh chặn nhầm và tối ưu hiệu suất, hệ thống duy trì danh sách trắng (WhiteList) cho IP tin cậy (DNS, Gateway) và danh sách đen (BlackList) cho attacker đã xác nhận. IP trong WhiteList được bypass hoàn toàn không qua AI; IP trong BlackList bị chặn ngay lập tức không cần phân tích lại.

•	Feedback Loop (Human-in-the-loop): Khi AI phát hiện với độ tin cậy ở "vùng xám" (60-85%), hệ thống lưu sample vào thư mục potential_false_positives/ để admin review. Sau khi xác nhận, dữ liệu được dùng để retrain model, tạo vòng lặp cải thiện liên tục.

•	Explainable AI (XAI): Thay vì chỉ đưa ra dự đoán "đây là UDP Flood", hệ thống sử dụng Spatial Attention và Temporal Attention để giải thích chi tiết: Flow nào bất thường (trong 10 flows), đặc trưng nào quan trọng nhất (Entropy, Packet_Rate...), giúp admin hiểu tại sao AI quyết định như vậy.

•	Persistence & Recovery: Hệ thống tự động lưu checkpoint (ngưỡng động threshold, danh sách WL/BL) mỗi 60 giây. Khi restart, AI khôi phục trạng thái cũ với giá trị MIN đảm bảo (threshold không thể thấp hơn 90% giá trị cơ bản), tránh mất "trí nhớ" sau sự cố.

[CHÈN ẢNH: nhanDienVaXuLyUDPFlood.png - Tiêu đề: Demo phát hiện và xử lý UDP Flood thời gian thực]

[CHÈN ẢNH: nhanDienVaXuLySYNFlood.png - Tiêu đề: Demo phát hiện và xử lý SYN Flood]
2.4.4. Xây dựng và Cài đặt hệ thống (System Implementation)
2.4.4.1. Môi trường triển khai
Quá trình hiện thực hóa các mô hình lý thuyết về SDN và AI vào thực tiễn đòi hỏi một môi trường thực nghiệm có hiệu năng ổn định và khả năng xử lý thời gian thực cao. Trong giai đoạn đầu, chúng em đã tiến hành thử nghiệm triển khai trên nền tảng ảo hóa VMWare. Tuy nhiên, do đặc thù của hệ thống yêu cầu vận hành đồng thời Controller ONOS, mạng mô phỏng Mininet và mô hình học sâu CNN-GRU, việc ảo hóa đã gây ra sự chiếm dụng tài nguyên RAM quá mức, dẫn đến hiện tượng trễ và không đảm bảo tính chính xác của dữ liệu.
Nhằm khắc phục hạn chế về phần cứng và khai thác tối đa hiệu suất xử lý của máy vật lý, chúng em đã quyết định cài đặt Ubuntu song song (Dual-boot) với hệ điều hành chính. Giải pháp này giúp hệ thống vận hành trực tiếp trên phần cứng, đảm bảo môi trường thực nghiệm mượt mà và ổn định cho các kịch bản tấn công DDoS phức tạp.
Các thông số phần cứng cùng với kĩ thuật sử dụng được chúng em tổng hợp qua bảng sau:
Thành phần	Thông số kỹ thuật	Ghi chú
Hệ điều hành	Ubuntu 22.04 LTS	Nền tảng chạy Mininet/ONOS
CPU / RAM	AMD Ryzen 5, Core I7 / 8GB ram	Tài nguyên máy vật lý
SDN Controller	ONOS 	Bộ não điều khiển mạng
Network Emulator	Mininet / Containernet	Môi trường mô phỏng topo
Deep Learning Library	Torch, Sklearn	Thư viện huấn luyện AI
Dataset	InSDN + CIC-IoT2023 và dữ liệu thu thập thực tế	Nguồn dữ liệu huấn luyện
Bảng 2.2. Môi trường ban đầu xác định
2.4.4.2. Quy trình huấn luyện mô hình (Offline Phase)
Mặc dù trên các cộng đồng nghiên cứu (như Kaggle hay UCI) có rất nhiều bộ dữ liệu về DDoS được chia sẻ công khai, nhưng nhóm chúng em nhận thấy việc áp dụng trực tiếp vào khóa luận gặp phải những rào cản lớn:
-	Tính đặc thù của mạng SDN: Các bộ dữ liệu truyền thống thường được thu thập từ môi trường mạng vật lý cũ. Trong khi đó, mạng SDN sử dụng giao thức OpenFlow với các thuộc tính dữ liệu đặc trưng từ Controller (như packet_ins, flow_duration_nsec) mà các bộ dữ liệu công khai thường thiếu sót hoặc không đồng nhất.
-	Sự thiếu nhất quán: Các tập dữ liệu rời rạc có sự khác biệt lớn về cấu trúc tên cột, khoảng giá trị của các đặc trưng và cách gán nhãn. Đặc biệt, đa số dữ liệu thô thường bị mất cân bằng nghiêm trọng (tỷ lệ dữ liệu bình thường chiếm đa số tuyệt đối so với dữ liệu tấn công).
-	Vấn đề bảo mật tầng ứng dụng (L7): Các cuộc tấn công tầng 7 (như Slowloris) thường chứa thông tin nhạy cảm về payload, dẫn đến việc các bộ dữ liệu công khai thường bị lược bỏ hoặc làm mờ các trường dữ liệu quan trọng này để đảm bảo quyền riêng tư, gây khó khăn cho việc huấn luyện khối GRU.
Những yếu tố trên khiến cho chúng em phải đặt vấn đề xây dựng bộ dữ liệu chuẩn phù hợp với mô hình mạng đã thiết kế là 1 việc cấp thiết.
Để giải quyết vấn đề này, thay vì chỉ thu thập dữ liệu thụ động, quy trình huấn luyện của đề tài yêu cầu xây dựng một bộ dữ liệu có tính thích nghi cao. Nguồn dữ liệu huấn luyện được tổng hợp và trích xuất trực tiếp từ chính môi trường mạng SDN mô phỏng. Việc này giúp mô hình học được các chỉ số đặc thù của giao thức OpenFlow và hành vi thời gian thực của người dùng (như độ trễ phản hồi, thời gian duy trì kết nối), từ đó loại bỏ hiện tượng sai lệch phân phối dữ liệu.
a. Kỹ thuật tiền xử lý và Kiến tạo đặc trưng: Dữ liệu thô thu được từ các thiết bị chuyển mạch không thể đưa trực tiếp vào mạng nơ-ron. Quá trình tiền xử lý được thực hiện để chuyển đổi các gói tin rời rạc thành các đặc trưng thống kê theo luồng (Flow-based Features).
Điểm đột phá trong quy trình này là hệ thống không chỉ trích xuất các giá trị tuyệt đối (như tổng số byte, số lượng gói tin) mà còn ứng dụng toán học vi phân để kiến tạo nhóm Đặc trưng biến thiên (Differential Features). Bằng cách tính toán "gia tốc" và sự chênh lệch lưu lượng giữa các mốc thời gian liên tiếp, mô hình được cung cấp thêm một chiều thông tin quan trọng. Điều này giúp AI dễ dàng bóc tách những cuộc tấn công có nhịp độ cực chậm và ngụy trang tinh vi (như Slowloris), vốn có bề ngoài rất giống với lưu lượng truy cập Web thông thường. Toàn bộ dữ liệu sau đó được chuẩn hóa về cùng một phương sai để đảm bảo tính công bằng giữa các thuộc tính trước khi đưa vào huấn luyện.
b. Chiến lược huấn luyện hai giai đoạn: Nhằm đối phó với sự phức tạp của các kịch bản tấn công hiện đại, quy trình huấn luyện không diễn ra theo một bước đơn lẻ mà được chia thành hai giai đoạn chiến lược, tương ứng với kiến trúc Hai lớp khiên:
-	Giai đoạn 1 - Học không giám sát: Hệ thống chỉ sử dụng các mẫu dữ liệu của người dùng bình thường để huấn luyện mạng tự mã hóa (Autoencoder). Mục tiêu là ép AI phải ghi nhớ hoàn hảo "hình hài" của một luồng mạng an toàn. Khi quá trình huấn luyện hoàn tất, hệ thống sẽ xác định được một ngưỡng sai số cấu trúc. Bất kỳ luồng mạng nào có cấu trúc sai lệch vượt quá ngưỡng này sẽ bị đánh dấu là bất thường, tạo tiền đề để bắt giữ các cuộc tấn công Zero-day.
-	Giai đoạn 2 - Học có giám sát nhạy cảm chi phí: Dữ liệu của cả lưu lượng bình thường và các loại hình tấn công được đưa vào để huấn luyện mạng phân loại chuyên sâu (CNN-GRU). Trong thực tế, dữ liệu về các cuộc tấn công tinh vi thường chiếm tỷ lệ rất nhỏ so với các cuộc tấn công làm ngập lụt băng thông, dẫn đến hiện tượng mất cân bằng dữ liệu. Để mô hình không bị "thiên vị" và bỏ qua các loại tấn công thiểu số, nhóm nghiên cứu áp dụng chiến lược học nhạy cảm chi phí. Các nhãn dữ liệu hiếm sẽ được gán trọng số phạt cao hơn, ép thuật toán phải chú ý và học cách phân biệt rạch ròi, từ đó triệt tiêu tình trạng chặn nhầm người dùng hợp lệ.
Sau khi hoàn tất các vòng lặp huấn luyện và vượt qua các bài kiểm định chéo để chống hiện tượng quá khớp (Overfitting), các tham số cấu trúc nơ-ron tốt nhất sẽ được đóng gói thành các tệp tin tri thức. Khối lượng tri thức này chính là "bộ não" sẽ được chuyển giao và tích hợp trực tiếp lên bộ điều khiển Controller trong giai đoạn vận hành thời gian thực.
Tên tệp tin	Chức năng trong hệ thống
sdn_scaler.pkl	Lưu trữ tham số chuẩn hóa dữ liệu để đồng bộ hóa đầu vào.
sdn_autoencoder.pth	Trọng số mạng Autoencoder phục vụ phát hiện tấn công Zero-day.
ae_threshold.pkl	Ngưỡng sai số để phân biệt lưu lượng bình thường và bất thường.
sdn_model_cnn_gru_attn.pth	Trọng số mô hình Hybrid dùng để phân loại chính xác các loại tấn công mạng.
Bảng 2.3. Các bảng được sinh ra sau khi huấn luyện
2.4.4.3. Quy trình tích hợp vào Onos Controller (Online Phase)
Dạ thưa các thầy cô, sau khi đã huấn luyện thành công "bộ não" AI ở giai đoạn ngoại tuyến, bài toán thách thức nhất đặt ra là làm thế nào để ghép nối bộ não này vào hệ thống mạng SDN đang vận hành mà không tạo ra độ trễ hay làm nghẽn cổ chai bộ điều khiển ONOS.
Thay vì sử dụng cơ chế kéo dữ liệu (Polling) qua REST API truyền thống vốn có độ trễ rất cao, nhóm chúng em đã thiết kế lại kiến trúc tích hợp ở Giai đoạn Online theo một đường ống bất đồng bộ, bao gồm 4 khối chức năng hoạt động song song:
a.	Khối nạp tri thức và Dịch vụ suy luận (Model Serving)
Tri thức của AI sau khi huấn luyện (bao gồm các trọng số của mạng Autoencoder, mạng CNN-GRU và tham số chuẩn hóa) được khởi tạo thành một dịch vụ chạy ngầm trên bộ nhớ RAM trực tiếp tại máy chủ điều hành. Dịch vụ này luôn ở trạng thái sẵn sàng lắng nghe (Listen) và nhận các luồng dữ liệu mới mà không cần phải khởi động lại qua mỗi chu kỳ dự báo.
b.	Đường ống thu thập ngoại tuyến (Out-of-band Ingestion)
Đây là cải tiến thiết kế quan trọng nhất của hệ thống. Thay vì bắt ONOS phải liên tục báo cáo lưu lượng mạng, hệ thống sử dụng cơ chế Sao chép cổng (Port Mirroring) tại Switch trung tâm. Toàn bộ gói tin đi qua mạng sẽ được nhân bản và phân luồng ra một cổng giám sát riêng biệt. Tại đây, công cụ bóc tách sâu (NFStream) sẽ phân tích dữ liệu và truyền trực tiếp kết quả cho Khối suy luận AI thông qua các ống truyền tải bộ nhớ (Named Pipes - FIFO). Thiết kế này đảm bảo dữ liệu di chuyển hoàn toàn trên RAM (Zero-copy IPC), giúp hệ thống phòng thủ vẫn đứng vững ngay cả khi mạng chính bị DDoS đánh sập.
c.	Khối suy luận và Ra quyết định (Inference Engine)
Dữ liệu từ ống truyền tải được đưa vào bộ đệm (Flow buffer) để đóng gói thành các cửa sổ trượt (gồm 10 bước thời gian). Tại đây, kiến trúc Hai lớp khiên (Dual-Shield) bắt đầu hoạt động. Mạng Autoencoder (Lớp 1) và CNN-GRU (Lớp 2) sẽ đồng thời kiểm tra dữ liệu. Nếu hệ thống AI xác nhận đây là tấn công với độ tin cậy cao và không bị kích hoạt quyền phủ quyết (Veto Power) từ lớp kiểm tra bất thường, một cờ cảnh báo (Alert Flag) sẽ được bật lên.
d.	Khối thực thi phản vệ và Giám sát (Mitigation & Dashboard)
Ngay khi cờ cảnh báo được bật, module Phản vệ (Mitigation) mới bắt đầu giao tiếp với bộ điều khiển ONOS thông qua giao diện REST API. Khối này sẽ tự động biên dịch kết quả của AI thành các chỉ thị Flow Rule (như lệnh DROP hoặc RATE_LIMIT) và đẩy xuống Switch để cách ly IP kẻ tấn công. Đồng thời, toàn bộ trạng thái của mạng lưới, lưu lượng băng thông thực tế và nhật ký cảnh báo sẽ được đồng bộ hóa lên Giao diện giám sát Web (Dashboard) theo thời gian thực, giúp quản trị viên có cái nhìn toàn cảnh về các cuộc tấn công đang bị ngăn chặn.
2.4.4.4. Giao diện giám sát (Dashboard - Tùy chọn nâng cao)
Ngoài ra, giao diện giám sát được chúng em xây dựng trên nền tảng Web-based, đóng vai trò là tầng tương tác cao nhất trong kiến trúc SDN, cho phép người dùng theo dõi toàn diện trạng thái hệ thống và hiệu quả của mô hình AI.
Dựa trên thiết kế thực tế, giao diện được chia thành các phân khu chức năng chuyên biệt:
-	Bảng thống kê tổng quát (Statistics Cards): Cung cấp cái nhìn nhanh về quy mô hệ thống bao gồm: tổng số 06 Switch OVS, 34 Host (tổng cộng 20 máy Botnet và 14 máy chủ dịch vụ).
-	Sơ đồ Topology trực quan (Network Visualization): Sử dụng các thư viện đồ họa để vẽ lại bản đồ mạng SDN thời gian thực. 
-	Bảng giám sát luồng dữ liệu (Flow Monitoring Table): Đây là nơi hiển thị dữ liệu đã qua xử lý từ server.py. 
-	Hệ thống Biểu đồ phân tích (Analytical Charts): Trực quan hóa dữ liệu dưới dạng đồ thị đường (Line Chart) để theo dõi xu hướng lưu lượng. 

TIỂU KẾT
Như vậy, trong Chương 2, chúng em đã mô hình hóa toàn bộ các sơ đồ kiến trúc, luồng dữ liệu và nguyên lý hoạt động tạo thành một bộ khung (framework) vững chắc. Tuy nhiên, để hiện thực hóa các bản thiết kế này từ lý thuyết thành một hệ thống phần mềm vận hành thực tế là một thách thức lớn. Các kỹ thuật cấu hình môi trường, quá trình xử lý dữ liệu, huấn luyện "bộ não" AI (Giai đoạn Offline) cũng như việc ghép nối các module để chống chịu với các kịch bản tấn công khốc liệt (Giai đoạn Online) sẽ được trình bày chi tiết tại Chương 3: Cài đặt, thực nghiệm và đánh giá.
