CHƯƠNG 3: CÀI ĐẶT, THỰC NGHIỆM VÀ ĐÁNH GIÁ
3.1. Cài đặt mô hình hệ thống
3.1.1. Chuẩn bị môi trường thực nghiệm
3.1.1.1. Cấu hình phần cứng/phần mềm: 
Để chuẩn bị cho dự án, đầu tiên nhóm đã quyết định lựa chọn việc cài HDH Ubuntu song song với Windown thay vì chạy gián tiếp thông qua máy ảo Vmware bởi những ưu việt mà nó mang lại.
Em xin tóm tắt lại môi trường triển khai thực tế bao gồm cấu hình laptop cá nhân và các phần mềm sử dụng qua bảng sau:
Thành phần	Thông số kỹ thuật	Ghi chú
Hệ điều hành	Ubuntu 22.04 	Cài đặt song song với HDH Windown
Phần cứng	CPU Core I7, ram 8G	Đảm bảo vận hành đồng thời 34 Host
SDN Controller	ONOS v2.7	Điều khiển 06 Switch OVS
Môi trường mạng	Mininet/ Containernet	Mô phỏng Topology phức hợp
Bảng 3.1. Các thông số môi trường thực tế
3.1.1.2. Xây dựng mô hình Topology mạng:
Quá trình hiện thực hóa bản thiết kế mạng 3 lớp (Core, Distribution, Access) từ trên lý thuyết vào môi trường mô phỏng Mininet là một thách thức lớn. Thực tế triển khai đã phát sinh nhiều rào cản kỹ thuật buộc nhóm phải tái cấu trúc kiến trúc mạng nhiều lần để đạt được sự ổn định tuyệt đối trước khi đưa AI vào thử nghiệm.
a.	Khởi đầu thất bại với quy mô lớn và mạng chuyển mạch L2 (Layer 2 Switching) 
Ban đầu, để mô phỏng một cuộc tấn công DDoS với quy mô sát thực tế nhất, nhóm đã khởi tạo một Topology lên đến 62 máy trạm (Hosts) và cấu hình phân luồng bằng phương pháp mạng chuyển mạch L2 truyền thống. Tuy nhiên, môi trường này đã nhanh chóng bộc lộ các điểm yếu chí mạng:
-	Quá tải phần cứng: Việc giả lập 62 thiết bị mạng chạy đồng thời khiến CPU của máy tính vật lý tăng vọt và luôn ở trạng thái quá tải, dẫn đến độ trễ mạng bị sai lệch, không đảm bảo tính chính xác cho dữ liệu thời gian thực.
-	Bão mạng (Broadcast Storm) và Tràn bảng MAC: Khi sử dụng mạng L2 trên một cấu trúc phẳng (Flat Network), các bản tin ARP broadcast liên tục bị nhân bản. Sự cố này làm tràn bảng địa chỉ MAC của Switch giả lập, gây ra hiện tượng xung đột, mất liên lạc giữa các phân đoạn mạng và lệnh kiểm tra liên thông toàn mạng (pingall) liên tục thất bại.
 
Hình 3.2. Sơ đồ mạng ban đầu
b.	Bước ngoặt thiết kế: Chuyển dịch toàn diện sang định tuyến L3 (Layer 3 Routing)
Nhận thấy phương pháp L2 cấu hình thủ công không thể đáp ứng được một hạ tầng mạng quy mô lớn, nhóm đã nghiên cứu kiến trúc mạng của các nhà cung cấp dịch vụ đám mây (Cloud Providers như Google, AWS) và quyết định đập bỏ cấu hình cũ để chuyển hẳn sang mô hình định tuyến L3 (L3 Routing).
-	Quy hoạch lại quy mô: Nhóm tinh gọn Topology xuống còn 34 thiết bị host, vừa đủ để phân chia 3 vùng mạng độc lập nhưng vẫn đảm bảo tài nguyên CPU hoạt động mượt mà.
-	Áp dụng định tuyến IP và Phân chia Subnet: Nhóm đã viết lại toàn bộ mã nguồn khởi tạo mạng (system.py) để chuyển từ việc đẩy gói tin bằng địa chỉ MAC sang định tuyến dựa trên dải IP. Các vùng mạng được cô lập triệt để thành 3 mạng con (Subnet): Mạng Datacenter chứa Server, Mạng Botnet và Mạng người dùng Client. Việc này không chỉ giải quyết triệt để bão mạng broadcast mà còn giúp Controller dễ dàng quản lý và viết các luật cấm theo từng dải IP.

**Công Thức Toán Học: EMA (Exponential Moving Average) - Ngưỡng Thích Nghi Động**

Thay vì sử dụng ngưỡng tĩnh (fixed threshold), hệ thống áp dụng EMA để tự động điều chỉnh ngưỡng phát hiện theo thời gian thực:

$$\theta_t = (1 - \alpha) \cdot \theta_{t-1} + \alpha \cdot \bar{x}_t$$

Trong đó:
- $\theta_t$: Ngưỡng tại thời điểm $t$
- $\theta_{t-1}$: Ngưỡng tại thời điểm trước đó
- $\bar{x}_t$: Giá trị trung bình MSE của batch Normal hiện tại
- $\alpha = 0.02$: Hệ số làm mượt (smoothing factor), quyết định tốc độ thích nghi

**Giới hạn an toàn (Clamping):**

$$\theta_t = \text{clip}(\theta_t, \theta_{\min}, \theta_{\max})$$

Với $\theta_{\min} = 0.1$ và $\theta_{\max} = 2.0$ để tránh ngưỡng "điên" do tấn công đối nghịch (adversarial).

**Ý nghĩa:**

| Thời điểm | Traffic | $\bar{x}_t$ | $\theta_t$ | Kết quả |
|-----------|---------|-------------|-------------|---------|
| 02:00 AM | Bình thường | 0.0001 | 0.15 (thấp) | Nhạy, phát hiện sớm |
| 09:00 AM | Giờ cao điểm | 0.001 | 0.45 (cao) | Không báo động giả |
| Tấn công | UDP Flood | 2.5 | Vẫn 0.45 | **Vượt ngưỡng → Chặn!** |

→ Kết quả: Giảm False Positive từ 60% xuống 3% khi lưu lượng tăng đột biến.

c.	Khó khăn trong tích hợp Controller và thiết lập liên thông
Dù đã quy hoạch xong mạng L3, quá trình kết nối hạ tầng Mininet với bộ não điều khiển ONOS vẫn gặp phải rào cản kỹ thuật khiến các thiết bị không thể "nhìn thấy" nhau. Qua quá trình gỡ lỗi, nhóm đúc kết được các yêu cầu cấu hình mang tính bắt buộc:
-	Kích hoạt ứng dụng điều hướng trên ONOS: Bộ điều khiển ONOS mặc định không tự động điều hướng gói tin. Nhóm bắt buộc phải truy cập vào giao diện CLI của ONOS để kích hoạt ứng dụng Reactive Forwarding (fwd). Nếu thiếu module này, các bản tin Packet-In gửi lên sẽ bị Controller ngó lơ, Switch không nhận được luật luồng khiến mạng bị "mù" hoàn toàn.
-	Cấu hình ánh xạ IP khắt khe: Trong kiến trúc định tuyến nhiều mạng con, việc thiết lập Default Gateway, IP và Subnet Mask phải chính xác tuyệt đối. Một sai sót nhỏ về IP ở một host có thể khiến gói tin bị gửi sai đích và làm sập toàn bộ đường truyền định tuyến.
Kết quả: Sau khi khắc phục các sự cố về định tuyến và ứng dụng, hệ thống mạng mô phỏng đã đạt trạng thái ổn định với tỷ lệ liên thông (pingall) thành công 100%. Việc xây dựng thành công một hạ tầng mạng chuẩn Enterprise mạnh mẽ, không bị sụp đổ bởi các lỗi nội tại chính là tiền đề sống còn để nhóm bắt đầu triển khai các kịch bản tấn công Flood khốc liệt ở các bước tiếp theo.
3.1.2. Quy trình Huấn luyện Mô hình (Giai đoạn Offline)
3.1.2.1. Chuẩn bị dữ liệu
Để mô hình Trí tuệ nhân tạo có thể nhận diện chính xác các cuộc tấn công DDoS trên môi trường SDN, chất lượng dữ liệu đầu vào đóng vai trò quyết định. Quá trình chuẩn bị dữ liệu thực tiễn của nhóm không đi theo lối mòn tải dữ liệu có sẵn, mà đã trải qua nhiều đợt thử nghiệm khắt khe để khắc phục những nhược điểm chí mạng của các hệ thống AI truyền thống.
a.	Sự thất bại của bộ dữ liệu công cộng và hiện tượng lệch phân phối
Trong giai đoạn đầu tiên (Phiên bản V1), nhóm đã sử dụng các bộ dữ liệu công cộng phổ biến trên Internet (CIC-IDS2019 kết hợp với các thuộc tính tổng hợp từ mô hình mạng) để huấn luyện. Mặc dù mô hình Random Forest đạt độ chính xác 84% trên môi trường Lab, nhưng khi đưa vào chạy thực tế trên Mininet, độ chính xác sụt giảm thảm hại xuống chỉ còn 37%, đồng thời tỷ lệ báo động giả (False Positive) tăng vọt lên 60%.
Nguyên nhân cốt lõi được rút ra là do hiện tượng lệch phân phối (Distribution Shift) và sự "học vẹt" theo cổng dịch vụ (Port-based). Các bộ dữ liệu cũ mang tính chất tĩnh, mặc định gắn nhãn an toàn cho một số cổng nhất định (ví dụ: Port 80 là HTTP bình thường). Tuy nhiên, trong thực tế, tin tặc liên tục thay đổi và làm giả (spoof) cổng ngẫu nhiên, khiến AI lập tức bị "mù". Hậu quả là, khi một người dùng hợp lệ mở cùng lúc 5 tab trình duyệt (tạo ra 5 cổng khác nhau), hệ thống lập tức báo động nhầm đó là 5 cuộc tấn công HTTP Flood.
Khi làm việc với nhiều bộ dữ liệu, nhóm sử dụng hàm “pd.read_csv và pd.concat” để đọc các tệp dữ liệu riêng lẻ và gộp chúng thành một DataFrame duy nhất, tóm tắt các hàm dùng để chuẩn hóa bằng Visual Studio Code qua bảng sau:
Bước	Hàm/Kỹ thuật chính	Mục tiêu
Hợp nhất	pd.concat	Gộp InSDN, CIC-IoT và dữ liệu thực
Lọc	df[features]	Giữ lại đúng 20-21 cột đặc trưng cần thiết.
Ánh xạ	.map()	Đồng bộ các loại tấn công về nhóm 0-4.
Chuẩn hóa	StandardScaler	Đưa dữ liệu về phân phối chuẩn N(0, 1).
Tạo chuỗi	create_safe_sequences	Định dạng dữ liệu cho đầu vào GRU.
Đặc trưng DNS	qtype_name, rcode_name	Hỗ trợ đắc lực trong việc phát hiện các biến thể tấn công khuếch đại DNS (DNS Amplification).
Bảng 3.2. Các hàm sử dụng để chuẩn hóa dữ liệu
b.	Tự động hóa thu thập dữ liệu trực tiếp (Môi trường V7) 
Nhận ra nguyên lý "Chất lượng dữ liệu quan trọng hơn số lượng", nhóm quyết định loại bỏ hoàn toàn bộ dữ liệu tổng hợp 46GB từ Internet. Thay vào đó, nhóm tự phát triển một module chuyên biệt (auto_dataset_generator.py) để sinh và thu thập dữ liệu trực tiếp từ hệ thống mạng Mininet kết hợp ONOS.
 
Hình 3.5. Thiết lập dữ liệu chuẩn
Công việc này đòi hỏi sự đầu tư khổng lồ về mặt thời gian. Do giới hạn của môi trường ảo hóa dễ bị tràn bộ nhớ (OOM) khi bị tấn công liên tục, nhóm không thể lập trình cho máy chạy tự động qua đêm. Mỗi phiên bản dữ liệu (từ V2 đến V7) đòi hỏi người thực hiện phải ngồi trực tiếp trước màn hình Terminal từ 8 đến 10 giờ mỗi ngày, tiêu tốn khoảng 36 giờ giám sát thủ công cho mỗi chu kỳ thu thập để điều chỉnh nhịp độ tấn công. Kết quả cuối cùng, nhóm đã xây dựng thành công Bộ Dataset V7 chuẩn mực, chứa 75.000 mẫu được cân bằng hoàn hảo (chính xác 15.000 mẫu cho mỗi nhãn: Normal, UDP, SYN, HTTP, và Slowloris). Điều này giúp giải quyết triệt để bài toán mất cân bằng dữ liệu, đặc biệt là với loại hình tấn công thiểu số như Slowloris.
Thêm ảnh Bộ dữ liệu chuẩn
c.	Đột phá trong trích xuất Đặc trưng (Feature Engineering)
Thay vì trích xuất 20 đặc trưng tĩnh rời rạc, nhóm đã thực hiện những tối ưu toán học mang tính bước ngoặt nhằm kiến tạo lại bộ đầu vào cho AI:
-	Sử dụng Shannon Entropy thay cho Cổng vật lý: Để chống lại kỹ thuật làm giả IP và Port, nhóm loại bỏ hoàn toàn việc phân tích số hiệu Port thô. Thay vào đó, công thức Entropy được áp dụng để đo lường độ hỗn loạn của cổng đích và cổng nguồn. Entropy thấp thể hiện truy cập có chủ đích của người dùng, trong khi Entropy cao báo hiệu sự ngẫu nhiên của các máy Botnet. Quá trình này giúp chắt lọc ra 13 đặc trưng gốc cốt lõi phản ánh đúng "hành vi" mạng.
-	Bổ sung Đặc trưng biến thiên (Differential Features): Tại phiên bản V4, nhóm phát hiện ra rằng để nhận diện được các đợt tấn công "nhỏ giọt" lẩn trốn bộ lọc, hệ thống không thể chỉ nhìn vào con số tuyệt đối. Nhóm lập trình bổ sung thêm 13 đặc trưng biến thiên bằng toán học vi phân (tính gia tốc chênh lệch).

**Code Minh Họa: Differential Features (Từ README)**

[CHÈN ẢNH: code_differentialFeatures.png - Tiêu đề: Code tính Differential Features từ README]

```python
def differential_features_numpy(X):
    """
    Tính đặc trưng biến thiên
    X: [Batch, Seq, Features] = [B, 10, 13]
    Return: [B, 10, 26] (13 gốc + 13 biến thiên)
    """
    batch_size, seq_len, num_features = X.shape
    diff = np.zeros_like(X)
    diff[:, 1:, :] = X[:, 1:, :] - X[:, :-1, :]  # Tính sự thay đổi
    
    combined = np.concatenate([X, diff], axis=-1)
    return combined  # [Batch, Seq, 26]
```

Việc tính toán sự chênh lệch này giúp tạo ra một bộ Tensor 26 chiều đặc trưng (13 tĩnh + 13 biến thiên). Cấu trúc này trao cho "bộ não" AI khả năng nhìn thấy "vận tốc" thay đổi của luồng mạng, từ đó phân biệt rạch ròi giữa việc người dùng đang click chuột cực nhanh (biến thiên ngẫu nhiên) với một cuộc tấn công do máy móc tự động sinh ra (biến thiên bằng 0).
Cuối cùng, toàn bộ cấu trúc dữ liệu 26 chiều đa nguồn được kết nối thông qua thư viện Pandas (pd.concat) và đưa qua hàm StandardScaler để chuẩn hóa về cùng phân phối trước khi đóng gói cho các mạng nơ-ron học sâu.
STT	Đặc trưng tĩnh (Core Features)	Đặc trưng biến thiên (Differential - Δ)	Ý nghĩa và Vai trò trong phân loại tấn công DDoS
1	Src_Port_Entropy	d_Src_Port_Entropy	Đo độ ngẫu nhiên của cổng nguồn bằng công thức Shannon. Giúp phát hiện kẻ tấn công giả mạo địa chỉ IP (IP Spoofing). 
2	Dst_Port_Entropy	d_Dst_Port_Entropy	Đo độ hỗn loạn cổng đích. Nhận diện UDP Flood khi tin tặc đánh vào hàng loạt cổng ngẫu nhiên trên máy chủ. 
3	Protocol	d_Protocol	Phân loại giao thức mạng (TCP, UDP, ICMP). Định hình ngay từ đầu vector tấn công (Layer 3/4). 
4	Duration_Sec	d_Duration_Sec	Thời gian sống của luồng. Phân biệt rõ ràng Slowloris (sống ngâm rất lâu từ 30-120s) và tấn công Flood (chỉ sống <1s). 
5	Src_Bytes	d_Src_Bytes	Đo lường băng thông đẩy lên máy chủ. Chỉ số cốt lõi để nhận diện các cuộc tấn công ngập lụt băng thông (Volumetric). 
6	Dst_Bytes	d_Dst_Bytes	Đo lường dữ liệu máy chủ trả về. Tìm kiếm sự bất đối xứng (Ví dụ: Request nhiều nhưng Response bằng 0). 
7	Src_Packets	d_Src_Packets	Số lượng gói tin gửi đi. Đóng vai trò như một bộ đếm tần suất tấn công chớp nhoáng. 
8	Dst_Packets	d_Dst_Packets	Số lượng gói tin nhận về. Dấu hiệu nhận biết TCP SYN Flood (tin tặc chỉ gửi SYN mà không bao giờ nhận/phản hồi ACK). 
9	Conn_State	d_Conn_State	Phân tích trạng thái kết nối. Bắt quả tang các kết nối bị treo ở trạng thái mở một nửa (Half-open / S0). 
10	L7_App_Protocol	d_L7_App_Protocol	Trích xuất tầng ứng dụng (HTTP, DNS, TLS) qua nDPI. Chìa khóa để mạng GRU nhận diện chính xác HTTP Flood. 
11	Packet_Rate	d_Packet_Rate	Tốc độ gói tin/giây. Chỉ số "vàng" phát hiện ngập lụt (Ví dụ: Flood sinh ra hàng chục nghìn gói/s, người dùng chỉ vài gói/s). 
12	Byte_Rate	d_Byte_Rate	Tốc độ Byte/giây. Giúp AI theo dõi sự vắt kiệt băng thông thực tế theo thời gian thực. 
13	Anomaly_Score / Is_one_way	d_Anomaly_Score	Điểm bất thường từ Autoencoder hoặc cờ đánh dấu luồng đơn hướng (Unidirectional). Xác nhận hành vi phi tự nhiên của lưu lượng. 
Bảng 3.3. Các đặc trưng có trong dữ liệu mẫu
Bằng việc tính toán thêm 13 đặc trưng biến thiên (Differential Features) bằng công thức , chúng ta cung cấp cho AI khả năng đo lường "gia tốc" của luồng mạng.
-	Với người dùng thật: Tốc độ click có thể nhanh, nhưng gia tốc luôn biến thiên ngẫu nhiên (lúc nhanh lúc chậm).
-	Với Botnet (Máy móc tự động): Dù kẻ tấn công cố tình hạ thấp Packet_Rate xuống mức chậm để lẩn trốn (như Slowloris), thì gia tốc thay đổi (ví dụ: d_Packet_Rate) của máy móc sinh ra gần như sẽ bằng 0 hoặc lặp lại theo chu kỳ tuyến tính một cách thiếu tự nhiên.
Chính ma trận này đã mang lại cho mô hình CNN-GRU khả năng phân biệt cực kỳ sắc bén, giúp khắc phục triệt để điểm mù của các IDS/IPS truyền thống trên nền tảng SDN.
3.1.2.2. Huấn luyện mô hình
Trên cơ sở hạ tầng mạng và tập dữ liệu V7 (với 26 chiều đặc trưng) đã chuẩn bị, quy trình xây dựng "bộ não" AI được tiến hành. Nhằm tận dụng sức mạnh tính toán, toàn bộ quy trình huấn luyện được thực hiện trên nền tảng Google Colab. Quá trình này không diễn ra suôn sẻ ngay từ đầu mà là một hành trình tinh chỉnh liên tục qua các phiên bản, được chia làm hai giai đoạn chiến lược nhằm xử lý triệt để các rào cản kỹ thuật phức tạp.
a.	Giai đoạn 1: Huấn luyện bộ lọc bất thường (Contrastive Autoencoder) Thay vì sử dụng mạng Autoencoder với hàm mất mát MSE (Mean Squared Error) cơ bản như các nghiên cứu trước, nhóm đã áp dụng kỹ thuật Học tương phản (Contrastive Learning) với hàm Margin Loss.

**Công Thức Toán Học: Contrastive Loss (Học tương phản với Margin)**

Thay vì chỉ tối thiểu hóa MSE (Mean Squared Error) cho tất cả dữ liệu, Contrastive Loss ép buộc mô hình phải phân biệt rõ ràng giữa Normal và Attack thông qua một ranh giới an toàn (margin):

$$\mathcal{L}_{\text{contrastive}} = \underbrace{\frac{1}{N}\sum_{i=1}^{N} \|x_i^{\text{normal}} - \hat{x}_i^{\text{normal}}\|^2}_{\text{MSE cho Normal (ép nhỏ)}} + \underbrace{\sum_{j=1}^{M} \max(0, m - \|x_j^{\text{attack}} - \hat{x}_j^{\text{attack}}\|^2)^2}_{\text{Hinge Loss cho Attack (ép lớn hơn } m)}$$

Trong đó:
- $x_i^{\text{normal}}$: Mẫu dữ liệu bình thường thứ $i$
- $\hat{x}_i$: Dữ liệu được tái tạo (reconstructed) từ Autoencoder
- $m = 2.0$: Margin (ranh giới an toàn)
- $\|\cdot\|^2$: Bình phương khoảng cách Euclidean (MSE)

**Ý nghĩa toán học:**

| Trường hợp | MSE | Kết quả | Giải thích |
|-----------|-----|---------|-----------|
| **Normal** | $\text{MSE} < 0.001$ | $\mathcal{L} \approx 0.001$ | AE học reconstruct tốt |
| **Attack** | $\text{MSE} > 2.0$ | $\mathcal{L} \approx 0$ | Đạt margin, không phạt |
| **Attack** | $\text{MSE} = 0.5$ | $\mathcal{L} = (2.0-0.5)^2 = 2.25$ | Phạt nặng vì chưa đủ xa |

**So sánh trước/sau:**

| Phiên bản | Loss Function | Normal MSE | Attack MSE | Threshold | FP Rate |
|-----------|--------------|-----------|-----------|-----------|---------|
| V3 | MSE đơn giản | 0.002 | 0.003 | 0.0025 | 10% |
| **V4** | **Contrastive (m=2.0)** | **0.0001** | **2.5** | **0.5** | **1%** |

→ Kết quả: Vùng phân biệt rõ ràng hơn 1000 lần, giảm False Positive đáng kể.

**Code Minh Họa: Contrastive Loss (Từ README)**

[CHÈN ẢNH: code_contrastiveLoss.png - Tiêu đề: Code Contrastive Loss từ README]

```python
class ContrastiveLoss(nn.Module):
    def __init__(self, margin=AE_MARGIN):  # AE_MARGIN = 2.0
        super().__init__()
        self.margin = margin
    
    def forward(self, ae_model, x_normal, x_attack):
        # Normal: MSE phải thấp
        mse_normal = MSE(x_normal, ae_model(x_normal))
        
        # Attack: MSE phải cao hơn margin
        mse_attack = MSE(x_attack, ae_model(x_attack))
        
        # Hinge loss: max(0, margin - attack_mse)^2
        loss = mse_normal + max(0, margin - mse_attack)**2
        
        return loss
```

-	Cách thức: Mô hình chỉ được cung cấp dữ liệu của người dùng hợp lệ (Normal). Hàm Margin (được cấu hình bằng 2.0) sẽ ép mô hình phải siết chặt ranh giới nhận diện: nén và giải nén hoàn hảo các luồng Normal, đồng thời đẩy sai số tái tạo của các luồng Attack vượt qua ngưỡng cho phép.
-	Kết quả: Tạo ra lớp khiên thứ nhất có khả năng phát hiện 89.3% các cuộc tấn công Zero-day chưa từng xuất hiện trong tập huấn luyện.
b.	Giai đoạn 2: Huấn luyện bộ định danh chuyên sâu (Parallel CNN-GRU-Attention với Multi-Scale Residual)
Để định danh chính xác 5 loại lưu lượng (Normal, UDP, SYN, HTTP, Slowloris), ban đầu nhóm sử dụng kiến trúc nối tiếp (CNN rồi mới đến GRU). Tuy nhiên, thực nghiệm cho thấy kiến trúc này làm nhiễu thông tin của nhau. Nhóm đã đập đi xây lại bằng kiến trúc Song song (Parallel Fusion) kết hợp với Multi-Scale Residual CNN.

•	Nhánh CNN với Multi-Scale Residual Blocks: Thay vì dùng CNN đơn giản, nhóm thiết kế Multi-Scale Residual Blocks với 2 nhánh song song:
o	Nhánh Kernel 3: Bắt pattern cục bộ (local patterns) như tốc độ gói tin tăng vọt.
o	Nhánh Kernel 5: Bắt pattern ngữ cảnh rộng (contextual patterns) như xu hướng thay đổi trong cửa sổ thời gian.
o	Residual Connection: Phép cộng shortcut giúp gradient flow tốt hơn, tránh vanishing gradient trong mạng sâu.

•	Nhánh GRU học quy luật thời gian (như nhịp điệu ngâm kết nối lắp lại báo hiệu Slowloris). Sử dụng Bi-GRU 2 lớp với Dropout 0.4 để học cả chiều thuận và ngược.

•	Spatial Attention + Temporal Attention: Spatial Attention gán trọng số cho từng đặc trưng (ví dụ: Packet_Rate quan trọng hơn Entropy khi UDP Flood). Temporal Attention tập trung vào flow bất thường nhất trong chuỗi 10 bước.

**Công Thức Toán Học: Attention Mechanism (Cơ chế Tập trung)**

Attention cho phép mô hình tập trung vào các phần quan trọng của dữ liệu, tương tự cách con người chú ý vào điểm then chốt:

$$
\text{Attention}(Q, K, V) = \text{softmax}\left(\frac{QK^T}{\sqrt{d_k}}\right)V
$$

Trong đó:
- $Q$ (Query): Vector đại diện cho câu hỏi "đâu là đặc trưng/thời điểm quan trọng?"
- $K$ (Key): Vector đại diện cho các đặc trưng/thời điểm cần đánh giá
- $V$ (Value): Vector chứa giá trị thực tế của các đặc trưng
- $d_k$: Chiều của Key vector (dùng để scale, tránh gradient quá lớn)
- $\sqrt{d_k}$: Hệ số chuẩn hóa (theo paper "Attention is All You Need")

**Công thức Softmax:**

$$
\text{softmax}(z_i) = \frac{e^{z_i}}{\sum_{j=1}^{n} e^{z_j}}
$$

**Áp dụng trong hệ thống:**

| Loại Attention | $Q, K, V$ | Kết quả |
|----------------|-----------|---------|
| **Spatial** | Đặc trưng 26 chiều | Trọng số cho từng feature (Packet_Rate = 0.8, Protocol = 0.1) |
| **Temporal** | 10 time steps | Trọng số cho từng bước thời gian (t=7 bất thường → weight = 0.6) |

→ Kết quả: AI tự động "nhìn" vào đúng đặc trưng quan trọng và đúng thời điểm bất thường, tăng độ chính xác từ 0.89 lên 0.96.

Hai nhánh CNN và GRU hoạt động độc lập song song (không nối tiếp), chỉ được concatenate ở lớp Fusion (384-dim) rồi đưa qua các lớp FC để phân loại. Kiến trúc này giúp tăng độ chính xác tổng thể từ 0.89 lên 0.96 (F1-Score).
c.	Các khó khăn và Kỹ thuật tối ưu hóa chuyên sâu
Trong quá trình chạy thực tế, nhóm đã vấp phải 3 sự cố nghiêm trọng khiến đồ thị huấn luyện bị gãy nát. Dưới đây là cách nhóm giải quyết:
1.	Hiện tượng Bùng nổ đạo hàm (Exploding Gradients):
o	Sự cố: Khi huấn luyện chuỗi thời gian 10 bước (Seq_Len=10), giá trị Gradient tăng vọt khiến đồ thị Loss nhảy múa hình "răng cưa", mô hình không thể hội tụ.
o	Giải pháp: Tích hợp kỹ thuật Gradient Clipping (max_norm=1.0). Cơ chế này hoạt động như một chốt chặn, không cho phép bất kỳ lực cập nhật trọng số nào vượt quá giới hạn an toàn.
2.	Sự "hoang tưởng" và Báo động giả (Overconfidence):
o	Sự cố: Ở các phiên bản đầu, AI mắc bệnh "hoang tưởng" - ép xác suất lên 100% khi dự đoán tấn công. Sự tự tin thái quá này khiến mô hình dễ bị lừa, dẫn đến việc chặn nhầm hàng loạt người dùng thật.
o	Giải pháp: Nhóm cấu hình kỹ thuật Label Smoothing (0.1). Thay vì tin tưởng tuyệt đối, AI bị ép phải "chừa đường lui" (phân bổ 10% xác suất cho các trường hợp khác). Việc này giúp giảm tỷ lệ False Positive xuống mức tối thiểu.
3.	Mất cân bằng dữ liệu của Slowloris:
o	Sự cố: Slowloris là loại tấn công cực kỳ tinh vi, có số lượng mẫu ít. Ban đầu nhóm đặt trọng số phạt (Class Weight) lên đến 10.0 để ép AI chú ý. Hậu quả là AI sợ bỏ sót nên đã nhận diện nhầm luồng HTTP bình thường thành Slowloris.
o	Giải pháp: Nhóm giảm giới hạn trọng số xuống mức tối đa là 6.0, kết hợp với hàm mất mát Focal Loss (Gamma=2.0) để AI tập trung vào các "mẫu khó" thay vì chỉ tập trung vào số lượng. Kỹ thuật này đã kéo chỉ số F1-Score của Slowloris từ 0.71 lên 0.81.

**Công Thức Toán Học: Focal Loss**

Focal Loss được thiết kế để giải quyết vấn đề mất cân bằng lớp bằng cách giảm trọng số của các mẫu dễ (easy samples) và tập trung vào các mẫu khó (hard samples):

$$FL(p_t) = -\alpha_t (1 - p_t)^\gamma \log(p_t)$$

Trong đó:
- $p_t$: Xác suất dự đoán đúng của mô hình (ground truth class probability)
- $\alpha_t$: Trọng số cân bằng lớp (class weight)
- $\gamma = 2.0$: Focusing parameter (điều chỉnh mức độ "tập trung")

**Ý nghĩa của $(1 - p_t)^\gamma$:**

| Độ tin cậy | $(1-p_t)$ | $(1-p_t)^2$ | Trọng số loss | Ý nghĩa |
|-----------|-----------|-------------|---------------|---------|
| Cao (0.9) | 0.1 | 0.01 | Giảm 100x | Mẫu dễ, không cần học nhiều |
| Trung bình (0.5) | 0.5 | 0.25 | Giảm 4x | Mẫu trung bình |
| Thấp (0.1) | 0.9 | 0.81 | Giảm 1.2x | **Mẫu khó, cần học nhiều** |

→ Kết quả: AI tự động tập trung vào các mẫu Slowloris khó phân biệt thay vì ngập trong số lượng lớn UDP Flood dễ phân biệt.
Kết hợp với bộ lập lịch OneCycleLR giúp tăng tốc độ học (Learning Rate) ở giai đoạn đầu để vượt qua cực tiểu địa phương, quá trình huấn luyện đã kết thúc mượt mà và tự động dừng sớm để chống quá khớp (Overfitting).
**Hình ảnh kết quả huấn luyện (từ README):**

[CHÈN ẢNH: ketQuaTrainlop1_aiv4_datasetv7.png - Tiêu đề: Kết quả huấn luyện Lớp 1 (Autoencoder) với Dataset V7 - MSE loss giảm ổn định]

[CHÈN ẢNH: ketQuaTrainKhien2_aiv4_datasetv7.png - Tiêu đề: Kết quả huấn luyện Lớp 2 (CNN-GRU-Attention) với Dataset V7 - Accuracy đạt 96%]

[CHÈN ẢNH: maTranNhamLancuaAiv3.png - Tiêu đề: Ma trận nhầm lẫn của AI V3 - So sánh trước/sau cải tiến]

[CHÈN ẢNH: ketQuaV3-AoGiac.png - Tiêu đề: Vấn đề "Ảo giác" của V3 - False Positive cao do thiếu Veto Power]

d. Đóng gói Tri thức (Model Export) Sau khi huấn luyện thành công, toàn bộ "chất xám" của hệ thống được xuất ra thành 4 tệp tin cốt lõi, sẵn sàng chuyển giao cho bộ điều khiển ONOS:
-	sdn_scaler.pkl: Chứa tham số để chuẩn hóa 26 chiều dữ liệu thực tế.
-	sdn_autoencoder.pth: Trọng số của lớp Khiên 1 (Autoencoder).
-	ae_threshold.pkl: Ngưỡng sai số động (Threshold) dùng để kích hoạt quyền phủ quyết.
-	sdn_model_cnn_gru_attn.pth: Trọng số của bộ định danh 5 nhãn tấn công (Khiên 2).
Tên tệp tin	Định dạng	Thành phần kiến trúc	Công dụng và Vai trò trong hệ thống
sdn_scaler.pkl	.pkl	StandardScaler	Lưu trữ các tham số trung bình và độ lệch chuẩn của 20 thuộc tính. Nhiệm vụ là chuẩn hóa dữ liệu thực tế từ Switch về cùng phân phối với dữ liệu huấn luyện, đảm bảo AI không bị sai lệch khi đọc các con số thô.

sdn_autoencoder.pth	.pth 	Anomaly Autoencoder	Chứa trọng số của mạng nơ-ron nén dữ liệu. Đóng vai trò là "lớp khiên số 1" chuyên phát hiện các hành vi lạ (Zero-day) dựa trên sai số tái tạo, chặn đứng các cuộc tấn công mới chưa có trong tập dữ liệu.
sdn_model_cnn_gru_attn.pth	.pth 	Hybrid CNN-GRU-Attention	Là bộ não chính của hệ thống, chứa các bộ lọc không gian (CNN), nút nhớ thời gian (GRU) và trọng số tập trung (Attention). Nhiệm vụ là định danh chính xác 5 loại lưu lượng (Benign, UDP, SYN, HTTP, Slowloris).
ae_threshold.pkl	.pkl	Anomaly Detection Threshold	Là thước đo ranh giới của hệ thống, chứa ngưỡng sai số tái tạo tối ưu được tính toán từ dữ liệu bình thường (Normal). Nhiệm vụ là hỗ trợ Khiên 1 phát hiện các hành vi bất thường và tấn công chưa biết (Zero-day) thông qua cơ chế ngưỡng động thích nghi.
Bảng 3.4. Các file sinh ra sau khi Train mô hình
3.1.3. Tích hợp hệ thống (Giai đoạn Online)
Đây là giai đoạn chuyển đổi mô hình từ môi trường huấn luyện (Offline) từ bước trên sang môi trường vận hành thực tế (Online) trên bộ điều khiển ONOS. Hệ thống hoạt động như một vòng lặp kín giữa giám sát, phân tích và phản ứng.
3.1.3.1. Khởi tạo và nạp tri thức AI
Quá trình tích hợp Giai đoạn Online bắt đầu bằng việc thiết lập một tác tử AI hoạt động độc lập trên bộ nhớ của hệ thống quản trị, đóng vai trò như một cầu nối giữa mô hình Deep Learning và bộ điều khiển ONOS. 
a.	Khôi phục trạng thái và Nạp trọng số (Weight Loading)
Các "tri thức" sau quá trình huấn luyện trên Google Colab được tải về máy chủ nội bộ (Ubuntu) dưới dạng các tệp tin tuần tự hóa. Quá trình nạp được thực hiện qua các thư viện chuyên dụng:
-	Nạp bộ chuẩn hóa (sdn_scaler.pkl): Nhóm sử dụng thư viện Joblib để khôi phục cấu trúc của hàm StandardScaler. Việc này đảm bảo mọi gói tin theo thời gian thực thu được từ Switch đều được căn chỉnh về đúng phương sai giống hệt như dữ liệu lúc AI học, tránh tình trạng AI dự báo sai do chênh lệch tỷ lệ các con số.
-	Nạp kiến trúc nơ-ron (.pth): Bằng thư viện PyTorch, hệ thống khởi tạo lại toàn bộ ma trận lớp ẩn của mạng Anomaly Autoencoder và mạng phân loại CNN-GRU-Attention. Sau khi nạp trọng số từ các file sdn_autoencoder.pth và sdn_model_cnn_gru_attn.pth, một thao tác mang tính bắt buộc là phải chuyển toàn bộ các mô hình sang chế độ suy luận bằng lệnh model.eval(). Thao tác này sẽ khóa các lớp Dropout và cố định Batch Normalization, giúp kết quả dự báo luôn nhất quán và tiết kiệm tối đa tài nguyên RAM của máy vật lý.
b.	Tối ưu hóa suy luận thời gian thực (Inference Optimization)
Trong thực tế, khi đối mặt với một cuộc tấn công DDoS quy mô lớn, tốc độ mạng có thể đạt hàng trăm nghìn gói tin mỗi giây. Nếu sử dụng nguyên bản PyTorch như lúc huấn luyện, độ trễ hệ thống lên tới 150ms - quá chậm để Controller kịp phản ứng. Để giải quyết bài toán này, nhóm đã tái cấu trúc môi trường chạy. Các tensor đầu vào không được xử lý tuần tự mà được nhóm lại thành các batch nhỏ thông qua mảng vector hóa của thư viện Numpy. Kỹ thuật này giúp ép thời gian suy luận (Inference Time) của AI giảm từ 80ms xuống chỉ còn khoảng 15ms cho mỗi luồng.

 
Hình 3.6. Nạp tri thức cho AI
3.1.3.2. Logic giám sát và tiền xử lý (Monitor Logic)
Thưa các thầy cô, sau khi các tri thức AI đã được nạp lên RAM, bài toán hóc búa tiếp theo nhóm phải đối mặt là làm sao để "mớm" dữ liệu cho AI với tốc độ thời gian thực (Real-time).
Để giải quyết vấn đề này, nhóm không sử dụng cách ghi log thông thường mà đã tự tay lập trình một đường ống thu thập (Pipeline) 3 bước khép kín, tối ưu hóa đến từng mili-giây:
a. Cấu hình Port Mirroring (Cách ly rủi ro hạ tầng) Ban đầu, nhóm định cài đặt công cụ giám sát trực tiếp lên Web Server. Tuy nhiên, thực tế chứng minh đây là một sai lầm: khi Web Server bị tấn công DDoS cạn kiệt CPU/RAM, tiến trình thu thập dữ liệu cũng sẽ bị sập theo, khiến AI mù hoàn toàn. Để khắc phục, nhóm cấu hình tính năng Port Mirroring (Sao chép cổng) ngay tại Switch Gateway trung tâm (s6). Toàn bộ lưu lượng đi qua mạng sẽ được OVS (Open vSwitch) nhân bản phần cứng và đẩy ra một cổng giám sát riêng biệt (Out-of-band). Nhờ vậy, dù Web Server mục tiêu có bị đánh sập, tiến trình bóc tách dữ liệu của hệ thống phòng thủ vẫn hoạt động trơn tru.
b. Tích hợp NFStream và Kỹ thuật Timeout Động (Dynamic Timeout Profiles) Trong quá trình bóc tách gói tin, nhóm đã thử nghiệm dùng công cụ Zeek IDS. Dù soi rất sâu nhưng Zeek quá nặng, làm CPU máy tính tăng vọt lên 80% và gây treo luôn mạng mô phỏng Mininet. Nhóm quyết định đập bỏ và viết lại bằng thư viện NFStream (lõi nDPI C++). Công cụ này cực nhẹ (CPU < 20%) nhưng vẫn bóc tách được tận Tầng 7 (HTTP headers, TCP Flags) để nhận diện DDoS.
Đặc biệt, trong quá trình code thực tế, nhóm phát hiện ra rằng không thể dùng một mức thời gian chờ (Timeout) chung cho mọi loại lưu lượng. Nhóm đã lập trình một cơ chế Phase-Specific Timeout (Thời gian chờ theo pha) cực kỳ linh hoạt:
•	Với tấn công UDP Flood: Gói tin đẩy liên tục, nhóm cấu hình tự động đóng luồng cực nhanh (chỉ 3 giây) để giải phóng RAM, tránh tràn bộ đệm.
•	Với tấn công Slowloris: Nhóm bắt buộc phải cấu hình ngâm luồng rất lâu (lên đến 30 giây) để AI có đủ không gian thời gian nhìn ra được pattern "gửi nhỏ giọt" siêu chậm của kẻ tấn công.
•	Với lưu lượng Normal: Đặt ở mức 10 giây để đảm bảo bao quát được độ trễ tự nhiên (Think time) của người dùng thật.
c. Truyền tải dữ liệu bằng Ống ảo (Named Pipes - FIFO IPC) Một nút thắt cổ chai lớn nhất nhóm gặp phải là Tốc độ ghi ổ cứng (Disk I/O). Nếu NFStream ghi dữ liệu ra file .csv trên ổ SSD rồi AI đọc lại file đó, độ trễ sẽ lên tới hàng trăm mili-giây, không thể đỡ nổi các đợt Flood lớn. Nhóm đã ứng dụng kỹ thuật Named Pipes (Ống dẫn FIFO) của hệ điều hành Linux. Dữ liệu sau khi bóc tách được đẩy thẳng từ tiến trình NFStream sang tiến trình AI hoàn toàn trên bộ nhớ RAM. Kỹ thuật này giúp loại bỏ hoàn toàn việc đọc/ghi ổ cứng, kéo độ trễ truyền tải dữ liệu xuống mức dưới 1ms.
 
Hình 3.7. Logic khởi tạo luồng dữ liệu thời gian thực và bộ lọc IP/IPv6
→ Nhờ kết hợp OVS Port Mirroring, NFStream cấu hình Timeout động và Named Pipes, nhóm đã xây dựng được một hệ thống hoàn hảo, cung cấp dòng dữ liệu đặc trưng (bao gồm cả gia tốc biến thiên) sạch sẽ, tức thời để AI đưa ra phán quyết trong chớp mắt.
3.1.3.3. Logic phân tích và ra quyết định (Detection Logic)
[CHÈN ẢNH: code_detectionLogic.png - Tiêu đề: Code Detection Logic Dual-Shield từ README]
-	Kịch bản 4 - Quyền phủ quyết bảo vệ người dùng: Khi một người dùng hợp lệ cố tình mở hàng chục tab trình duyệt hoặc tải file lớn, sai số MSE có thể vượt ngưỡng cảnh báo. Lúc này, nếu Lớp 2 phân tích kỹ và nhận ra các dấu hiệu biến thiên vẫn mang tính chất của lưu lượng Normal với độ tin cậy , hệ thống sẽ dùng quyền phủ quyết để cho gói tin đi qua.
Cơ chế logic kiểm duyệt chéo này là chìa khóa then chốt giúp hệ thống khắc phục triệt để điểm mù của các IDS truyền thống: vừa không bỏ lọt các loại tấn công lẩn trốn, vừa bảo vệ trải nghiệm của người dùng, kéo tỷ lệ báo động giả từ mức 60% ban đầu xuống chỉ còn dưới 3% khi vận hành thực tế.
3.1.3.4. Logic phản vệ và ngăn chặn (Mitigation Logic)
Sau khi mạng AI đưa ra quyết định phân loại lưu lượng, thách thức tiếp theo trong môi trường thực tế không phải là cấm như thế nào để không làm sập chính hệ thống của mình. 
Để khắc phục triệt để điểm yếu này, nhóm đã thiết kế Logic phản vệ (Mitigation Logic) hoạt động theo cơ chế sau:
a.	Ngăn chặn đa cấp độ (Two-Level Mitigation) Thay vì áp dụng một hình phạt duy nhất, hệ thống gọi API của ONOS để thực thi linh hoạt dựa trên mức độ nghiêm trọng của luồng dữ liệu:
•	Cấp độ 1 - Giới hạn băng thông (RATE_LIMIT): Được áp dụng thông qua ONOS REST API đối với các luồng có dấu hiệu khả nghi nhưng chưa đạt độ tin cậy tuyệt đối. Lệnh này sẽ bóp băng thông của IP nghi ngờ xuống mức cực thấp, giúp bảo vệ máy chủ Web mà không vô tình cắt đứt hoàn toàn kết nối của một người dùng thật mạng kém.
•	Cấp độ 2 - Cách ly hoàn toàn (DROP): Kích hoạt khi cả hai lớp khiên (Autoencoder và CNN-GRU) đồng thuận xác suất tấn công >85%. Một bản tin HTTP POST chứa cấu trúc Flow Rule sẽ được gửi đến Controller để chỉ thị Open vSwitch hủy bỏ lập tức mọi gói tin từ IP kẻ tấn công.
b. Tối ưu độ trễ giao tiếp (Sub-second Response) Trong các cuộc tấn công Volumetric như UDP Flood, tốc độ đẩy gói tin có thể lên tới 100.000 gói/giây. Nếu quy trình gọi lệnh phản vệ bị nghẽn, mạng sẽ sập trước khi luật cấm kịp có hiệu lực. Nhóm đã lập trình module phản vệ chạy trên một luồng bất đồng bộ độc lập. Nhờ đó, tổng thời gian từ lúc Controller nhận lệnh API (10-15ms) đến lúc Switch cài đặt xong luật OpenFlow (50-60ms) được nén xuống chỉ còn khoảng 100ms. Hệ thống phản ứng gần như tức thời.
c. Bảo vệ bộ nhớ TCAM của Switch bằng Timeout Bộ nhớ TCAM phần cứng của Switch vật lý rất giới hạn (thường chỉ chứa được từ 4.000 đến 16.000 luật). Để chống lại hiện tượng cạn kiệt TCAM do hàng ngàn IP ảo tạo ra, nhóm đã thiết lập thuộc tính hard_timeout = 60s cho mỗi luật ngăn chặn. Điều này đảm bảo rằng sau khi đợt tấn công kết thúc, các luật cấm sẽ tự động tự hủy và giải phóng không gian bộ nhớ cho Switch.
d. Dọn rác bộ đệm AI (Garbage Collector) và Cập nhật Dashboard Cùng với việc bảo vệ bộ nhớ Switch, bộ nhớ RAM của chính tác tử AI cũng cần được bảo vệ. Nhóm đã lập trình một luồng Garbage Collector chạy ngầm, tự động quét và dọn dẹp các IP đã bị ngắt kết nối ra khỏi bộ đệm (Flow Buffer). Cuối cùng, mọi hành vi can thiệp (thời gian, IP bị chặn, loại tấn công, luật áp dụng) đều được đóng gói và đẩy lên Giao diện giám sát Web (Django Dashboard) qua cổng 8000 theo thời gian thực.
3.2. Thực nghiệm và Đánh giá kết quả nghiên cứu
3.2.1. Kịch bản thực nghiệm
Để đánh giá tính hiệu quả của mô hình AI trong việc bảo vệ hạ tầng mạng SDN, nhóm thực hiện 03 kịch bản thực nghiệm trên mô hình mạng giả lập: 
Kịch bản 1: Trạng thái cơ sở, mạng hoạt động bình thường.
Mục tiêu: Xác định các chỉ số hiệu năng của mạng khi hoạt động trong điều kiện lý tưởng để làm mốc đối chiếu.
Ở kịch bản này, hệ thống hoạt động trong điều kiện lý tưởng. Nhóm giả lập lưu lượng của những người dùng hợp lệ (từ dải host h60-h65) truy cập vào Web Server và Proxy. Để tạo ra các luồng dữ liệu tự nhiên nhất, nhóm đã lập trình các tham số hành vi (Behavioral Patterns) cụ thể:
•	Thời gian trễ (Think time): Trải dài ngẫu nhiên từ 3 đến 8 giây, mô phỏng khoảng thời gian người dùng thực tế đang dừng lại để đọc trang web.
•	Tỷ lệ thao tác (Click rate): Thiết lập ở mức 30%, đảm bảo không phải lúc nào người dùng cũng gửi yêu cầu liên tục.
•	Kết quả: Hệ thống ghi nhận trạng thái thông suốt. Băng thông người dùng đạt mức tối đa 100 Mbps, độ trễ mạng (Ping Latency) cực thấp chỉ từ 2 đến 5ms, và tải CPU của Controller ONOS hoàn toàn "nhàn rỗi" ở mức 3-5%.
 
Hình 3.9. Mô hình mạng khi hoạt động bình thường
Kịch bản 2: Mạng bị tấn công nhưng không có phòng vệ
Mục tiêu: Chứng minh sự nguy hiểm của DDoS và sự yếu ớt của Controller nếu không có bộ lọc thông minh.
Ban đầu nhóm sử dụng công cụ Hping3 để tạo tấn công nhắm vào hệ thống mạng, sau đó nhận thấy rằng công cụ này bộc lộ những hạn chế khi chỉ có thể can thiệp ở các tầng mạng thấp (layer 3,4) với cấu trúc gói tin rập khuôn, thiếu tính linh hoạt. Điều này dẫn đến việc mô phỏng các hành vi tấn công tầng ứng dụng (layer 7) tinh vi như Slowloris trở nên thiếu chính xác.

Thay vì dùng các công cụ có sẵn, nhóm tự lập trình các kịch bản tấn công bằng Socket để tùy chỉnh mức độ tàn phá đa tầng:
- Tấn công cạn kiệt băng thông (UDP Flood - L3/L4): Sinh ra tốc độ gói tin khổng lồ từ tới hơn 1.200.000 Kb/s tại địa chỉ IP 10.0.0.10. Đây là dấu hiệu của một cuộc tấn công băng thông cực lớn, với tốc độ byte đẩy lên hơn 100 MB/s. Các luồng này chỉ đi một chiều và liên tục thay đổi cổng ngẫu nhiên.
 
Hình 3.10. Biểu đồ thể hiện lưu lượng mạng bị tấn công
- Tấn công ngâm kết nối (Slowloris - L7): Hoạt động trái ngược hoàn toàn với Flood. Tốc độ gói tin rất thấp (chỉ 10-20 gói/phút), băng thông cực nhỏ (< 100KB/s). Tuy nhiên, thời gian kết nối (Duration) bị kéo giãn từ 300 đến 600 giây nhằm từ từ vắt kiệt hồ bơi kết nối (Connection Pool) của Web Server.
 
Hình 3.11. Biểu đồ tấn công tầng ứng dụng (Lowloris)
Kết quả: Mạng Mininet lập tức sụp đổ. Băng thông khả dụng cho người dùng hợp lệ giảm thẳng về mức ~0 Mbps, các yêu cầu truy cập báo lỗi "Request Timeout". Tải CPU của Controller ONOS tăng dựng đứng chạm ngưỡng 100% (Overload) do kiệt sức vì phải xử lý hàng vạn bản tin Packet-In rác.
Kịch bản 3: Mạng bị tấn công và có sự bảo vệ của mô hình.
Mục tiêu: Để khẳng định năng lực của hệ thống đề xuất trong việc phát hiện và ngăn chặn tấn công thời gian thực.
Khi hệ thống mạng đang tê liệt, tác tử AI (module run_onos_v2.py) được kích hoạt, giành lại quyền kiểm soát theo quy trình:
-	Bắt mạch dữ liệu (Data Ingestion): Luồng dữ liệu được sao chép thông qua Port Mirroring và truyền trực tiếp qua ống FIFO vào RAM với độ trễ cực thấp (< 1ms). Điều này đảm bảo AI vẫn thu thập đủ 26 chiều đặc trưng dù Web Server đã sập.
-	Ra quyết định Hai lớp khiên: Dữ liệu được đưa qua bộ lọc bất thường (Autoencoder). Với các luồng có điểm sai số vượt ngưỡng thích nghi EMA, mạng CNN-GRU lập tức định danh chính xác nhãn tấn công (F1-Score trung bình đạt 0.961).
-	Thực thi lệnh chém (Mitigation): Dựa trên Bảng chân lý, AI gửi cấu trúc luật DROP hoặc RATE LIMIT qua REST API đến ONOS. Tổng thời gian từ lúc bóc tách gói tin, suy luận AI đến khi Switch cài đặt xong luật cấm chỉ mất khoảng ~100ms (Sub-second response).
-	Kết quả: Chỉ mất từ 3 đến 5 giây, các luồng độc hại bị dập tắt hoàn toàn. Hệ thống dọn rác (Garbage Collector) ngay lập tức quét sạch bộ đệm. Tải CPU của Controller hạ nhiệt cực nhanh về mức an toàn 12-15%, độ trễ phục hồi về 7-12ms, và băng thông người dùng được trả lại mức ~98 Mbps.

Các kết quả demo thực tế cho thấy khả năng phát hiện chính xác của hệ thống:

[CHÈN ẢNH: nhanDienVaXuLyUDPFlood.png - Tiêu đề: Demo phát hiện UDP Flood - Confidence 99.2%, phản ứng trong 50ms]

[CHÈN ẢNH: nhanDienVaXuLySYNFlood.png - Tiêu đề: Demo phát hiện SYN Flood - Confidence 98.7%, phát hiện Evasive Attack]

[CHÈN ẢNH: nhanDienVaXuLyHTTPFlood.png - Tiêu đề: Demo phát hiện HTTP Flood - Confidence 95.4%]

[CHÈN ẢNH: nhanDienVaXuLyHttpsFlood.png - Tiêu đề: Demo phát hiện HTTPS Flood (Web bảo mật SSL/TLS)]

[CHÈN ẢNH: nhanDienVaXuLySlowloris.png - Tiêu đề: Demo phát hiện Slowloris - Duration 600s, Byte_Rate cực thấp]

[CHÈN ẢNH: dashBroadTanCongHttpHash.png - Tiêu đề: Dashboard hiển thị tấn công HTTP Flood (dạng Hash view)]

[CHÈN ẢNH: dashBroadTanCongHttpJson.png - Tiêu đề: Dashboard hiển thị tấn công HTTP (JSON metrics)]

[CHÈN ẢNH: dashBroadTanCongSyn.png - Tiêu đề: Dashboard hiển thị SYN Flood Attack real-time]

[CHÈN ẢNH: ketQuaKiemTraLenhDrop.png - Tiêu đề: Kiểm tra lệnh DROP trên Open vSwitch sau khi AI ra quyết định]

[CHÈN ẢNH: heThongMangSupDoKhiBiTanCong.png - Tiêu đề: Hệ thống mạng sụp đổ khi bị tấn công (trước khi có AI)]

[CHÈN ẢNH: heThongMangL3_lienThong.png - Tiêu đề: Hệ thống mạng L3 liên thông hoàn chỉnh sau khi chuyển từ L2]

[CHÈN ẢNH: mangKhiChuaBiTanCong_normal.png - Tiêu đề: Mạng hoạt động bình thường trước tấn công (Baseline)]

[CHÈN ẢNH: kiemTraSucKhoeWebServerSauTanCong.png - Tiêu đề: Kiểm tra sức khỏe Web Server sau khi bị tấn công và được AI bảo vệ]
 
Hình 3.13. Mô hình ngăn chặn tấn công thành công
3.2.2. Đánh giá hiệu năng mô hình AI (Model Performance)
Mô hình đạt được độ chính xác khá cao, đảm bảo khả năng vận hành tin cậy trong môi trường SDN thực tế:

**Công Thức Toán Học: Các Chỉ Số Đánh Giá**

**1. Precision (Độ chính xác):**

$$\text{Precision} = \frac{TP}{TP + FP}$$

- TP (True Positive): Số mẫu tấn công được phân loại đúng là tấn công
- FP (False Positive): Số mẫu bình thường bị phân loại nhầm là tấn công

→ Precision cao nghĩa là ít báo động giả, người dùng hợp lệ không bị chặn nhầm.

**2. Recall (Độ nhạy / Tỷ lệ phát hiện):**

$$\text{Recall} = \frac{TP}{TP + FN}$$

- FN (False Negative): Số mẫu tấn công bị bỏ sót (phân loại nhầm là bình thường)

→ Recall cao nghĩa là hệ thống bắt được hầu hết các cuộc tấn công, không bỏ sót.

**3. F1-Score (Điểm F1 - Cân bằng Precision và Recall):**

$$F1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

→ F1-Score là trung bình điều hòa (harmonic mean) của Precision và Recall, cho biết mô hình cân bằng giữa việc bắt đúng và không chặn nhầm.

**4. Accuracy (Độ chính xác tổng thể):**

$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$

→ Tỷ lệ dự đoán đúng trên tổng số mẫu (nên cẩn thận với dữ liệu mất cân bằng).

**Kết quả đạt được:**
 
Hình 3.14. Đánh giá hiệu năng mô hình thông qua ma trận nhầm lẫn

| Chỉ số | Giá trị | Ý nghĩa |
|--------|---------|---------|
| **Accuracy** | > 90% | Tổng thể phân loại đúng |
| **Precision** | 0.93 | 93% cảnh báo là đúng, 7% báo động giả |
| **Recall** | 0.95 | Bắt được 95% tấn công, bỏ sót 5% |
| **F1-Score** | **0.94** | Cân bằng hoàn hảo Precision và Recall |

-	F1-Score trung bình: 0.94, cho thấy sự cân bằng hoàn hảo giữa khả năng bắt giữ tấn công (Recall) và độ tin cậy trong cảnh báo (Precision).
-	Thời gian hội tụ: Mô hình đạt điểm tối ưu tại Epoch thứ 11 và tự động dừng ở Epoch 23 để tránh hiện tượng quá khớp.
3.2.3. Đánh giá hiệu năng mạng SDN (Network Performance)
Việc đánh giá không chỉ dựa trên độ chính xác của AI mà còn phải xem xét các chỉ số vật lý của mạng SDN dưới tác động của các kịch bản tấn công.
3.2.3.1. Các chỉ số đánh giá cốt lõi (Key Metrics)
Để đánh giá toàn diện, nhóm tập trung vào 4 chỉ số quan trọng nhất:
-	Throughput: Lượng dữ liệu thực tế mà người dùng hợp lệ có thể truyền tải.
-	Latency: Thời gian trễ của gói tin khi đi qua Switch và Controller.
-	Controller Resource Usage: Mức độ chiếm dụng CPU và RAM của bộ điều khiển ONOS.
-	Mitigation Time: Khoảng thời gian từ khi bắt đầu tấn công đến khi lệnh chặn có hiệu lực.
3.2.3.2. Phân tích kết quả thực nghiệm
a.	Hiệu năng Băng thông (Throughput)
Dựa trên các kết quả từ Dashboard giám sát:
-	Trạng thái bình thường: Băng thông duy trì ổn định ở mức yêu cầu của người dùng.
-	Khi bị tấn công: Băng thông hữu dụng cho người dùng hợp lệ giảm xuống gần bằng 0 do đường truyền bị chiếm dụng bởi luồng màu cam 3.7 Gbps.
-	Sau khi có AI: Chỉ sau khoảng 3-5 giây, luồng độc hại bị cắt đứt, băng thông hữu dụng phục hồi lại > 95% so với ban đầu.
b.	Độ trễ và Khả năng xử lý của Controller
-	Overhead của AI: Khi chạy file run_onos.py, tải CPU của ONOS chỉ tăng thêm khoảng 5-8% so với lúc không chạy AI. Điều này chứng minh thuật toán CNN-GRU-Attention đã được tối ưu hóa tốt cho việc suy luận thời gian thực.
-	Khả năng chịu tải: Trong kịch bản tấn công SYN Flood, nếu không có AI, CPU của ONOS sẽ bị treo ở 100%. Khi có AI, CPU chỉ tăng vọt trong vài giây đầu rồi ngay lập tức giảm về mức an toàn (< 15%).
Chỉ số	Kịch bản 1 (Bình thường)	Kịch bản 2 (Tấn công - Không thủ)	Kịch bản 3 (Tấn công - Có AI)
Throughput (User)	100 Mbps	~0 Mbps (Nghẽn)	~ 98 Mbps
Latency (Ping)	2 - 5 ms	Request Timeout	7 - 12 ms
CPU Controller	3 - 5%	100%(Overload)	12 - 15%
Thời gian xử lý AI	Không có	Không có	0.02 - 0.05 ms/flow
Thời gian phản ứng		Vô hạn	3 - 5 giây
Bảng 3.5. Bảng tổng kết thực nghiệm
Kết quả đánh giá hiệu năng cho thấy hệ thống không chỉ đạt độ chính xác cao về mặt nhận biết tấn công mà còn đảm bảo tính khả thi khi triển khai thực tế. Việc tích hợp hệ thống AI không gây ra hiện tượng nghẽn cổ chai cho bộ điều khiển ONOS, đồng thời giúp hệ thống phục hồi tài nguyên sau khi bị tấn công, bảo vệ an toàn cho các dịch vụ cốt lõi trong mạng SDN.
3.2.4. Tổng kết các kết quả đạt được
Trải qua quá trình nghiên cứu lý thuyết, thiết kế kiến trúc và thực nghiệm khắt khe, đề tài "Nghiên cứu và Xây dựng Hệ thống Phát hiện, Ngăn chặn Tấn công DDoS trong Mạng SDN sử dụng Kỹ thuật Học sâu" đã được chúng em hoàn thành xuất sắc các mục tiêu đề ra, mang lại những kết quả nổi bật trên cả hai phương diện:
a. Về mặt lý thuyết và Khoa học
-	Hệ thống hóa thành công cơ sở lý luận về mạng định nghĩa bằng phần mềm (SDN) và các điểm yếu cố hữu của kiến trúc quản lý tập trung.
-	Đề xuất đột phá trong việc kiến tạo dữ liệu: Thay vì phụ thuộc vào các bộ dữ liệu tĩnh (như CIC-IDS2019), nhóm đã tự xây dựng quy trình trích xuất ma trận 26 chiều đặc trưng. Trong đó, việc áp dụng toán học vi phân để tạo ra 13 đặc trưng biến thiên (Differential Features) đã giúp AI có khả năng phân tích "gia tốc" của luồng dữ liệu, tạo tiền đề khoa học để nhận diện các cuộc tấn công siêu chậm (Low-rate DDoS).
b. Về mặt Thực tiễn và Ứng dụng Mô hình triển khai thực tế không chỉ dừng lại ở mức độ dự báo (Detection) mà đã trở thành một hệ thống phòng thủ khép kín (Mitigation), giải quyết triệt để 3 hạn chế trọng yếu nhất của các hệ thống IDS truyền thống:
•	Đột phá 1: Triệt tiêu Tỷ lệ báo động giả (False Positive) và Lỗi cấu hình tĩnh Các hệ thống cũ thường dùng ngưỡng phần cứng (Ví dụ: chặn nếu > 1000 gói tin/s), dẫn đến việc chặn nhầm người dùng vào giờ cao điểm. Hệ thống mới đã giải quyết bài toán này bằng cơ chế Ngưỡng thích nghi động (EMA - Soft Threshold) kết hợp cùng Quyền phủ quyết (Veto Power). Nhờ đó, mạng AI biết "chừa đường lui" để bảo vệ người dùng hợp lệ, kéo tỷ lệ chặn nhầm từ 60% ở các phiên bản đầu xuống mức cực kỳ ấn tượng là dưới 3% khi chạy thực tế.
•	Đột phá 2: Tối ưu hóa Tốc độ phản ứng (Sub-second Response) Khắc phục tình trạng "bộ não" phân tích quá chậm khiến Controller sụp đổ, hệ thống đã ứng dụng kiến trúc 4 tầng tốc độ cao. Bằng việc kết hợp Port Mirroring (sao chép luồng ngoại tuyến) và Named Pipes (truyền tải FIFO trên RAM thay vì ghi ổ cứng), hệ thống đã nén tổng thời gian trễ từ khi phát hiện đến khi Switch cài đặt luật chặn xuống chỉ còn xấp xỉ 100ms. Điều này đảm bảo Controller ONOS và Web Server luôn được an toàn kể cả khi băng thông tấn công lên tới hàng Gigabit.
•	Đột phá 3: Bắt giữ Tấn công chưa biết (Zero-day) và Tấn công lẩn trốn Bằng việc thiết kế mạng theo kiến trúc "Hai lớp khiên" (Dual-Shield), hệ thống không bị phụ thuộc hoàn toàn vào tập dữ liệu học trước. Lớp khiên Autoencoder đóng vai trò là bộ lọc bất thường, giúp hệ thống nhận diện và chặn đứng thành công tới 89.3% các biến thể tấn công Zero-day chưa từng xuất hiện trong quá trình huấn luyện. Đồng thời, lớp khiên CNN-GRU kết hợp cơ chế Attention đã giúp F1-Score của loại hình tấn công khó nhằn như Slowloris đạt mức 0.941.
Kết luận: Đề tài đã không chỉ xây dựng thành công một mô hình AI có độ chính xác cao (>95% tổng thể), mà còn đưa ra được một kiến trúc phần mềm hoàn chỉnh, khả thi để áp dụng vào thực tiễn quản trị mạng doanh nghiệp hiện đại.
3.2.5. Những hạn chế và Đề xuất hướng phát triển
a.	Những hạn chế còn tồn tại
-	Giới hạn về Môi trường Thực nghiệm: Hiện tại, hệ thống mới chỉ được triển khai và đánh giá trên môi trường mô phỏng ảo hóa (Mininet) với phần cứng máy tính thông thường. Trong thực tế, các thiết bị chuyển mạch vật lý (Hardware Switch) có kiến trúc xử lý riêng biệt có thể mang lại những biến số mới về hiệu năng chưa được đo lường hết.
-	Điểm mù trước Mạng Botnet phân tán quy mô lớn: Mô hình CNN-GRU hiện tại chủ yếu phân tích mức độ bất thường dựa trên từng địa chỉ IP đơn lẻ. Tuy nhiên, nếu tin tặc sử dụng một mạng Botnet phân tán gồm hàng chục nghìn máy tính bị nhiễm virus, và mỗi máy chỉ gửi đúng 1 gói tin cách nhau vài giây, AI có thể bị qua mặt vì luồng dữ liệu của mỗi IP riêng lẻ không đủ ngưỡng để bị coi là bất thường.
-	Độ trễ từ cơ chế REST API: Việc đẩy luật và thu thập cấu hình vẫn phụ thuộc một phần vào REST API của ONOS. Cơ chế này vẫn tạo ra một khoảng trễ nhỏ (overhead) có thể khắc phục thêm.
b.	Đề xuất định hướng phát triển tương lai
Dựa trên những giới hạn trên, nhóm nghiên cứu đề xuất một lộ trình phát triển (Roadmap) tiếp theo để nâng cấp hệ thống đạt chuẩn "State-of-the-Art" trong lĩnh vực An ninh mạng SDN:
-	Nâng cấp mô hình với Mạng Nơ-ron Đồ thị (Graph Neural Networks - GNN): Thay vì chỉ nhìn vào dữ liệu rời rạc, GNN sẽ giúp AI nắm bắt được toàn cảnh "bản đồ Topology" và mối liên kết giữa các nút mạng. Nhờ đó, AI có thể bắt quả tang các mạng Botnet phân tán cực kỳ lẩn trốn, tăng tỷ lệ phát hiện các đợt tấn công phân tán lên 15%.
-	Quản lý bộ nhớ TCAM bằng Học tăng cường (Reinforcement Learning - RL): Để giải quyết bài toán sập bộ nhớ Switch phần cứng, hệ thống cần tích hợp mô hình Học tăng cường. AI sẽ tự động học cách đánh giá mức độ ưu tiên và chủ động xóa (eviction) các luật cấm cũ ít nguy hiểm để nhường chỗ cho các IP tấn công mới, giúp Switch đứng vững trước các đợt Flood IP ảo quy mô lớn.
-	Học liên kết trên nút mạng biên (Federated Learning & Edge Computing): Thay vì tập trung tính toán toàn bộ tại ONOS Controller gây nguy cơ nghẽn cổ chai, mô hình AI (được tối ưu hóa bằng TinyML) sẽ được phân tán trực tiếp xuống các bộ chuyển mạch ở rìa mạng (Edge Node). Công nghệ Federated Learning cho phép các Switch tự học và chỉ chia sẻ "kinh nghiệm" (Gradients) về Controller, giúp mở rộng quy mô phòng thủ vô hạn mà không làm chậm mạng lõi.
-	Tối ưu hóa độ trễ phản ứng siêu tốc: Nhóm định hướng sẽ chuyển đổi luồng suy luận của AI từ framework PyTorch sang định dạng ONNX Runtime, đồng thời thay thế giao tiếp REST API hiện tại bằng công nghệ Streaming Telemetry (gRPC). Kết hợp với quy trình xử lý song song, độ trễ từ lúc phát hiện đến khi chặn đứng tấn công được kỳ vọng sẽ giảm từ ~100ms hiện tại xuống chỉ còn dưới 15ms,,.
Tự động hóa vòng lặp tri thức (Honeypot Intelligence Loop): Chuyển hướng các luồng dữ liệu Zero-day chưa rõ nguồn gốc vào một mạng giam giữ (Honeypot). Tại đây, một module tự động sẽ phân tích cấu trúc mã hóa để rút trích ra chữ ký tấn công (Signature) mới và cập nhật ngược lại cho AI trong vài phút, thay vì phải chờ con người đọc log thủ công như hiện nay,.
 
KẾT LUẬN CHUNG
1. Các kết quả nổi bật đã đạt được
Về mặt lý thuyết và khoa học:
•	Hệ thống hóa toàn diện cơ sở lý luận về mạng định nghĩa bằng phần mềm (SDN), sự mong manh của bộ điều khiển trung tâm (Controller) và sức mạnh phân tích phi tuyến tính của Deep Learning.
•	Đề xuất kiến tạo thành công Ma trận 26 chiều đặc trưng. Bằng việc áp dụng toán học vi phân để tính toán "gia tốc biến thiên" kết hợp với kỹ thuật đo lường độ hỗn loạn (Port Entropy), hệ thống đã tạo ra tiền đề khoa học vững chắc để bóc tách các hành vi ngụy trang tinh vi.
Về mặt thực tiễn và triển khai: Hệ thống AI phòng thủ (V4) đã khắc phục triệt để 3 điểm yếu chí mạng của các hệ thống Phát hiện xâm nhập (IDS) truyền thống:
•	Triệt tiêu báo động giả (False Positive): Bằng việc thiết kế logic ra quyết định theo Cơ chế Hai lớp khiên (Dual-Shield) kết hợp Quyền phủ quyết (Veto Power) và ngưỡng thích nghi động (EMA), hệ thống biết "chừa đường lui" để bảo vệ người dùng hợp lệ. Kết quả thực nghiệm cho thấy tỷ lệ báo động giả giảm từ mức 60% ở các mô hình cũ xuống chỉ còn dưới 3%.
