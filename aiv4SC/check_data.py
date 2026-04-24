# Tên file: check_data.py (Upgraded v2.0)
import pandas as pd
import numpy as np
import os
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

warnings.filterwarnings('ignore')
console = Console()

# ĐƯỜNG DẪN TỚI FILE DATASET V6 (520k mẫu)
DATASET_PATH = "/home/tgf/Documents/DoAn_SDN/thuThapData/master_dataset_v7.csv" 

LABELS = {
    0: "Normal (Bình thường)",
    1: "UDP Flood",
    2: "SYN Flood",
    3: "HTTP Flood",
    4: "Slowloris"
}

FEATURE_NAMES = [
    "Src_Port_Entropy", "Dst_Port_Entropy", "Protocol", "Duration_Sec", "Src_Bytes", "Dst_Bytes",
    "Src_Packets", "Dst_Packets", "Conn_State", "L7_App_Protocol", "Packet_Rate", "Byte_Rate", "Anomaly_Score"
]

# Định nghĩa nhóm đặc trưng để phân tích chuyên sâu
FEATURE_GROUPS = {
    "Port Entropy": ["Src_Port_Entropy", "Dst_Port_Entropy"],
    "Protocol & State": ["Protocol", "Conn_State", "L7_App_Protocol"],
    "Traffic Volume": ["Src_Bytes", "Dst_Bytes", "Src_Packets", "Dst_Packets"],
    "Rate Metrics": ["Packet_Rate", "Byte_Rate"],
    "Temporal": ["Duration_Sec"],
    "Anomaly": ["Anomaly_Score"]
}

# ===== UTILITY FUNCTIONS (NEW) =====

def compute_class_weights(df):
    """Tính toán class weights cho FocalLoss (cân bằng imbalance)"""
    label_col = df.columns[-1]
    counts = df[label_col].value_counts().sort_index()
    total = len(df)
    weights = {}
    for label, count in counts.items():
        weights[label] = total / (len(counts) * count)
    return weights

def check_feature_distribution(df):
    """Kiểm tra phân bố các đặc trưng (skewness, kurtosis)"""
    feature_stats = {}
    for col in df.columns[:-1]:
        feature_stats[col] = {
            "mean": df[col].mean(),
            "std": df[col].std(),
            "skewness": df[col].skew(),
            "kurtosis": df[col].kurtosis(),
            "median": df[col].median()
        }
    return feature_stats

def detect_outliers(df, threshold=3):
    """Phát hiện outliers sử dụng Z-score"""
    from scipy import stats
    outlier_counts = {}
    for col in df.columns[:-1]:
        z_scores = np.abs(stats.zscore(df[col]))
        outliers = (z_scores > threshold).sum()
        outlier_counts[col] = outliers
    return outlier_counts

def check_class_imbalance(df):
    """Đánh giá độ mất cân bằng (imbalance ratio)"""
    label_col = df.columns[-1]
    counts = df[label_col].value_counts().sort_index()
    max_count = counts.max()
    min_count = counts.min()
    imbalance_ratio = max_count / min_count
    return imbalance_ratio, counts

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def analyze_all_features_by_label(df):
    """
    PHÂN TÍCH CHI TIẾT TẤT CẢ ĐẶC TRƯNG THEO TỪNG NHÃN
    Trả về dict: {feature_name: {label_id: stats_dict}}
    """
    label_col = df.columns[-1]
    feature_cols = df.columns[:-1]  # Tất cả cột trừ nhãn
    
    analysis = {}
    
    for feat_idx, feat_name in enumerate(feature_cols):
        # Sử dụng tên đặc trưng mới nếu có
        display_name = FEATURE_NAMES[feat_idx] if feat_idx < len(FEATURE_NAMES) else feat_name
        analysis[display_name] = {}
        
        for label_id in sorted(df[label_col].unique()):
            label_name = LABELS.get(label_id, f"Unknown ({label_id})")
            df_label = df[df[label_col] == label_id]
            values = df_label[feat_name]
            
            stats = {
                "count": len(values),
                "mean": values.mean(),
                "std": values.std(),
                "min": values.min(),
                "max": values.max(),
                "median": values.median(),
                "q25": values.quantile(0.25),
                "q75": values.quantile(0.75),
                "skew": values.skew(),
                "unique": values.nunique()
            }
            analysis[display_name][label_id] = stats
    
    return analysis

def print_feature_analysis_table(analysis, feature_name, console):
    """In bảng phân tích chi tiết cho một đặc trưng"""
    from rich.table import Table
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Nhãn", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Mean", justify="right")
    table.add_column("Std", justify="right")
    table.add_column("Min", justify="right")
    table.add_column("Max", justify="right")
    table.add_column("Median", justify="right")
    table.add_column("Skew", justify="right")
    table.add_column("Đánh giá")
    
    for label_id in sorted(analysis[feature_name].keys()):
        stats = analysis[feature_name][label_id]
        label_name = LABELS.get(label_id, f"Label {label_id}").split()[0]  # Lấy tên ngắn
        
        # Đánh giá phân bố
        skew = stats['skew']
        if abs(skew) > 3:
            eval_text = "[red]Rất lệch[/red]"
        elif abs(skew) > 1.5:
            eval_text = "[yellow]Lệch[/yellow]"
        else:
            eval_text = "[green]Chuẩn[/green]"
        
        table.add_row(
            label_name,
            f"{stats['count']:,}",
            f"{stats['mean']:.3f}",
            f"{stats['std']:.3f}",
            f"{stats['min']:.3f}",
            f"{stats['max']:.3f}",
            f"{stats['median']:.3f}",
            f"{skew:.2f}",
            eval_text
        )
    
    console.print(table)

def check_port_entropy(df):
    """Tính toán Entropy của Port cho từng nhãn - ĐÃ CẬP NHẬT CHO ENTROPY FEATURES"""
    from scipy.stats import entropy
    
    label_col = df.columns[-1]
    results = []
    
    # Lấy tên cột entropy (giờ là giá trị entropy thay vì port numbers)
    src_entropy_col = df.columns[0]  # Src_Port_Entropy
    dst_entropy_col = df.columns[1]  # Dst_Port_Entropy
    
    for label_id in sorted(df[label_col].unique()):
        label_name = LABELS.get(label_id, f"Unknown ({label_id})")
        df_label = df[df[label_col] == label_id]
        
        # Entropy đã được tính sẵn trong features
        src_entropy_mean = df_label[src_entropy_col].mean()
        dst_entropy_mean = df_label[dst_entropy_col].mean()
        
        # Số lượng giá trị entropy duy nhất
        unique_src = df_label[src_entropy_col].nunique()
        unique_dst = df_label[dst_entropy_col].nunique()
        
        results.append({
            "Label": label_name,
            "Src_Entropy": src_entropy_mean,
            "Dst_Entropy": dst_entropy_mean,
            "Unique_Src": unique_src,
            "Unique_Dst": unique_dst
        })
    return results

def run_inspection():
    clear_screen()
    console.print(Panel("[bold cyan]🚀 HỆ THỐNG KIỂM ĐỊNH DATASET (BIG DATA) CHO CNN-GRU 🚀[/bold cyan]", expand=False))

    if not os.path.exists(DATASET_PATH):
        console.print(f"[bold red]❌ Không tìm thấy file {DATASET_PATH}. Vui lòng kiểm tra lại đường dẫn![/bold red]")
        return

    # 1. ĐỌC DỮ LIỆU VÀ KIỂM TRA BỘ NHỚ (RAM)
    console.print("[yellow]⏳ Đang tải dữ liệu và phân tích khối lượng lớn (Vui lòng chờ)...[/yellow]")
    df = pd.read_csv(DATASET_PATH)
    total_rows = len(df)
    total_cols = len(df.columns)
    mem_usage = df.memory_usage(deep=True).sum() / (1024 ** 2) # Đổi sang MB
    
    console.print(f"\n[bold green]✅ Đã nạp thành công: {total_rows:,} mẫu | {total_cols} cột[/bold green]")
    console.print(f"[*] Dung lượng file trên RAM: [cyan]{mem_usage:.2f} MB[/cyan]")

    # 2. KIỂM TRA KIỂU DỮ LIỆU (Yêu cầu bắt buộc của AI: Phải là số)
    console.print("\n[bold cyan]1. KIỂM TRA KIỂU DỮ LIỆU (Data Types)[/bold cyan]")
    non_numeric_cols = df.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric_cols:
        console.print(f"[bold red]❌ LỖI CHÍ MẠNG: PyTorch không thể đọc chuỗi (String). Phát hiện các cột chứa chữ:[/bold red] {non_numeric_cols}")
    else:
        console.print("[green]✅ 100% dữ liệu là dạng số (Numeric). Sẵn sàng đưa vào Tensor.[/green]")

    # 3. KIỂM TRA TÍNH TOÀN VẸN (NaN / Infinity)
    console.print("\n[bold cyan]2. KIỂM TRA TÍNH TOÀN VẸN (NaN / Infinity)[/bold cyan]")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    null_counts = df.isnull().sum()
    total_nulls = null_counts.sum()
    
    if total_nulls > 0:
        console.print(f"[bold red]⚠️ CẢNH BÁO: Phát hiện {total_nulls:,} giá trị NaN/Infinity![/bold red]")
        console.print("[dim]-> Giải pháp: Khuyên dùng df.dropna() trước khi đưa vào hàm DataLoader của PyTorch.[/dim]")
    else:
        console.print("[green]✅ Dữ liệu sạch 100%. Không có lỗi Infinity làm Crash Loss Function.[/green]")

    # 4. ĐÁNH GIÁ BIÊN ĐỘ ĐẶC TRƯNG (QUAN TRỌNG CHO CNN-GRU)
    console.print("\n[bold cyan]3. ĐÁNH GIÁ BIÊN ĐỘ ĐẶC TRƯNG (Feature Scale Check)[/bold cyan]")
    table_scale = Table(show_header=True, header_style="bold yellow")
    table_scale.add_column("Đặc trưng (Feature)")
    table_scale.add_column("Min")
    table_scale.add_column("Max")
    table_scale.add_column("Đánh giá Scale")
    
    needs_scaler = False
    for i, col in enumerate(df.columns[:-1]): # Trừ cột nhãn
        f_min = df[col].min()
        f_max = df[col].max()
        f_name = FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else col
        
        status = "[green]Bình thường[/green]"
        if f_max - f_min > 10000:
            status = "[bold red]Biến thiên cực lớn[/bold red]"
            needs_scaler = True
            
        table_scale.add_row(f_name, f"{f_min:,.4f}", f"{f_max:,.4f}", status)
    
    console.print(table_scale)
    if needs_scaler:
        console.print("[bold yellow]💡 KẾT LUẬN SCALE:[/bold yellow] Các tính năng có biên độ lệch nhau quá lớn (Vài triệu vs số thập phân).")
        console.print("[bold yellow]BẮT BUỘC:[/bold yellow] Phải sử dụng [cyan]StandardScaler[/cyan] hoặc [cyan]MinMaxScaler[/cyan] trong file train_colab.py trước khi đưa vào CNN.")
    else:
        console.print("[green]✅ Dữ liệu có biên độ đồng đều.[/green]")

    # 5. KIỂM TRA TRÙNG LẶP (ĐÃ NỚI LỎNG CHO DDOS)
    console.print("\n[bold cyan]4. KIỂM TRA ĐỘ TRÙNG LẶP (Duplication Check)[/bold cyan]")
    duplicates = df.duplicated().sum()
    dup_percent = (duplicates / total_rows) * 100
    
    console.print(f"[*] Có {duplicates:,} dòng trùng lặp ({dup_percent:.1f}%).")
    if dup_percent > 90.0:
        console.print("[bold red]⚠️ CẢNH BÁO: Trùng lặp > 90%. Có thể mạng đang bị kẹt hoặc bắt vòng lặp![/bold red]")
    else:
        console.print("[green]✅ Tỷ lệ trùng lặp trong ngưỡng an toàn của mạng SDN. (Tấn công Flood luôn sinh ra các gói tin giống hệt nhau).[/green]")

    # 6. KIỂM TRA CÂN BẰNG LỚP
    console.print("\n[bold cyan]5. ĐÁNH GIÁ CÂN BẰNG LỚP (Class Distribution)[/bold cyan]")
    imbalance_ratio, label_counts = check_class_imbalance(df)
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Nhãn")
    table.add_column("Loại Tấn Công")
    table.add_column("Số lượng")
    table.add_column("Tỷ lệ")
    
    for label_id in sorted(label_counts.index):
        count = label_counts[label_id]
        name = LABELS.get(label_id, "Unknown")
        percent = (count / total_rows) * 100
        table.add_row(str(label_id), name, f"{count:,}", f"{percent:.1f}%")
        
    console.print(table)
    console.print(f"[*] Imbalance Ratio (max/min): {imbalance_ratio:.2f}x")
    if imbalance_ratio > 5:
        console.print("[bold yellow]💡 LƯỚI CẢNH BÁO: Dữ liệu mất cân bằng >5x. Sẽ dùng FocalLoss + class_weights trong training.[/bold yellow]")
    
    # 6b. TÍNH CLASS WEIGHTS CHO FOCALLOSS (NEW)
    console.print("\n[bold cyan]5b. CLASS WEIGHTS CHO FOCALLOSS (Cân bằng Imbalance)[/bold cyan]")
    class_weights = compute_class_weights(df)
    table_weights = Table(show_header=True, header_style="bold green")
    table_weights.add_column("Nhãn")
    table_weights.add_column("Loại Tấn Công")
    table_weights.add_column("Weight")
    table_weights.add_column("Ý nghĩa")
    
    for label_id in sorted(class_weights.keys()):
        weight = class_weights[label_id]
        name = LABELS.get(label_id, "Unknown")
        meaning = f"Nặng {weight:.2f}x" if weight > 1 else f"Nhẹ {1/weight:.2f}x"
        table_weights.add_row(str(label_id), name, f"{weight:.4f}", meaning)
    
    console.print(table_weights)
    console.print("[dim]-> Những lớp hiếm hơn (ít mẫu) sẽ được trọng số cao hơn để mô hình tập trung học.[/dim]")

    # 7. KIỂM TRA PHÂN BỐ ĐẶCTRƯNG (NEW)
    console.print("\n[bold cyan]6. PHÂN TÍCH PHÂN BỐ ĐẶC TRƯNG (Feature Distribution)[/bold cyan]")
    # ... (giữ nguyên logic cũ)

    # 7b. PHÂN TÍCH ENTROPY PORT (YÊU CẦU MỚI)
    console.print("\n[bold cyan]6b. PHÂN TÍCH ENTROPY PORT THEO NHÃN (Port Diversity)[/bold cyan]")
    port_entropy_results = check_port_entropy(df)
    
    table_entropy = Table(show_header=True, header_style="bold yellow")
    table_entropy.add_column("Nhãn")
    table_entropy.add_column("Entropy SrcPort")
    table_entropy.add_column("Unique Src")
    table_entropy.add_column("Entropy DstPort")
    table_entropy.add_column("Unique Dst")
    table_entropy.add_column("Đánh giá")
    
    for res in port_entropy_results:
        # Đánh giá sơ bộ: Entropy thấp = Port bị cố định (thường là tấn công hoặc dịch vụ cụ thể)
        # Entropy cao = Port ngẫu nhiên (thường là client bình thường hoặc spoofing port)
        eval_msg = ""
        if res['Src_Entropy'] < 1.0:
            eval_msg = "[cyan]SrcPort Cố định[/cyan]"
        elif res['Src_Entropy'] > 5.0:
            eval_msg = "[magenta]SrcPort Phân tán[/magenta]"
        else:
            eval_msg = "[green]Bình thường[/green]"
            
        table_entropy.add_row(
            res['Label'],
            f"{res['Src_Entropy']:.4f}",
            f"{res['Unique_Src']:,}",
            f"{res['Dst_Entropy']:.4f}",
            f"{res['Unique_Dst']:,}",
            eval_msg
        )
    
    console.print(table_entropy)
    console.print("[dim]Giải thích: Entropy càng cao -> Port càng ngẫu nhiên. Entropy thấp -> Port tập trung vào 1 vài giá trị.[/dim]")
    console.print("[dim]Gợi ý: Nếu Entropy SrcPort của Normal và Attack quá khác biệt, nên dùng Entropy thay vì Port gốc.[/dim]")

    # 7c. PHÂN TÍCH CHI TIẾT TẤT CẢ ĐẶC TRƯNG THEO NHÃN (MỚI - COMPREHENSIVE)
    console.print("\n[bold cyan]6c. PHÂN TÍCH CHI TIẾT TẤT CẢ ĐẶC TRƯNG THEO NHÃN (Comprehensive Analysis)[/bold cyan]")
    console.print("[yellow]Đang phân tích chi tiết tất cả 13 đặc trưng...[/yellow]")
    
    analysis = analyze_all_features_by_label(df)
    
    # Phân tích theo nhóm đặc trưng
    for group_name, features in FEATURE_GROUPS.items():
        console.print(f"\n[bold magenta]📊 NHÓM: {group_name}[/bold magenta]")
        
        for feat_name in features:
            if feat_name in analysis:
                console.print(f"\n[bold yellow]▸ {feat_name}[/bold yellow]")
                print_feature_analysis_table(analysis, feat_name, console)
                
                # Thêm nhận xét chuyên sâu cho từng đặc trưng
                stats_by_label = analysis[feat_name]
                if len(stats_by_label) > 1:
                    normal_mean = stats_by_label.get(0, {}).get('mean', 0)
                    attack_means = [stats_by_label[lbl]['mean'] for lbl in stats_by_label if lbl != 0]
                    
                    if attack_means and normal_mean > 0:
                        max_attack_mean = max(attack_means)
                        ratio = max_attack_mean / normal_mean if normal_mean > 0 else 0
                        
                        if ratio > 10:
                            console.print(f"   [green]✓ Phân biệt tốt:[/green] Attack cao gấp ~{ratio:.1f}x Normal")
                        elif ratio < 0.1:
                            console.print(f"   [green]✓ Phân biệt tốt:[/green] Attack thấp gấp ~{1/ratio:.1f}x Normal")
                        else:
                            console.print(f"   [yellow]⚠ Chưa rõ:[/yellow] Attack/Normal ratio ~{ratio:.2f}")
    
    # Tổng kết khả năng phân biệt
    console.print("\n[bold cyan]6d. TỔNG KẾT KHẢ NĂNG PHÂN BIỆT CỦA TỪNG ĐẶC TRƯNG[/bold cyan]")
    discrimination_scores = []
    
    for feat_name in FEATURE_NAMES:
        if feat_name in analysis:
            stats_by_label = analysis[feat_name]
            normal_stats = stats_by_label.get(0)
            if normal_stats:
                normal_mean = normal_stats['mean']
                normal_std = normal_stats['std']
                
                # Tính separation score: độ cách biệt giữa Normal và các Attack
                separations = []
                for lbl in [1, 2, 3, 4]:  # Các nhãn attack
                    if lbl in stats_by_label:
                        attack_mean = stats_by_label[lbl]['mean']
                        attack_std = stats_by_label[lbl]['std']
                        # Cohen's d effect size
                        pooled_std = ((normal_std**2 + attack_std**2) / 2) ** 0.5 if attack_std > 0 else normal_std
                        if pooled_std > 0:
                            cohens_d = abs(attack_mean - normal_mean) / pooled_std
                            separations.append(cohens_d)
                
                avg_separation = sum(separations) / len(separations) if separations else 0
                discrimination_scores.append((feat_name, avg_separation))
    
    # Sắp xếp và hiển thị
    discrimination_scores.sort(key=lambda x: x[1], reverse=True)
    
    table_disc = Table(show_header=True, header_style="bold green")
    table_disc.add_column("Xếp hạng")
    table_disc.add_column("Đặc trưng")
    table_disc.add_column("Separation Score (Cohen's d)")
    table_disc.add_column("Đánh giá")
    
    for rank, (feat_name, score) in enumerate(discrimination_scores, 1):
        if score > 2:
            eval_text = "[bold green]★★★ Xuất sắc[/bold green]"
        elif score > 1:
            eval_text = "[green]★★ Tốt[/green]"
        elif score > 0.5:
            eval_text = "[yellow]★ Khá[/yellow]"
        else:
            eval_text = "[dim]Yếu[/dim]"
        
        table_disc.add_row(str(rank), feat_name, f"{score:.3f}", eval_text)
    
    console.print(table_disc)
    console.print("[dim]Giải thích: Cohen's d > 2.0 = phân biệt rất tốt, 1.0-2.0 = tốt, 0.5-1.0 = trung bình, <0.5 = yếu[/dim]")
    
    feature_stats = check_feature_distribution(df)
    table_dist = Table(show_header=True, header_style="bold cyan")
    table_dist.add_column("Đặc trưng")
    table_dist.add_column("Mean")
    table_dist.add_column("Std Dev")
    table_dist.add_column("Skewness")
    table_dist.add_column("Phân loại")
    
    for feat_name, stats in feature_stats.items():
        skewness = stats['skewness']
        if abs(skewness) > 2:
            dist_type = "[bold red]Quá lệch[/bold red]"
        elif abs(skewness) > 1:
            dist_type = "[yellow]Lệch[/yellow]"
        else:
            dist_type = "[green]Bình thường[/green]"
        
        table_dist.add_row(
            feat_name[:15],
            f"{stats['mean']:.2f}",
            f"{stats['std']:.2f}",
            f"{skewness:.2f}",
            dist_type
        )
    
    console.print(table_dist)
    console.print("[dim]-> Nếu Skewness > 2, đặc trưng quá lệch, có thể cần log-transform.[/dim]")

    # 8. PHÁT HIỆN OUTLIERS (NEW)
    console.print("\n[bold cyan]7. PHÁT HIỆN OUTLIERS (Sử dụng Z-score > 3)[/bold cyan]")
    outliers = detect_outliers(df, threshold=3)
    total_outliers = sum(outliers.values())
    outlier_percent = (total_outliers / (total_rows * len(df.columns[:-1]))) * 100
    
    console.print(f"[*] Tổng số outliers phát hiện: {total_outliers:,} ({outlier_percent:.2f}%)")
    if outlier_percent > 1:
        console.print("[bold yellow]💡 LƯỚI CẢNH BÁO: Outliers > 1%. Nên kiểm tra quy trình thu thập dữ liệu.[/bold yellow]")
        # Liệt kê top 5 features có outliers nhiều nhất
        top_outlier_features = sorted(outliers.items(), key=lambda x: x[1], reverse=True)[:5]
        console.print("[dim]Top 5 đặc trưng có outliers nhiều nhất:[/dim]")
        for feat, count in top_outlier_features:
            console.print(f"  - {feat}: {count:,} outliers")
    else:
        console.print("[green]✅ Outliers < 1%. Dữ liệu sạch.[/green]")

    # Index các cột cần nén: Bytes, Packets, Rates
    cols_to_log = [4, 5, 6, 7, 10, 11, 17, 18, 19, 20, 23, 24] 
    
    # Chỉ lấy dữ liệu Normal để phân tích sâu
    df_normal = df[df.iloc[:, -1] == 0].copy()
    
    if len(df_normal) == 0:
        console.print("[bold red]❌ Không tìm thấy dữ liệu Normal (nhãn 0) trong dataset![/bold red]")
        return

    console.print(f"\n[bold cyan]9. PHÂN TÍCH CHUYÊN SÂU DỮ LIỆU NORMAL (Nhãn 0) - {len(df_normal):,} mẫu[/bold cyan]")
    
    # Phân tích sự ổn định (Variance)
    normal_stats = []
    # Các đặc trưng quan trọng cho AE
    key_features = ["Duration_Sec", "Src_Bytes", "Dst_Bytes", "Packet_Rate", "Byte_Rate"]
    
    table_normal = Table(show_header=True, header_style="bold green")
    table_normal.add_column("Đặc trưng")
    table_normal.add_column("CV (%)")
    table_normal.add_column("Độ ổn định")
    table_normal.add_column("Nhận xét cho AE")

    for feat in key_features:
        if feat in df.columns:
            mean = df_normal[feat].mean()
            std = df_normal[feat].std()
            cv = (std / mean * 100) if mean != 0 else 0
            
            stability = "Rất tốt" if cv < 20 else "Ổn định" if cv < 50 else "Biến động mạnh"
            comment = "Dễ học" if cv < 50 else "Khó học (Cần Log)"
            
            table_normal.add_row(feat, f"{cv:.1f}%", stability, comment)
    
    console.print(table_normal)
    console.print("[dim]-> CV (Coefficient of Variation) < 50% là lý tưởng để Autoencoder học pattern ổn định.[/dim]")

    # Kiểm tra sự tương quan trong Normal
    normal_corr = df_normal[key_features].corr()
    console.print("\n[bold cyan]10. ĐỘ TƯƠNG QUAN TRONG NORMAL (Redundancy Check)[/bold cyan]")
    high_corr = []
    for i in range(len(normal_corr.columns)):
        for j in range(i):
            if abs(normal_corr.iloc[i, j]) > 0.9:
                high_corr.append((normal_corr.columns[i], normal_corr.columns[j], normal_corr.iloc[i, j]))
    
    if high_corr:
        for f1, f2, val in high_corr:
            console.print(f"  - [yellow]⚠️ Tương quan cao:[/yellow] {f1} & {f2} ({val:.2f})")
        console.print("[dim]-> Tương quan quá cao giữa các đặc trưng giúp AE nén dữ liệu tốt hơn.[/dim]")
    else:
        console.print("[green]✅ Các đặc trưng độc lập tốt, mang lại nhiều thông tin đa dạng.[/green]")

    # 9. VẼ BIỂU ĐỒ (TỐI ƯU CHO BIG DATA)
    console.print("\n[bold cyan]8. TẠO BÁO CÁO TRỰC QUAN (EDA)[/bold cyan]")
    console.print("[yellow]Đang render biểu đồ (Có thể mất vài giây do dữ liệu lớn)...[/yellow]")
    
    # Lấy mẫu (Sample) 50,000 dòng ngẫu nhiên để vẽ Heatmap cho nhanh, tránh treo máy
    df_sample = df.sample(n=min(50000, len(df)), random_state=42)
    
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # Biểu đồ 1: Phân bố nhãn
    ax1 = axes[0, 0]
    label_counts_plot = df.iloc[:, -1].value_counts().sort_index()
    colors = plt.cm.Set3(np.linspace(0, 1, len(label_counts_plot)))
    ax1.bar(label_counts_plot.index, label_counts_plot.values, color=colors)
    ax1.set_title(f'Phân bố Nhãn (Tổng: {total_rows:,} mẫu)', fontsize=12, fontweight='bold')
    ax1.set_xlabel('Nhãn')
    ax1.set_ylabel('Số lượng')
    for i, v in enumerate(label_counts_plot.values):
        ax1.text(i, v, f'{v:,}\n({v/total_rows*100:.1f}%)', ha='center', va='bottom', fontsize=9)

    # Biểu đồ 2: Heatmap Tương quan
    ax2 = axes[0, 1]
    corr = df_sample.iloc[:, :-1].corr() 
    sns.heatmap(corr, annot=False, cmap='RdBu_r', center=0, cbar=True, square=True, ax=ax2)
    ax2.set_title('Ma trận Tương quan (Feature Correlation)', fontsize=12, fontweight='bold')

    # Biểu đồ 3: Anomaly_Score distribution
    ax3 = axes[1, 0]
    anomaly_dist = df.iloc[:, -2]  # Anomaly_Score column
    ax3.hist(anomaly_dist, bins=50, color='skyblue', edgecolor='black', alpha=0.7)
    ax3.set_title('Phân bố Anomaly_Score', fontsize=12, fontweight='bold')
    ax3.set_xlabel('Anomaly_Score')
    ax3.set_ylabel('Tần suất')

    # Biểu đồ 4: Byte_Rate distribution (log scale)
    ax4 = axes[1, 1]
    byte_rate = df.iloc[:, 11]  # Byte_Rate column
    ax4.hist(byte_rate[byte_rate > 0], bins=50, color='lightcoral', edgecolor='black', alpha=0.7)
    ax4.set_title('Phân bố Byte_Rate', fontsize=12, fontweight='bold')
    ax4.set_xlabel('Byte_Rate (log scale)')
    ax4.set_ylabel('Tần suất')
    ax4.set_yscale('log')
    
    plt.tight_layout()
    plot_path = "dataset_v6_report.png"
    plt.savefig(plot_path, dpi=300)
    console.print(f"[bold green]✅ Đã xuất biểu đồ chuẩn báo cáo ra file: {plot_path}[/bold green]")
    plt.close()

    # KẾT LUẬN
    console.print("\n" + "="*70)
    console.print("[bold bright_green]📋 TỔNG KẾT KIỂM ĐỊNH DATASET[/bold bright_green]")
    console.print("="*70)
    
    if total_nulls == 0 and len(non_numeric_cols) == 0 and outlier_percent < 1:
        console.print("[bold bright_green]✅ DATASET ĐẠT CHUẨN ĐẦU VÀO AI (READY 100%).[/bold bright_green]")
        console.print("\n[bold yellow]📤 BƯỚC TIẾP THEO:[/bold yellow]")
        console.print("1. Upload file master_dataset_v6.csv lên Google Drive")
        console.print("2. Chạy train_colab_v2.py trên Google Colab (tham khảo HƯỚNG DẪN bên dưới)")
        console.print("3. Download 4 file model sau khi train:")
        console.print("   - sdn_scaler.pkl")
        console.print("   - sdn_autoencoder_contrastive.pth")
        console.print("   - sdn_model_parallel_fusion.pth")
        console.print("   - ae_threshold.pkl")
        console.print("4. Copy vào thư mục ai/ và chạy python run_onos_v2.py để triển khai")
    else:
        console.print("[bold yellow]⚠️ TỔNG KẾT: DATASET CÓ MỘT SỐ VẤN ĐỀ CẦN CHÚ Ý[/bold yellow]")
        if total_nulls > 0:
            console.print(f"  - NaN/Infinity: {total_nulls:,} → Sẽ tự động xử lý trong train_colab_v2.py")
        if len(non_numeric_cols) > 0:
            console.print(f"  - Cột không số: {non_numeric_cols} → LỖI! Cần sửa trong auto_dataset_generator.py")
        if outlier_percent > 1:
            console.print(f"  - Outliers: {outlier_percent:.2f}% → Kiểm tra quy trình thu thập")
    
    console.print("="*70 + "\n")

if __name__ == "__main__":
    run_inspection()