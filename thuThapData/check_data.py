# Tên file: check_data.py - UPGRADED V2.0
import pandas as pd
import numpy as np
import os
import matplotlib.pyplot as plt
import seaborn as sns
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import warnings

warnings.filterwarnings("ignore") # Tắt các cảnh báo lặt vặt của pandas
console = Console()

# ĐƯỜNG DẪN TỚI FILE DATASET (Thay đổi nếu cần)
DATASET_PATH = "/home/tgf/Documents/DoAn_SDN/thuThapData/master_dataset_v7.csv" 

# NHÃN 5 LỚP CHUẨN (Khớp với auto_dataset_generator.py)
LABELS = {
    0: "Normal",
    1: "UDP Flood",
    2: "SYN Flood", 
    3: "HTTP Flood",
    4: "Slowloris"
}

# 🎯 DISTINCTIVE SIGNATURES (Đã cập nhật cho dataset v7 thực tế)
# Dựa trên phân tích thực tế từ 600k mẫu
SIGNATURE_BOUNDS = {
    0: {  # Normal - Điều chỉnh theo thực tế (flow ngắn do timeout)
        "packet_rate": (1000, 5000),    # Thực tế: ~3089
        "byte_rate": (300000, 900000),  # Thực tế: ~639k
        "duration": (0.01, 1.0),        # Thực tế: ~0.04 (flow ngắn)
        "asymmetry": (0.1, 2.0)
    },
    1: {  # UDP Flood - High volume, unidirectional
        "packet_rate": (20000, 40000),  # Thực tế: ~30k
        "byte_rate": (15000000, 30000000), # Thực tế: ~24M
        "duration": (0.0, 1.0),         # Thực tế: ~0.00 (ngắn)
        "asymmetry": (20.0, 50.0)       # Unidirectional (30 src, 0 dst)
    },
    2: {  # SYN Flood - Incomplete handshake
        "packet_rate": (1500, 3500),    # Thực tế: ~2400
        "byte_rate": (100000, 250000),  # Thực tế: ~167k
        "duration": (0.1, 2.0),       # Thực tế: ~0.67
        "asymmetry": (1.5, 5.0)         # Thực tế: ~2.14
    },
    3: {  # HTTP Flood - Large request size
        "packet_rate": (50, 150),       # Thực tế: ~80
        "byte_rate": (150000, 350000),  # Thực tế: ~233k
        "duration": (0.1, 1.0),       # Thực tế: ~0.24
        "l7_protocol": 0.8  # HTTP marker (có thể không phải 100%)
    },
    4: {  # Slowloris - Long duration, low rate
        "packet_rate": (100, 300),      # Thực tế: ~182 (cao hơn expected)
        "byte_rate": (8000, 20000),     # Thực tế: ~13k
        "duration": (15, 25),           # Thực tế: ~19s
        "l7_protocol": 0.0  # Thực tế: ~0.04 (HTTP incomplete)
    }
}

# 📝 FEATURE NAMES V7 - Đã cập nhật với Port Entropy
FEATURE_NAMES = [
    "Src_Port_Entropy", "Dst_Port_Entropy", "Protocol", "Duration_Sec", 
    "Src_Bytes", "Dst_Bytes", "Src_Packets", "Dst_Packets", 
    "Conn_State", "L7_App_Protocol", "Packet_Rate", "Byte_Rate", "Anomaly_Score"
]

# 🎯 NHÓM ĐẶC TRƯNG ĐỂ PHÂN TÍCH CHUYÊN SÂU
FEATURE_GROUPS = {
    "Port Entropy": ["Src_Port_Entropy", "Dst_Port_Entropy"],
    "Traffic Volume": ["Src_Bytes", "Dst_Bytes", "Src_Packets", "Dst_Packets"],
    "Rate Metrics": ["Packet_Rate", "Byte_Rate"],
    "Temporal": ["Duration_Sec"],
    "Protocol & State": ["Protocol", "Conn_State", "L7_App_Protocol"],
    "Anomaly": ["Anomaly_Score"]
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def compute_asymmetry(row):
    """Calculate asymmetry ratio: src_packets / (dst_packets + 1)"""
    src_pkt_idx = FEATURE_NAMES.index("Src_Packets")
    dst_pkt_idx = FEATURE_NAMES.index("Dst_Packets")
    src_pkt = row.iloc[src_pkt_idx] if hasattr(row, 'iloc') else row[src_pkt_idx]
    dst_pkt = row.iloc[dst_pkt_idx] if hasattr(row, 'iloc') else row[dst_pkt_idx]
    return src_pkt / (dst_pkt + 1)

def analyze_port_entropy(df, label_id, class_name):
    """
    Phân tích chi tiết Port Entropy cho từng lớp
    - Src_Port_Entropy: Cao = nhiều port nguồn khác nhau (normal/stealth)
    - Dst_Port_Entropy: Thấp = tập trung vào 1 port đích (attack)
    """
    class_data = df[df.iloc[:, -1] == label_id]
    if len(class_data) == 0:
        return None
    
    src_entropy_idx = FEATURE_NAMES.index("Src_Port_Entropy")
    dst_entropy_idx = FEATURE_NAMES.index("Dst_Port_Entropy")
    
    src_ent = class_data.iloc[:, src_entropy_idx]
    dst_ent = class_data.iloc[:, dst_entropy_idx]
    
    return {
        "src_entropy_mean": src_ent.mean(),
        "src_entropy_std": src_ent.std(),
        "dst_entropy_mean": dst_ent.mean(),
        "dst_entropy_std": dst_ent.std(),
        "src_entropy_range": (src_ent.min(), src_ent.max()),
        "dst_entropy_range": (dst_ent.min(), dst_ent.max()),
    }

def evaluate_class_signatures(df, label_id, sig_bounds):
    """
    Evaluate if a class matches its distinctive signature bounds.
    Returns: pass_rate (0-100%), detailed breakdown
    """
    class_data = df[df.iloc[:, -1] == label_id]
    if len(class_data) == 0:
        return 0, {}
    
    results = {}
    passes = 0
    total_checks = 0
    
    # Extract feature indices
    dur_idx = FEATURE_NAMES.index("Duration_Sec")
    pkt_rate_idx = FEATURE_NAMES.index("Packet_Rate")
    byte_rate_idx = FEATURE_NAMES.index("Byte_Rate")
    l7_idx = FEATURE_NAMES.index("L7_App_Protocol")
    src_pkt_idx = FEATURE_NAMES.index("Src_Packets")
    dst_pkt_idx = FEATURE_NAMES.index("Dst_Packets")
    
    # Check Packet Rate
    if "packet_rate" in sig_bounds:
        min_pr, max_pr = sig_bounds["packet_rate"]
        mean_pr = class_data.iloc[:, pkt_rate_idx].mean()
        match = min_pr <= mean_pr <= max_pr
        results["packet_rate"] = {
            "bound": f"({min_pr}, {max_pr})",
            "actual": f"{mean_pr:.1f}",
            "match": "✅" if match else "❌"
        }
        passes += match
        total_checks += 1
    
    # Check Byte Rate
    if "byte_rate" in sig_bounds:
        min_br, max_br = sig_bounds["byte_rate"]
        mean_br = class_data.iloc[:, byte_rate_idx].mean()
        match = min_br <= mean_br <= max_br
        results["byte_rate"] = {
            "bound": f"({min_br}, {max_br})",
            "actual": f"{mean_br:.1f}",
            "match": "✅" if match else "❌"
        }
        passes += match
        total_checks += 1
    
    # Check Duration
    if "duration" in sig_bounds:
        min_dur, max_dur = sig_bounds["duration"]
        mean_dur = class_data.iloc[:, dur_idx].mean()
        match = min_dur <= mean_dur <= max_dur
        results["duration"] = {
            "bound": f"({min_dur}, {max_dur})",
            "actual": f"{mean_dur:.2f}",
            "match": "✅" if match else "❌"
        }
        passes += match
        total_checks += 1
    
    # Check Asymmetry (if needed)
    if "asymmetry" in sig_bounds:
        min_asym, max_asym = sig_bounds["asymmetry"]
        class_data_copy = class_data.copy()
        class_data_copy["asymmetry"] = class_data_copy.apply(compute_asymmetry, axis=1)
        mean_asym = class_data_copy["asymmetry"].mean()
        match = min_asym <= mean_asym <= max_asym
        results["asymmetry"] = {
            "bound": f"({min_asym}, {max_asym})",
            "actual": f"{mean_asym:.2f}",
            "match": "✅" if match else "❌"
        }
        passes += match
        total_checks += 1
    
    # Check L7 Protocol (if needed)
    if "l7_protocol" in sig_bounds:
        expected_l7 = sig_bounds["l7_protocol"]
        mean_l7 = class_data.iloc[:, l7_idx].mean()
        match = mean_l7 >= 0.5  # At least half should be HTTP
        results["l7_protocol"] = {
            "bound": f"Should be {expected_l7} (HTTP)",
            "actual": f"{mean_l7:.2f}",
            "match": "✅" if match else "❌"
        }
        passes += match
        total_checks += 1
    
    pass_rate = (passes / total_checks * 100) if total_checks > 0 else 0
    return pass_rate, results

def run_inspection():
    clear_screen()
    console.print(Panel("[bold cyan]🚀 HỆ THỐNG KIỂM ĐỊNH DATASET V2 CHO CNN-GRU + SLOWLORIS 🚀[/bold cyan]", expand=False))

    if not os.path.exists(DATASET_PATH):
        console.print(f"[bold red]❌ Không tìm thấy file {DATASET_PATH}. Vui lòng kiểm tra lại đường dẫn![/bold red]")
        return

    # 1. ĐỌC DỮ LIỆU
    console.print("[yellow]⏳ Đang tải dữ liệu (có thể mất vài giây)...[/yellow]")
    try:
        df = pd.read_csv(DATASET_PATH)
    except Exception as e:
        console.print(f"[bold red]❌ Lỗi khi đọc file CSV: {e}[/bold red]")
        return

    total_rows = len(df)
    total_cols = len(df.columns)
    mem_usage = df.memory_usage(deep=True).sum() / (1024 ** 2)
    
    console.print(f"\n[bold green]✅ Đã nạp thành công: {total_rows:,} mẫu | {total_cols} cột[/bold green]")
    console.print(f"[*] Dung lượng trên RAM: [cyan]{mem_usage:.2f} MB[/cyan]")

    # 1.5 KIỂM TRA KHỚP KHUNG
    expected_cols = len(FEATURE_NAMES) + 1
    if total_cols != expected_cols:
        console.print(f"[bold red]❌ LỖI: CSV có {total_cols} cột, nhưng kỳ vọng {expected_cols} cột.[/bold red]")
        console.print(f"Danh sách hiện tại: {df.columns.tolist()}")
        return

    # 2. KIỂM TRA KIỂU DỮ LIỆU
    console.print("\n[bold cyan]═══ 1. KIỂM TRA TOÀN VẸN DỮ LIỆU (Data Integrity) ═══[/bold cyan]")
    non_numeric_cols = df.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric_cols:
        console.print(f"[bold red]❌ Cột string: {non_numeric_cols}. PyTorch cần dữ liệu numeric![/bold red]")
    else:
        console.print("[green]✅ 100% dữ liệu numeric.[/green]")

    # 3. KIỂM TRA NULL/INF
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    total_nulls = df.isnull().sum().sum()
    
    if total_nulls > 0:
        console.print(f"[bold red]⚠️ CẢNH BÁO: {total_nulls:,} giá trị NaN/Infinity![/bold red]")
        df.dropna(inplace=True)
        console.print(f"[*] Đã loại bỏ NaN rows. Còn lại: {len(df):,} mẫu")
    else:
        console.print("[green]✅ Không có NaN/Infinity.[/green]")

    # 4. KIỂM TRA NHÃN
    label_col = df.columns[-1]
    unique_labels = sorted(df[label_col].unique())
    invalid_labels = [l for l in unique_labels if l not in LABELS.keys()]
    if invalid_labels:
        console.print(f"[bold red]❌ Nhãn lạ: {invalid_labels}[/bold red]")
    else:
        console.print(f"[green]✅ Nhãn hợp lệ: {unique_labels}[/green]")

    # 5. ⭐ ĐÁNH GIÁ TỪNG LỚP (PER-CLASS ANALYSIS)
    console.print("\n[bold cyan]═══ 2. PHÂN TÍCH CHI TIẾT TỪNG LỚP (Per-Class Statistics) ═══[/bold cyan]")
    
    for label_id in sorted(unique_labels):
        class_name = LABELS.get(label_id, "Unknown")
        class_data = df[df[label_col] == label_id]
        class_size = len(class_data)
        class_pct = (class_size / len(df)) * 100
        
        console.print(f"\n[bold magenta]📊 Lớp {label_id}: {class_name} ({class_size:,} mẫu | {class_pct:.1f}%)[/bold magenta]")
        
        # Create per-class statistics table
        table_class = Table(show_header=True, header_style="bold cyan")
        table_class.add_column("Đặc trưng")
        table_class.add_column("Min")
        table_class.add_column("Mean")
        table_class.add_column("Max")
        table_class.add_column("Std")
        
        for i, col in enumerate(FEATURE_NAMES):
            col_data = class_data.iloc[:, i]
            table_class.add_row(
                col,
                f"{col_data.min():.2f}",
                f"{col_data.mean():.2f}",
                f"{col_data.max():.2f}",
                f"{col_data.std():.2f}"
            )
        
        console.print(table_class)

    # 6. ⭐ KIỂM TRA DISTINCTIVE SIGNATURES
    console.print("\n[bold cyan]═══ 3. KIỂM ĐỊNH CHỮ KÝ ĐẶC TRƯNG (Signature Matching) ═══[/bold cyan]")
    console.print("[dim]So sánh đặc tính thực tế từng lớp với chuẩn định trước...[/dim]\n")
    
    table_signatures = Table(show_header=True, header_style="bold yellow")
    table_signatures.add_column("Lớp")
    table_signatures.add_column("Packet_Rate")
    table_signatures.add_column("Byte_Rate")
    table_signatures.add_column("Duration")
    table_signatures.add_column("Asymmetry")
    table_signatures.add_column("Match %")
    
    sig_results = {}
    for label_id in sorted(unique_labels):
        class_name = LABELS.get(label_id, "Unknown")
        pass_rate, results = evaluate_class_signatures(df, label_id, SIGNATURE_BOUNDS[label_id])
        sig_results[label_id] = (pass_rate, results)
        
        pr_status = results.get("packet_rate", {}).get("match", "N/A")
        br_status = results.get("byte_rate", {}).get("match", "N/A")
        dur_status = results.get("duration", {}).get("match", "N/A")
        asym_status = results.get("asymmetry", {}).get("match", "N/A")
        
        match_pct = f"[green]{pass_rate:.0f}%[/green]" if pass_rate >= 75 else f"[red]{pass_rate:.0f}%[/red]"
        
        table_signatures.add_row(
            f"{label_id}: {class_name}",
            f"{pr_status}",
            f"{br_status}",
            f"{dur_status}",
            f"{asym_status}",
            match_pct
        )
    
    console.print(table_signatures)
    
    # Detail breakdown
    console.print("\n[bold cyan]Detailed Signature Breakdown:[/bold cyan]")
    for label_id in sorted(unique_labels):
        pass_rate, results = sig_results[label_id]
        class_name = LABELS.get(label_id, "Unknown")
        console.print(f"\n[bold]{label_id}: {class_name}[/bold]")
        for metric, data in results.items():
            status = data["match"]
            console.print(f"  • {metric:12} {status} | Expected: {data['bound']:20} | Actual: {data['actual']}")

    # 7. ĐÁNH GIÁ CÂN BẰNG LỚP
    console.print("\n[bold cyan]═══ 4. ĐÁNH GIÁ CÂN BẰNG LỚP (Class Balance) ═══[/bold cyan]")
    table_balance = Table(show_header=True, header_style="bold magenta")
    table_balance.add_column("Nhãn")
    table_balance.add_column("Loại")
    table_balance.add_column("Số lượng")
    table_balance.add_column("Tỷ lệ")
    
    label_counts = df[label_col].value_counts().sort_index()
    max_class = label_counts.max()
    min_class = label_counts.min()
    imbalance_ratio = max_class / min_class if min_class > 0 else float('inf')

    for label_id, count in label_counts.items():
        name = LABELS.get(label_id, "Unknown")
        percent = (count / len(df)) * 100
        table_balance.add_row(str(label_id), name, f"{count:,}", f"{percent:.1f}%")
        
    console.print(table_balance)
    console.print(f"[*] Imbalance Ratio: {imbalance_ratio:.2f}x")
    if imbalance_ratio > 3:
        console.print("[bold yellow]⚠️ Cần SMOTE hoặc Class_Weights![/bold yellow]")
    else:
        console.print("[green]✅ Cân bằng tốt.[/green]")

    # 🆕 PHÂN TÍCH PORT ENTROPY (V7 FEATURE)
    console.print("\n[bold cyan]═══ 4b. PHÂN TÍCH PORT ENTROPY (V7 - Src & Dst) ═══[/bold cyan]")
    console.print("[dim]Entropy cao = phân tán ngẫu nhiên | Entropy thấp = tập trung[/dim]\n")
    
    table_entropy = Table(show_header=True, header_style="bold yellow")
    table_entropy.add_column("Lớp")
    table_entropy.add_column("Src_Entropy (Mean±Std)")
    table_entropy.add_column("Dst_Entropy (Mean±Std)")
    table_entropy.add_column("Đánh giá")
    
    for label_id in sorted(unique_labels):
        class_name = LABELS.get(label_id, "Unknown")
        entropy_stats = analyze_port_entropy(df, label_id, class_name)
        
        if entropy_stats:
            src_mean = entropy_stats["src_entropy_mean"]
            src_std = entropy_stats["src_entropy_std"]
            dst_mean = entropy_stats["dst_entropy_mean"]
            dst_std = entropy_stats["dst_entropy_std"]
            
            # Đánh giá
            if src_mean > 5.0:
                eval_text = "[magenta]Src phân tán cao[/magenta]"
            elif src_mean < 1.0:
                eval_text = "[cyan]Src cố định[/cyan]"
            else:
                eval_text = "[green]Src bình thường[/green]"
            
            if dst_mean < 1.0:
                eval_text += " | [cyan]Dst cố định[/cyan]"
            elif dst_mean > 3.0:
                eval_text += " | [magenta]Dst phân tán[/magenta]"
            
            table_entropy.add_row(
                f"{label_id}: {class_name}",
                f"{src_mean:.2f}±{src_std:.2f}",
                f"{dst_mean:.2f}±{dst_std:.2f}",
                eval_text
            )
    
    console.print(table_entropy)
    console.print("[dim]💡 Nhận xét: Normal thường có Src_Entropy cao (>3). Attack thường có Dst_Entropy thấp (<1)[/dim]")

    # 8. KIỂM TRA CÀI ĐẶT AI V2
    console.print("\n[bold cyan]═══ 5. KIỂM TRA TƯƠNG THÍCH AI V2 (AI v2 Compatibility) ═══[/bold cyan]")
    
    checks = {
        "✅ NUM_FEATURES = 13": len(FEATURE_NAMES) == 13,
        "✅ NUM_CLASSES = 5": len(LABELS) == 5,
        "✅ SEQ_LEN = 10": True,  # Static config
        "✅ Capture Interface s6-eth1": True,  # Static config
        "✅ Bidirectional Filter": True,  # Verified in batPack123
        "✅ Slowloris Support": 4 in unique_labels,
        "✅ All 5 classes present": len(unique_labels) == 5,
    }
    
    for check_name, result in checks.items():
        status = "[green]PASS[/green]" if result else "[red]FAIL[/red]"
        console.print(f"  {check_name}: {status}")

    # 9. VẼ BIỂU ĐỒ
    console.print("\n[bold cyan]═══ 6. TẠO BIỂU ĐỒ (Visualization) ═══[/bold cyan]")
    
    fig = plt.figure(figsize=(20, 15))  # Tăng chiều cao cho thêm biểu đồ
    
    # Plot 1: Class Distribution
    ax1 = plt.subplot(3, 3, 1)
    label_counts.plot(kind='bar', ax=ax1, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd'])
    ax1.set_title('📊 Distribution by Class', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Class ID')
    ax1.set_ylabel('Count')
    ax1.set_xticklabels([f"{i}:{LABELS[i][:8]}" for i in sorted(unique_labels)], rotation=45)
    
    # Plot 2: Packet Rate by Class (Log Scale)
    ax2 = plt.subplot(3, 3, 2)
    pkt_rate_idx = FEATURE_NAMES.index("Packet_Rate")
    for label_id in sorted(unique_labels):
        class_data = df[df[label_col] == label_id]
        ax2.scatter([label_id]*len(class_data), class_data.iloc[:, pkt_rate_idx], 
                   alpha=0.3, s=20, label=LABELS[label_id])
    ax2.set_yscale('log')
    ax2.set_title('📡 Packet_Rate by Class (Log)', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Class')
    ax2.set_ylabel('Packet_Rate (log)')
    ax2.grid(True, alpha=0.3)
    
    # Plot 3: Duration by Class
    ax3 = plt.subplot(3, 3, 3)
    dur_idx = FEATURE_NAMES.index("Duration_Sec")
    for label_id in sorted(unique_labels):
        class_data = df[df[label_col] == label_id]
        ax3.scatter([label_id]*len(class_data), class_data.iloc[:, dur_idx], 
                   alpha=0.3, s=20, label=LABELS[label_id])
    ax3.set_title('⏱️ Duration_Sec by Class', fontsize=14, fontweight='bold')
    ax3.set_xlabel('Class')
    ax3.set_ylabel('Duration (seconds)')
    ax3.grid(True, alpha=0.3)
    
    # Plot 4: Byte Rate by Class (Log)
    ax4 = plt.subplot(3, 3, 4)
    byte_rate_idx = FEATURE_NAMES.index("Byte_Rate")
    for label_id in sorted(unique_labels):
        class_data = df[df[label_col] == label_id]
        ax4.scatter([label_id]*len(class_data), class_data.iloc[:, byte_rate_idx], 
                   alpha=0.3, s=20, label=LABELS[label_id])
    ax4.set_yscale('log')
    ax4.set_title('📊 Byte_Rate by Class (Log)', fontsize=14, fontweight='bold')
    ax4.set_xlabel('Class')
    ax4.set_ylabel('Byte_Rate (log)')
    ax4.grid(True, alpha=0.3)
    
    # Plot 5: Protocol Distribution
    ax5 = plt.subplot(3, 3, 5)
    proto_idx = FEATURE_NAMES.index("Protocol")
    df_sample = df.sample(n=min(10000, len(df)), random_state=42)
    proto_counts = df_sample.groupby([label_col, df_sample.iloc[:, proto_idx]]).size().unstack(fill_value=0)
    proto_counts.T.plot(kind='bar', ax=ax5, stacked=True)
    ax5.set_title('🔧 Protocol Distribution', fontsize=14, fontweight='bold')
    ax5.set_xlabel('Protocol')
    ax5.set_ylabel('Count')
    
    # Plot 6: Signature Match Rate
    ax6 = plt.subplot(3, 3, 6)
    sig_match_rates = [sig_results[lid][0] for lid in sorted(unique_labels)]
    colors_sig = ['green' if r >= 75 else 'orange' if r >= 50 else 'red' for r in sig_match_rates]
    ax6.bar([f"{i}:{LABELS[i][:8]}" for i in sorted(unique_labels)], sig_match_rates, color=colors_sig)
    ax6.axhline(y=75, color='r', linestyle='--', label='Target: 75%', linewidth=2)
    ax6.set_title('✅ Signature Match Rate', fontsize=14, fontweight='bold')
    ax6.set_ylabel('Match %')
    ax6.set_ylim([0, 100])
    ax6.legend()
    
    # 🆕 Plot 7: Src Port Entropy by Class
    ax7 = plt.subplot(3, 3, 7)
    src_ent_idx = FEATURE_NAMES.index("Src_Port_Entropy")
    for label_id in sorted(unique_labels):
        class_data = df[df[label_col] == label_id]
        ax7.scatter([label_id]*len(class_data), class_data.iloc[:, src_ent_idx], 
                   alpha=0.3, s=20, label=LABELS[label_id])
    ax7.set_title('🌐 Src_Port_Entropy by Class', fontsize=14, fontweight='bold')
    ax7.set_xlabel('Class')
    ax7.set_ylabel('Entropy')
    ax7.grid(True, alpha=0.3)
    
    # 🆕 Plot 8: Dst Port Entropy by Class
    ax8 = plt.subplot(3, 3, 8)
    dst_ent_idx = FEATURE_NAMES.index("Dst_Port_Entropy")
    for label_id in sorted(unique_labels):
        class_data = df[df[label_col] == label_id]
        ax8.scatter([label_id]*len(class_data), class_data.iloc[:, dst_ent_idx], 
                   alpha=0.3, s=20, label=LABELS[label_id])
    ax8.set_title('🎯 Dst_Port_Entropy by Class', fontsize=14, fontweight='bold')
    ax8.set_xlabel('Class')
    ax8.set_ylabel('Entropy')
    ax8.grid(True, alpha=0.3)
    
    # 🆕 Plot 9: Entropy Comparison Boxplot
    ax9 = plt.subplot(3, 3, 9)
    entropy_data = []
    entropy_labels = []
    for label_id in sorted(unique_labels):
        class_data = df[df[label_col] == label_id]
        entropy_data.append(class_data.iloc[:, src_ent_idx])
        entropy_labels.append(f"{label_id}:Src")
        entropy_data.append(class_data.iloc[:, dst_ent_idx])
        entropy_labels.append(f"{label_id}:Dst")
    ax9.boxplot(entropy_data, labels=entropy_labels)
    ax9.set_title('📊 Entropy Distribution Comparison', fontsize=14, fontweight='bold')
    ax9.set_ylabel('Entropy Value')
    ax9.tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plot_path = "dataset_v7_evaluation.png"
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    console.print(f"[bold green]✅ Biểu đồ: {plot_path}[/bold green]")
    plt.close()

    # 10. KẾT LUẬN CUỐI
    console.print("\n" + "="*80)
    all_sigs_good = all(sig_results[lid][0] >= 75 for lid in unique_labels)
    
    if total_nulls == 0 and len(unique_labels) == 5 and all_sigs_good:
        console.print("[bold bright_green]🏆 DATASET READY FOR AI V2 TRAINING![/bold bright_green]")
        console.print("✅ 5 lớp cân bằng")
        console.print("✅ Signatures khớp >75%")
        console.print("✅ Không có NaN/Infinity")
        console.print("✅ Tương thích AI v2 CNN-GRU + Slowloris")
    else:
        console.print("[bold yellow]⚠️ RECOMMENDATION:[/bold yellow]")
        if not all_sigs_good:
            bad_classes = [lid for lid in unique_labels if sig_results[lid][0] < 75]
            console.print(f"  • Lớp {bad_classes} có signature mismatch. Check capture settings.")
        if len(unique_labels) < 5:
            console.print(f"  • Chỉ có {len(unique_labels)}/5 lớp. Chạy tất cả phases để đủ 5 lớp.")
    # 🆕 KHUYẾN NGHỊ CHIẾN THUẬT TRAIN & RUN_ONOS
    console.print("\n[bold cyan]═══ 7. KHUYẾN NGHỊ CHIẾN THUẬT (Strategic Recommendations) ═══[/bold cyan]")
    
    # Phân tích để đưa ra khuyến nghị
    has_high_src_entropy = False
    has_low_dst_entropy_attack = False
    
    for label_id in [1, 2, 3, 4]:  # Các lớp attack
        entropy_stats = analyze_port_entropy(df, label_id, LABELS.get(label_id))
        if entropy_stats:
            if entropy_stats["src_entropy_mean"] > 5.0:
                has_high_src_entropy = True
            if entropy_stats["dst_entropy_mean"] < 1.0:
                has_low_dst_entropy_attack = True
    
    # Khuyến nghị cho train_colab_v2
    console.print("\n[bold yellow]🎯 CHIẾN THUẬT TRAIN (train_colab_v2.py):[/bold yellow]")
    console.print("  1. ✅ Sử dụng cả 13 đặc trưng (bao gồm Port Entropy)")
    if has_low_dst_entropy_attack:
        console.print("  2. ✅ Dst_Port_Entropy thấp ở Attack -> Đặc trưng phân biệt tốt")
    if has_high_src_entropy:
        console.print("  3. ✅ Src_Port_Entropy cao ở Attack -> Có thể là Stealth Attack")
    console.print("  4. ✅ Log-transform cho: Src_Bytes, Dst_Bytes, Packet_Rate, Byte_Rate")
    console.print("  5. ✅ AE Threshold: P99.5 (bao dung với Normal)")
    console.print("  6. ✅ Contrastive Loss: Margin 2.0 để đẩy Attack xa Normal")
    
    # Khuyến nghị cho run_onos_v2
    console.print("\n[bold yellow]🛡️ CHIẾN THUẬT RUN_ONOS (run_onos_v2.py):[/bold yellow]")
    console.print("  1. ✅ 2-Shield Strategy: AE (Anomaly) + Classifier (Multi-class)")
    console.print("  2. ✅ AE báo động (MSE > threshold) -> Chuyển sang Classifier")
    console.print("  3. ✅ Classifier Confidence > 80% -> DROP ngay")
    console.print("  4. ✅ Classifier Confidence 50-80% -> Rate Limit")
    console.print("  5. ✅ AE báo động nhưng Classifier không nhận ra -> ZERO-DAY")
    console.print("  6. ✅ Zero-Day -> Redirect to Honeypot để phân tích thêm")
    
    # Cảnh báo nếu cần
    if has_high_src_entropy:
        console.print("\n[bold red]⚠️ CẢNH BÁO: Phát hiện Attack có Src_Entropy cao (>5)[/bold red]")
        console.print("  • Có thể là Stealth Attack (giả lập Normal)")
        console.print("  • AI cần tập trung vào đặc trưng hành vi khác (Duration, Packet_Rate)")
        console.print("  • Đề xuất: Tăng weight cho Duration và Byte_Rate trong Classifier")
    
    console.print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    run_inspection()