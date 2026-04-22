# Tên file: ai_monitor.py
import time
import os
import json
import numpy as np
from rich.console import Console
from rich.live import Console as LiveConsole
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import BarColumn, Progress, TextColumn
from rich.live import Live

# Cấu hình đường dẫn (đã update cho config_v2)
FIFO_PATH = "zeek_stream.json"
CHECKPOINT_FILE = "ai/threshold_state.json"
CONFIG_PATH = "ai/"  # Path tới thư mục lưu models

console = Console()

def make_layout() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=3)
    )
    layout["main"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1)
    )
    return layout

class AIMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.stats = {
            "total_flows": 0,
            "attack_detected": 0,
            "zero_day": 0,
            "ips_active": 0,
            "current_threshold": 0.0,
            "last_mse": 0.0,
            "latency": 0.0
        }
        
    def update_stats(self):
        # Đọc thông tin từ checkpoint của run_onos.py
        if os.path.exists(CHECKPOINT_FILE):
            try:
                with open(CHECKPOINT_FILE, 'r') as f:
                    data = json.load(f)
                    self.stats["current_threshold"] = data.get("threshold", 0.0)
            except: pass

    def generate_header(self) -> Panel:
        return Panel(
            f"[bold cyan]Hệ Thống Giám Sát Hiệu Suất AI - SDN-IDS[/bold cyan] | "
            f"Uptime: {int(time.time() - self.start_time)}s",
            style="white on blue"
        )

    def generate_stats_table(self) -> Table:
        table = Table(title="📊 Thông Số Thời Gian Thực", expand=True)
        table.add_column("Chỉ số", style="cyan")
        table.add_column("Giá trị", style="bold green")
        
        table.add_row("Ngưỡng Dị Thường (Adaptive)", f"{self.stats['current_threshold']:.4f}")
        table.add_row("Số IP đang theo dõi", str(self.stats["ips_active"]))
        table.add_row("Tổng số luồng đã quét", f"{self.stats['total_flows']:,}")
        table.add_row("Tấn công đã chặn", f"[bold red]{self.stats['attack_detected']}[/bold red]")
        table.add_row("Biến thể Zero-day", f"[bold magenta]{self.stats['zero_day']}[/bold magenta]")
        
        return table

    def generate_model_health(self) -> Panel:
        # Giả lập thanh tiến trình cho độ tin cậy/tài nguyên
        progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        progress.add_task("[green]CPU Usage", completed=25)
        progress.add_task("[yellow]RAM Usage", completed=40)
        progress.add_task("[blue]GPU Inference", completed=15)
        
        return Panel(progress, title="🩺 Sức Khỏe Tài Nguyên")

    def run(self):
        layout = make_layout()
        with Live(layout, refresh_per_second=2, screen=True):
            while True:
                self.update_stats()
                layout["header"].update(self.generate_header())
                layout["left"].update(self.generate_stats_table())
                layout["right"].update(self.generate_model_health())
                layout["footer"].update(Panel("[dim]Nhấn Ctrl+C để thoát chế độ giám sát[/dim]"))
                time.sleep(0.5)

if __name__ == "__main__":
    try:
        monitor = AIMonitor()
        monitor.run()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Đã dừng giám sát.[/bold yellow]")
