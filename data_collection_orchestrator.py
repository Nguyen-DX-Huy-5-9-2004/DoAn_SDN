#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
 🎯 DATA COLLECTION ORCHESTRATOR - TỐI ƯU FULL PIPELINE
═══════════════════════════════════════════════════════════════════════════════

CHIẾN LƯỢC TỐI ƯU:
  ✅ Capture interface: s6-eth1 (backbone, 99.7% filter pass)
  ✅ Filter bidirectional: Nhận cả REQUEST + RESPONSE flows
  ✅ Thứ tự ATTACK trước → NORMAL sau (kiểm soát tốt, flexible timing)

PHASES:
  Phase 1: UDP Flood (h1-h4)      →  10 min  →  ~80K samples
  Phase 2: SYN Flood (h6-h10)     →  10 min  →  ~80K samples  
  Phase 3: HTTP Flood (h11-h14)   →  10 min  →  ~80K samples
  Phase 4: Slowloris (h16-h20)    →  10 min  →  ~80K samples
  Phase 0: Normal (h60-h65)       →  50 min  →  ~80K samples
  
TOTAL: ~3 hours, ~400K samples ✅

═══════════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import time
import subprocess
import json
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════

PHASES = {
    1: {
        "name": "UDP Flood",
        "hosts": list(range(1, 5)),          # h1-h4
        "attack_type": "attack/udp_flood.py",
        "duration_minutes": 10,
        "target_samples": 80000,
        "description": "UDP flood attack from 4 botnet nodes"
    },
    2: {
        "name": "SYN Flood",
        "hosts": list(range(6, 11)),         # h6-h10
        "attack_type": "attack/syn_flood.py",
        "duration_minutes": 10,
        "target_samples": 80000,
        "description": "SYN flood attack from 5 botnet nodes"
    },
    3: {
        "name": "HTTP Flood",
        "hosts": list(range(11, 15)),        # h11-h14
        "attack_type": "attack/http_flood.py",
        "duration_minutes": 10,
        "target_samples": 80000,
        "description": "HTTP flood attack from 4 botnet nodes"
    },
    4: {
        "name": "Slowloris",
        "hosts": list(range(16, 21)),        # h16-h20
        "attack_type": "attack/slowloris.py",
        "duration_minutes": 10,
        "target_samples": 80000,
        "description": "Slowloris attack from 5 botnet nodes"
    },
    0: {
        "name": "Normal",
        "hosts": list(range(60, 66)),        # h60-h65
        "attack_type": "traffic/normal.py",
        "duration_minutes": 50,
        "target_samples": 80000,
        "description": "Normal traffic from 6 legitimate clients"
    }
}

CAPTURE_INTERFACE = "s6-eth1"      # 🎯 Optimal capture point
CAPTURE_INTERFACE_ALIAS = "eth1"   # Alternative if s6-eth1 not available
SERVICE_IP = "10.0.0.10"           # web1 service
SERVICE_PORT = 8000

WORK_DIR = Path("/home/tgf/Documents/DoAn_SDN/thuThapData")
CAPTURE_SCRIPT = Path("/home/tgf/Documents/DoAn_SDN/thuThapData/batPack123.py")
GENERATOR_SCRIPT = Path("/home/tgf/Documents/DoAn_SDN/thuThapData/auto_dataset_generator.py")

# ═══════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*80)
    print(f"  🎯 {text}")
    print("="*80)

def print_step(step_num, text):
    """Print formatted step"""
    print(f"\n  📍 [{step_num}] {text}")

def print_info(text):
    """Print info message"""
    print(f"  ℹ️  {text}")

def print_warn(text):
    """Print warning message"""
    print(f"  ⚠️  {text}")

def print_success(text):
    """Print success message"""
    print(f"  ✅ {text}")

def print_cmd(text):
    """Print command to copy"""
    print(f"\n  📋 Copy to Mininet (containernet>):")
    print(f"     \033[92m{text}\033[0m")

def generate_attack_cmd(phase_num):
    """Generate attack command for a phase"""
    phase = PHASES[phase_num]
    hosts = phase["hosts"]
    script = phase["attack_type"]
    
    # Generate commands for each host
    cmds = []
    for h in hosts:
        cmds.append(f"net.get('h{h}').cmd('cd /home/tgf/Documents/DoAn_SDN && python3 {script} {SERVICE_IP} &')")
    
    return f"py [{'; '.join(cmds)}]"

def generate_normal_cmd():
    """Generate normal traffic command"""
    hosts = PHASES[0]["hosts"]
    cmds = []
    for h in hosts:
        url = f"http://{SERVICE_IP}:{SERVICE_PORT}"
        cmds.append(f"net.get('h{h}').cmd('cd /home/tgf/Documents/DoAn_SDN && python3 traffic/normal.py {url} &')")
    
    return f"py [{'; '.join(cmds)}]"

def print_phase_plan():
    """Print full collection plan"""
    print_header("📋 FULL DATA COLLECTION PLAN")
    
    total_samples = 0
    total_time = 0
    
    print("\n  EXECUTION ORDER (OPTIMIZED):\n")
    
    # Print attack phases
    for phase_num in [1, 2, 3, 4]:
        phase = PHASES[phase_num]
        print(f"  ▶️  PHASE {phase_num}: {phase['name']}")
        print(f"      • Hosts: h{phase['hosts'][0]}-h{phase['hosts'][-1]} ({len(phase['hosts'])} nodes)")
        print(f"      • Duration: {phase['duration_minutes']} min")
        print(f"      • Target: {phase['target_samples']:,} samples")
        print(f"      • Description: {phase['description']}")
        print()
        
        total_samples += phase['target_samples']
        total_time += phase['duration_minutes']
    
    # Print normal phase
    phase = PHASES[0]
    print(f"  ▶️  PHASE 0: {phase['name']} (collected LAST)")
    print(f"      • Hosts: h{phase['hosts'][0]}-h{phase['hosts'][-1]} ({len(phase['hosts'])} nodes)")
    print(f"      • Duration: {phase['duration_minutes']} min")
    print(f"      • Target: {phase['target_samples']:,} samples")
    print(f"      • Description: {phase['description']}")
    print()
    
    total_samples += phase['target_samples']
    total_time += phase['duration_minutes']
    
    print(f"  📊 TOTAL: {total_samples:,} samples in ~{total_time} minutes (~{total_time/60:.1f} hours)")
    print(f"  📍 Capture interface: {CAPTURE_INTERFACE}")
    print(f"  🎯 Filter: Bidirectional (REQUEST + RESPONSE)")
    print(f"  💾 Output: master_dataset_v6.csv\n")

def print_terminal_setup():
    """Print how to setup terminals"""
    print_header("🖥️  TERMINAL SETUP (3 terminals needed)")
    
    print_step(1, "Terminal 1 (Packet Capture)")
    print_info("Start packet capture on s6-eth1")
    print_cmd(f"cd {WORK_DIR} && sudo {sys.executable} {CAPTURE_SCRIPT}")
    
    print_step(2, "Terminal 2 (Flow Processing)")
    print_info("Start flow processing & CSV generation")
    print_cmd(f"cd {WORK_DIR} && sudo {sys.executable} {GENERATOR_SCRIPT}")
    
    print_step(3, "Terminal 3 (Mininet CLI - commands)")
    print_info("Execute attack/normal commands in Mininet CLI")

def print_phase_instructions(phase_num):
    """Print instructions for a specific phase"""
    phase = PHASES[phase_num]
    
    print_header(f"PHASE {phase_num}: {phase['name'].upper()}")
    
    print_step(1, "Stop previous traffic")
    print_cmd("py [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(1, 21)] + [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(60, 66)]")
    print_info("Wait 2 seconds for cleanup")
    
    print_step(2, f"Start {phase['name']} traffic")
    if phase_num == 0:
        cmd = generate_normal_cmd()
    else:
        cmd = generate_attack_cmd(phase_num)
    print_cmd(cmd)
    
    print_step(3, f"Let traffic run for {phase['duration_minutes']} minutes")
    print_info(f"Monitor flow statistics in Terminal 2")
    print_info(f"Expected: ~{phase['target_samples']/phase['duration_minutes']:.0f} samples/min")
    
    print_step(4, "After timer expires")
    print_info("Check master_dataset_v6.csv for accumulated samples")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    clear_screen = lambda: os.system('clear')
    clear_screen()
    
    print_phase_plan()
    print_terminal_setup()
    
    print_header("EXECUTION SEQUENCE")
    
    print("\n  Step 1️⃣ : Open 3 terminals and run capture/generator as shown above")
    print("  Step 2️⃣ : Follow phase instructions below")
    print("  Step 3️⃣ : Monitor progress in Terminal 2\n")
    
    # Print all phase instructions
    for phase_num in [1, 2, 3, 4, 0]:
        phase = PHASES[phase_num]
        print("\n" + "-"*80)
        print_phase_instructions(phase_num)
        if phase_num < 4:
            print(f"\n  ⏱️  After Phase {phase_num}: Wait ~{phase['duration_minutes']} min, then move to Phase {[1,2,3,4,0][[1,2,3,4].index(phase_num)+1]}")
        else:
            print(f"\n  ⏱️  After Phase 4: Continue to PHASE 0 (Normal) for final ~50 min")
    
    print("\n" + "="*80)
    print("  ✅ FINAL RESULT: master_dataset_v6.csv with ~400K samples")
    print("     Rows: 5 classes × 80K samples/class = 400K rows")
    print("     Cols: 13 features + 1 label = 14 columns")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
