#!/usr/bin/env python3
import os
import re
import matplotlib.pyplot as plt
import numpy as np

# Resolve paths
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
BENCH_DIR = os.path.dirname(SCRIPTS_DIR)
PERF_FILE = os.path.join(BENCH_DIR, "perf_results.md")
PROFILE_FILE = os.path.join(BENCH_DIR, "profile_results.md")
OUTPUT_DIR = BENCH_DIR

# Set styles for professional look
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica', 'sans-serif']
plt.rcParams['axes.edgecolor'] = '#E2E8F0'
plt.rcParams['axes.linewidth'] = 0.8

# Color Palette (Tailwind-inspired)
COLORS = {
    "system": "#718096",        # Cool Gray
    "bsan-system": "#3182CE",   # Blue
    "dlmalloc": "#DD6B20",      # Orange
    "bsan-dlmalloc": "#E53E3E", # Red
    "mimalloc": "#319795",      # Teal
    "bsan-mimalloc": "#38A169"  # Green
}

def parse_perf_results(filepath):
    if not os.path.exists(filepath):
        return {}
    with open(filepath, 'r') as f:
        content = f.read()
    
    sections = content.split("## Allocator Benchmark: ")
    data = {}
    
    for section in sections[1:]:
        section_content = section.split("##")[0]
        lines = section_content.split('\n')
        benchmark_name = lines[0].strip()
        
        # Find the table lines
        table_lines = []
        is_ms = False
        for line in lines[1:]:
            if line.strip().startswith('|'):
                if 'Mean [ms]' in line:
                    is_ms = True
                table_lines.append(line)
        
        if len(table_lines) < 3:
            continue
            
        benchmark_data = {}
        for row in table_lines[2:]:
            parts = [p.strip() for p in row.split('|')]
            if len(parts) < 6:
                continue
            cmd = parts[1].replace('`', '').strip()
            mean_part = parts[2].split('±')[0].strip()
            try:
                mean_val = float(mean_part)
                if is_ms:
                    mean_val = mean_val / 1000.0  # Normalize to seconds
                benchmark_data[cmd] = mean_val
            except ValueError:
                pass
        
        data[benchmark_name] = benchmark_data
    return data

def parse_behemoth_perf(filepath):
    if not os.path.exists(filepath):
        return {}
    with open(filepath, 'r') as f:
        content = f.read()
    
    sections = content.split("## Node Clearing Performance: ultimate_behemoth")
    if len(sections) < 2:
        return {}
    section_content = sections[1].split("##")[0]
    lines = section_content.split('\n')
    table_lines = [l for l in lines if l.strip().startswith('|')]
    if len(table_lines) < 3:
        return {}
    
    behemoth_data = {}
    for row in table_lines[2:]:
        parts = [p.strip() for p in row.split('|')]
        if len(parts) < 6:
            continue
        cmd = parts[1].replace('`', '').strip()
        mean_part = parts[2].split('±')[0].strip()
        try:
            mean_val = float(mean_part)
            behemoth_data[cmd] = mean_val
        except ValueError:
            pass
    return behemoth_data

def parse_profile_results(filepath):
    if not os.path.exists(filepath):
        return {}, {}
    with open(filepath, 'r') as f:
        content = f.read()
    
    sections = content.split("## Peak RSS by Program and Allocator (KB)")
    if len(sections) < 2:
        return {}, {}
    
    table_section = sections[1].split("##")[0]
    lines = table_section.split('\n')
    table_lines = [l for l in lines if l.strip().startswith('|')]
    if len(table_lines) < 3:
        return {}, {}
    
    headers = [h.replace('`', '').strip() for h in table_lines[0].split('|')[1:-1]]
    
    rss_data = {}
    for row in table_lines[2:]:
        if ':---' in row or row.strip() == '':
            continue
        parts = [p.strip() for p in row.split('|')[1:-1]]
        if len(parts) < 2:
            continue
        prog = parts[0]
        vals = {}
        for i, h in enumerate(headers[1:]):
            try:
                vals[h] = float(parts[i+1]) / 1024.0  # Normalize to MB
            except ValueError:
                vals[h] = None
        rss_data[prog] = vals
    
    behemoth_mem = {}
    mem_sections = content.split("## Node Clearing Memory Usage: ultimate_behemoth (KB)")
    if len(mem_sections) >= 2:
        mem_lines = mem_sections[1].split('\n')
        mem_table = [l for l in mem_lines if l.strip().startswith('|')]
        if len(mem_table) >= 3:
            row_parts = [p.strip() for p in mem_table[2].split('|')[1:-1]]
            if len(row_parts) >= 3:
                try:
                    behemoth_mem['clearing'] = float(row_parts[1]) / 1024.0
                    behemoth_mem['no-clearing'] = float(row_parts[2]) / 1024.0
                except ValueError:
                    pass
                    
    return rss_data, behemoth_mem

def main():
    print("Parsing benchmark results...")
    perf_data = parse_perf_results(PERF_FILE)
    behemoth_perf = parse_behemoth_perf(PERF_FILE)
    rss_data, behemoth_mem = parse_profile_results(PROFILE_FILE)

    if not perf_data or not rss_data:
        print("Error: Could not parse results. Make sure benchmark output files exist.")
        return

    benchmarks = list(perf_data.keys())
    configs = ["system", "bsan-system", "mimalloc", "bsan-mimalloc"]

    # ==========================================
    # CHART 1: Relative Runtime Performance (Normalized to system = 1.0)
    # ==========================================
    print("Generating Chart 1: Performance Comparison...")
    fig, ax = plt.subplots(figsize=(14, 7), dpi=300)
    
    x = np.arange(len(benchmarks))
    width = 0.18
    
    for idx, config in enumerate(configs):
        y_vals = []
        for bench in benchmarks:
            runtime = perf_data[bench].get(config, 1.0)
            base_runtime = perf_data[bench].get("system", 1.0)
            y_vals.append(runtime / base_runtime)
            
        ax.bar(x + (idx - 1.5) * width, y_vals, width, label=config, color=COLORS[config], edgecolor='none', alpha=0.9)
        
    ax.set_yscale('log')
    import matplotlib.ticker as ticker
    ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%g'))
    ax.set_yticks([0.5, 0.7, 1.0, 1.5, 2.0, 3.0])
    ax.axhline(1.0, color='#718096', linestyle='--', linewidth=0.8, alpha=0.7)
    ax.set_title("Relative Execution Time by Allocator Configuration (Log Scale, Lower is Better)\n[Note: dlmalloc excluded as it was 2-3.5x slower and skewed the scale]", fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel("Execution Time Relative to system (1.0)", fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels([b.replace('_', '\n') for b in benchmarks], fontsize=10)
    ax.legend(frameon=True, facecolor='white', edgecolor='#E2E8F0', framealpha=0.9, loc='upper left')
    plt.tight_layout()
    
    perf_path = os.path.join(OUTPUT_DIR, "perf_comparison_nodl.png")
    plt.savefig(perf_path)
    plt.close()
    print(f"Saved: {perf_path}")

    # ==========================================
    # CHART 2: Memory Footprint (Peak RSS in MB)
    # ==========================================
    print("Generating Chart 2: Memory Footprint...")
    fig, ax = plt.subplots(figsize=(14, 7), dpi=300)
    
    for idx, config in enumerate(configs):
        y_vals = []
        for bench in benchmarks:
            y_vals.append(rss_data[bench].get(config, 0))
            
        ax.bar(x + (idx - 1.5) * width, y_vals, width, label=config, color=COLORS[config], edgecolor='none', alpha=0.9)
        
    ax.set_yscale('log')
    ax.set_title("Peak Resident Set Size (Peak RSS) by Allocator Configuration (Log Scale)\n[Note: dlmalloc excluded to focus on system vs mimalloc]", fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel("Peak RSS (MB)", fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels([b.replace('_', '\n') for b in benchmarks], fontsize=10)
    
    # Custom ticks for log scale
    import matplotlib.ticker as ticker
    ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%g'))
    ax.set_yticks([10, 50, 100, 200, 500, 1000, 2000, 4000])
    
    ax.legend(frameon=True, facecolor='white', edgecolor='#E2E8F0', framealpha=0.9, loc='upper left')
    plt.tight_layout()
    
    mem_path = os.path.join(OUTPUT_DIR, "memory_comparison_nodl.png")
    plt.savefig(mem_path)
    plt.close()
    print(f"Saved: {mem_path}")

    # ==========================================
    # CHART 3: Node Clearing (GC) Impact on ultimate_behemoth
    # ==========================================
    if behemoth_perf and behemoth_mem:
        print("Generating Chart 3: Node Clearing Impact...")
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5.5), dpi=300)
        
        # Colors for clearing vs no-clearing
        gc_colors = ["#3182CE", "#E53E3E"]  # Blue for clearing, Red for no-clearing
        
        # Plot Time
        t_vals = [behemoth_perf.get("ultimate-behemoth-clearing", 0), behemoth_perf.get("ultimate-behemoth-no-clearing", 0)]
        labels = ["Clearing Enabled\n(BSAN_CLEAR_NODES=1)", "Clearing Disabled\n(BSAN_CLEAR_NODES=0)"]
        bars1 = ax1.bar(labels, t_vals, color=gc_colors, width=0.5, alpha=0.9)
        ax1.set_title("Execution Time Comparison (Lower is Better)", fontsize=11, fontweight='bold', pad=10)
        ax1.set_ylabel("Execution Time (Seconds)", fontsize=10)
        ax1.set_ylim(0, max(t_vals) * 1.25)
        
        # Add labels on top of bars
        for bar in bars1:
            yval = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2.0, yval + 0.05, f"{yval:.3f} s", ha='center', va='bottom', fontweight='bold', fontsize=10)

        # Plot Memory
        m_vals = [behemoth_mem.get('clearing', 0), behemoth_mem.get('no-clearing', 0)]
        bars2 = ax2.bar(labels, m_vals, color=gc_colors, width=0.5, alpha=0.9)
        ax2.set_title("Peak Resident Set Size (Lower is Better)", fontsize=11, fontweight='bold', pad=10)
        ax2.set_ylabel("Peak RSS (MB)", fontsize=10)
        ax2.set_ylim(0, max(m_vals) * 1.25)
        
        # Add labels on top of bars
        for bar in bars2:
            yval = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2.0, yval + 20, f"{yval:.1f} MB", ha='center', va='bottom', fontweight='bold', fontsize=10)
            
        fig.suptitle("Impact of Shadow Node Clearing (GC) on ultimate_behemoth", fontsize=14, fontweight='bold', y=0.98)
        plt.tight_layout()
        
        gc_path = os.path.join(OUTPUT_DIR, "node_clearing_impact_nodl.png")
        plt.savefig(gc_path)
        plt.close()
        print(f"Saved: {gc_path}")

if __name__ == "__main__":
    main()
