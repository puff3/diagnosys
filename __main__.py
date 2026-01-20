#!/usr/bin/env python3

import psutil
import platform
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.prompt import Prompt
from rich import box
import time

console = Console()


class SystemDiagnostics:
    
    @staticmethod
    def get_cpu_info():
        cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
        cpu_freq = psutil.cpu_freq()
        return {
            'cores_physical': psutil.cpu_count(logical=False),
            'cores_logical': psutil.cpu_count(logical=True),
            'usage_per_core': cpu_percent,
            'usage_total': psutil.cpu_percent(interval=1),
            'frequency_current': cpu_freq.current if cpu_freq else 'N/A',
            'frequency_max': cpu_freq.max if cpu_freq else 'N/A'
        }
    
    @staticmethod
    def get_memory_info():
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            'total': mem.total,
            'available': mem.available,
            'used': mem.used,
            'percent': mem.percent,
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_percent': swap.percent
        }
    
    @staticmethod
    def get_disk_info():
        partitions = psutil.disk_partitions()
        disk_info = []
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent
                })
            except PermissionError:
                continue
        return disk_info
    
    @staticmethod
    def get_network_info():
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        net_info = []
        for interface, addrs in interfaces.items():
            info = {
                'interface': interface,
                'addresses': [],
                'is_up': stats[interface].isup if interface in stats else False
            }
            for addr in addrs:
                info['addresses'].append({
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask
                })
            net_info.append(info)
        return net_info


class SystemRecon:
    
    @staticmethod
    def scan_processes():
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(processes, key=lambda x: x.get('memory_percent', 0), reverse=True)[:20]
    
    @staticmethod
    def scan_directory(path):
        path_obj = Path(path)
        if not path_obj.exists():
            return None
        
        items = []
        total_size = 0
        for item in path_obj.iterdir():
            try:
                if item.is_file():
                    size = item.stat().st_size
                    total_size += size
                    items.append({
                        'name': item.name,
                        'type': 'file',
                        'size': size,
                        'modified': datetime.fromtimestamp(item.stat().st_mtime)
                    })
                elif item.is_dir():
                    items.append({
                        'name': item.name,
                        'type': 'dir',
                        'size': 0,
                        'modified': datetime.fromtimestamp(item.stat().st_mtime)
                    })
            except PermissionError:
                continue
        return {'items': items, 'total_size': total_size, 'count': len(items)}
    
    @staticmethod
    def scan_network_connections():
        connections = psutil.net_connections(kind='inet')
        active = []
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                active.append({
                    'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                    'status': conn.status,
                    'pid': conn.pid
                })
        return active[:20]


class DiagnosysTUI:
    
    def __init__(self):
        self.diagnostics = SystemDiagnostics()
        self.recon = SystemRecon()
        self.running = True
    
    def format_bytes(self, bytes_val):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    def show_header(self):
        header = Panel(
            f"[bold cyan]diagnosys[/bold cyan] - System Diagnostics & Reconnaissance\n"
            f"Host: {platform.node()} | OS: {platform.system()} {platform.release()} | "
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            box=box.DOUBLE
        )
        console.print(header)
    
    def show_cpu_diagnostics(self):
        cpu = self.diagnostics.get_cpu_info()
        table = Table(title="CPU Diagnostics", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Physical Cores", str(cpu['cores_physical']))
        table.add_row("Logical Cores", str(cpu['cores_logical']))
        table.add_row("Total Usage", f"{cpu['usage_total']}%")
        table.add_row("Current Frequency", f"{cpu['frequency_current']} MHz")
        
        console.print(table)
    
    def show_memory_diagnostics(self):
        mem = self.diagnostics.get_memory_info()
        table = Table(title="Memory Diagnostics", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Total", style="yellow")
        table.add_column("Used", style="red")
        table.add_column("Available", style="green")
        table.add_column("Usage %", style="magenta")
        
        table.add_row(
            "RAM",
            self.format_bytes(mem['total']),
            self.format_bytes(mem['used']),
            self.format_bytes(mem['available']),
            f"{mem['percent']}%"
        )
        table.add_row(
            "Swap",
            self.format_bytes(mem['swap_total']),
            self.format_bytes(mem['swap_used']),
            self.format_bytes(mem['swap_total'] - mem['swap_used']),
            f"{mem['swap_percent']}%"
        )
        
        console.print(table)
    
    def show_disk_diagnostics(self):
        disks = self.diagnostics.get_disk_info()
        table = Table(title="Disk Diagnostics", box=box.ROUNDED)
        table.add_column("Device", style="cyan")
        table.add_column("Mount", style="yellow")
        table.add_column("FS Type", style="blue")
        table.add_column("Total", style="green")
        table.add_column("Used", style="red")
        table.add_column("Free", style="green")
        table.add_column("Usage %", style="magenta")
        
        for disk in disks:
            table.add_row(
                disk['device'],
                disk['mountpoint'],
                disk['fstype'],
                self.format_bytes(disk['total']),
                self.format_bytes(disk['used']),
                self.format_bytes(disk['free']),
                f"{disk['percent']}%"
            )
        
        console.print(table)
    
    def show_process_recon(self):
        processes = self.recon.scan_processes()
        table = Table(title="Process Reconnaissance (Top 20 by Memory)", box=box.ROUNDED)
        table.add_column("PID", style="cyan")
        table.add_column("Name", style="yellow")
        table.add_column("User", style="blue")
        table.add_column("Memory %", style="red")
        table.add_column("CPU %", style="green")
        
        for proc in processes[:15]:
            table.add_row(
                str(proc.get('pid', 'N/A')),
                proc.get('name', 'N/A'),
                proc.get('username', 'N/A'),
                f"{proc.get('memory_percent', 0):.2f}%",
                f"{proc.get('cpu_percent', 0):.2f}%"
            )
        
        console.print(table)
    
    def show_network_recon(self):
        connections = self.recon.scan_network_connections()
        table = Table(title="Network Reconnaissance (Active Connections)", box=box.ROUNDED)
        table.add_column("Local Address", style="cyan")
        table.add_column("Remote Address", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("PID", style="magenta")
        
        for conn in connections[:15]:
            table.add_row(
                conn['local'],
                conn['remote'],
                conn['status'],
                str(conn.get('pid', 'N/A'))
            )
        
        console.print(table)
    
    def main_menu(self):
        console.clear()
        self.show_header()
        
        menu = Panel(
            "[1] System Diagnostics (Full)\n"
            "[2] CPU Diagnostics\n"
            "[3] Memory Diagnostics\n"
            "[4] Disk Diagnostics\n"
            "[5] Process Reconnaissance\n"
            "[6] Network Reconnaissance\n"
            "[7] Directory Scan\n"
            "[q] Quit",
            title="[bold yellow]Main Menu[/bold yellow]",
            box=box.ROUNDED
        )
        console.print(menu)
    
    def run(self):
        while self.running:
            try:
                self.main_menu()
                choice = Prompt.ask("\n[bold cyan]Select option[/bold cyan]", default="1")
                
                console.clear()
                self.show_header()
                
                if choice == '1':
                    self.show_cpu_diagnostics()
                    console.print()
                    self.show_memory_diagnostics()
                    console.print()
                    self.show_disk_diagnostics()
                elif choice == '2':
                    self.show_cpu_diagnostics()
                elif choice == '3':
                    self.show_memory_diagnostics()
                elif choice == '4':
                    self.show_disk_diagnostics()
                elif choice == '5':
                    self.show_process_recon()
                elif choice == '6':
                    self.show_network_recon()
                elif choice == '7':
                    path = Prompt.ask("[cyan]Enter directory path[/cyan]", default=".")
                    result = self.recon.scan_directory(path)
                    if result:
                        console.print(f"\n[green]Scanned {result['count']} items, "
                                    f"Total size: {self.format_bytes(result['total_size'])}[/green]")
                    else:
                        console.print("[red]Invalid path or permission denied[/red]")
                elif choice.lower() == 'q':
                    self.running = False
                    console.print("\n[yellow]Exiting diagnosys...[/yellow]")
                    break
                
                if choice != 'q':
                    Prompt.ask("\n[dim]Press Enter to continue[/dim]")
                    
            except KeyboardInterrupt:
                self.running = False
                console.print("\n\n[yellow]Interrupted. Exiting...[/yellow]")
                break
            except Exception as e:
                console.print(f"\n[red]Error: {str(e)}[/red]")
                Prompt.ask("\n[dim]Press Enter to continue[/dim]")


if __name__ == "__main__":
    app = DiagnosysTUI()
    app.run()
