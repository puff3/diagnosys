import psutil
import platform
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

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
    
    @staticmethod
    def get_boot_time():
        boot_timestamp = psutil.boot_time()
        boot_time = datetime.fromtimestamp(boot_timestamp)
        return {
            'boot_time': boot_time,
            'uptime': datetime.now() - boot_time
        }


class DiagnosysTUI:
    
    def __init__(self):
        self.diagnostics = SystemDiagnostics()
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
    
    def main_menu(self):
        console.clear()
        self.show_header()
        
        menu = Panel(
            "[1] System Diagnostics (Full)\n"
            "[2] CPU Diagnostics\n"
            "[3] Memory Diagnostics\n"
            "[4] Disk Diagnostics\n"
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


def main():
    app = DiagnosysTUI()
    app.run()


if __name__ == "__main__":
    main()
