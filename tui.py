import platform
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

from diagnosys.diagnostics import SystemDiagnostics, FirmwareDiagnostics
from diagnosys.recon import SystemRecon, ServerRecon

console = Console()


class DiagnosysTUI:
    
    def __init__(self):
        self.sys_diag = SystemDiagnostics()
        self.fw_diag = FirmwareDiagnostics()
        self.sys_recon = SystemRecon()
        self.srv_recon = ServerRecon()
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
        cpu = self.sys_diag.get_cpu_info()
        table = Table(title="CPU Diagnostics", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Physical Cores", str(cpu['cores_physical']))
        table.add_row("Logical Cores", str(cpu['cores_logical']))
        table.add_row("Total Usage", f"{cpu['usage_total']}%")
        table.add_row("Current Frequency", f"{cpu['frequency_current']} MHz")
        
        console.print(table)
    
    def show_memory_diagnostics(self):
        mem = self.sys_diag.get_memory_info()
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
        disks = self.sys_diag.get_disk_info()
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
    
    def show_firmware_diagnostics(self):
        fw = self.fw_diag.get_firmware_info()
        table = Table(title="Firmware & Hardware Info", box=box.ROUNDED)
        table.add_column("Component", style="cyan")
        table.add_column("Details", style="green")
        
        table.add_row("Platform", fw['platform'])
        table.add_row("Machine", fw['machine'])
        table.add_row("Processor", fw['processor'])
        
        console.print(table)
        
        if 'bios_output' in fw and fw['bios_output'] != 'Requires root privileges':
            console.print(Panel(fw['bios_output'][:500], title="BIOS Info (truncated)", border_style="dim"))
        elif 'hardware_output' in fw:
            console.print(Panel(fw['hardware_output'][:500], title="Hardware Info (truncated)", border_style="dim"))
    
    def show_software_inventory(self):
        packages = self.fw_diag.get_software_inventory()
        
        if not packages:
            console.print("[yellow]No package managers found or accessible[/yellow]")
            return
        
        table = Table(title="Software Inventory", box=box.ROUNDED)
        table.add_column("Package Manager", style="cyan")
        table.add_column("Package Count", style="green")
        
        for pkg in packages:
            table.add_row(pkg['manager'], str(pkg['count']))
        
        console.print(table)
    
    def show_process_recon(self):
        processes = self.sys_recon.scan_processes()
        table = Table(title="Process Reconnaissance (Top 20 by Memory)", box=box.ROUNDED)
        table.add_column("PID", style="cyan")
        table.add_column("Name", style="yellow")
        table.add_column("User", style="blue")
        table.add_column("Memory %", style="red")
        table.add_column("CPU %", style="green")
        
        for proc in processes[:15]:
            table.add_row(
                str(proc.get('pid', 'N/A')),
                proc.get('name', 'N/A')[:30],
                proc.get('username', 'N/A')[:15],
                f"{proc.get('memory_percent', 0):.2f}%",
                f"{proc.get('cpu_percent', 0):.2f}%"
            )
        
        console.print(table)
    
    def show_network_recon(self):
        connections = self.sys_recon.scan_network_connections()
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
    
    def show_server_recon(self):
        user_info = self.srv_recon.get_user_info()
        
        table = Table(title="Server User & Permissions Info", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Username", user_info['username'])
        table.add_row("UID", str(user_info['uid']))
        table.add_row("GID", str(user_info['gid']))
        table.add_row("Home Directory", user_info['home'])
        table.add_row("Shell", user_info['shell'])
        table.add_row("Primary Group", user_info['primary_group'])
        table.add_row("Is Root", "Yes" if user_info['is_root'] else "No")
        table.add_row("Groups", ", ".join(user_info['groups'][:5]))
        
        console.print(table)
        
        listening = self.srv_recon.scan_listening_ports()
        if listening:
            port_table = Table(title="Listening Ports", box=box.ROUNDED)
            port_table.add_column("Address", style="cyan")
            port_table.add_column("Port", style="yellow")
            port_table.add_column("PID", style="green")
            port_table.add_column("Protocol", style="magenta")
            
            for port in listening[:15]:
                port_table.add_row(
                    port['address'],
                    str(port['port']),
                    str(port.get('pid', 'N/A')),
                    port['protocol']
                )
            
            console.print()
            console.print(port_table)
    
    def show_network_interfaces_recon(self):
        interfaces = self.srv_recon.scan_network_interfaces()
        
        for iface in interfaces:
            table = Table(title=f"Interface: {iface['name']}", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Status", "Up" if iface['is_up'] else "Down")
            table.add_row("Speed", f"{iface['speed']} Mbps" if iface['speed'] else "N/A")
            table.add_row("MTU", str(iface['mtu']))
            
            if 'bytes_sent' in iface:
                table.add_row("Bytes Sent", self.format_bytes(iface['bytes_sent']))
                table.add_row("Bytes Received", self.format_bytes(iface['bytes_recv']))
                table.add_row("Packets Sent", str(iface['packets_sent']))
                table.add_row("Packets Received", str(iface['packets_recv']))
            
            for addr in iface['addresses']:
                table.add_row(f"{addr['type']} Address", addr['address'])
                if addr['netmask']:
                    table.add_row(f"{addr['type']} Netmask", addr['netmask'])
            
            console.print(table)
            console.print()
    
    def main_menu(self):
        console.clear()
        self.show_header()
        
        menu = Panel(
            "[bold yellow]DIAGNOSTICS[/bold yellow]\n"
            "[1] System Diagnostics (Full)\n"
            "[2] CPU Diagnostics\n"
            "[3] Memory Diagnostics\n"
            "[4] Disk Diagnostics\n"
            "[5] Firmware & Hardware Info\n"
            "[6] Software Inventory\n\n"
            "[bold yellow]RECONNAISSANCE[/bold yellow]\n"
            "[7] Process Reconnaissance\n"
            "[8] Network Connections\n"
            "[9] Directory Scan\n\n"
            "[bold yellow]SERVER RECON[/bold yellow]\n"
            "[10] Server User & Permissions\n"
            "[11] Network Interfaces Detail\n\n"
            "[q] Quit",
            title="[bold cyan]Main Menu[/bold cyan]",
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
                    self.show_firmware_diagnostics()
                elif choice == '6':
                    self.show_software_inventory()
                elif choice == '7':
                    self.show_process_recon()
                elif choice == '8':
                    self.show_network_recon()
                elif choice == '9':
                    path = Prompt.ask("[cyan]Enter directory path[/cyan]", default=".")
                    result = self.sys_recon.scan_directory(path)
                    if result:
                        console.print(f"\n[green]Scanned {result['count']} items, "
                                    f"Total size: {self.format_bytes(result['total_size'])}[/green]")
                    else:
                        console.print("[red]Invalid path or permission denied[/red]")
                elif choice == '10':
                    self.show_server_recon()
                elif choice == '11':
                    self.show_network_interfaces_recon()
                elif choice.lower() == 'q':
                    self.running = False
                    console.print("\n[yellow]Exiting diagnosys...[/yellow]")
                    break
                else:
                    console.print("[red]Invalid option[/red]")
                
                if choice.lower() != 'q':
                    Prompt.ask("\n[dim]Press Enter to continue[/dim]")
                    
            except KeyboardInterrupt:
                self.running = False
                console.print("\n\n[yellow]Interrupted. Exiting...[/yellow]")
                break
            except Exception as e:
                console.print(f"\n[red]Error: {str(e)}[/red]")
                Prompt.ask("\n[dim]Press Enter to continue[/dim]")
