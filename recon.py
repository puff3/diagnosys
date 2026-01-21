import platform
import threading
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.live import Live
from rich.layout import Layout
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
        self.current_view = '1'
        self.refresh_interval = 2  # seconds
        self.lock = threading.Lock()
    
    def format_bytes(self, bytes_val):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    def get_header(self):
        return Panel(
            f"[bold cyan]diagnosys[/bold cyan] - System Diagnostics & Reconnaissance\n"
            f"Host: {platform.node()} | OS: {platform.system()} {platform.release()} | "
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[dim]Refreshing every {self.refresh_interval}s | Press Ctrl+C to change view[/dim]",
            box=box.DOUBLE
        )
    
    def get_cpu_diagnostics(self):
        cpu = self.sys_diag.get_cpu_info()
        table = Table(title="CPU Diagnostics", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Physical Cores", str(cpu['cores_physical']))
        table.add_row("Logical Cores", str(cpu['cores_logical']))
        table.add_row("Total Usage", f"{cpu['usage_total']}%")
        table.add_row("Current Frequency", f"{cpu['frequency_current']} MHz")
        
        # Add per-core usage
        for i, usage in enumerate(cpu['usage_per_core']):
            table.add_row(f"Core {i} Usage", f"{usage}%")
        
        return table
    
    def get_memory_diagnostics(self):
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
        
        return table
    
    def get_disk_diagnostics(self):
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
        
        return table
    
    def get_process_recon(self):
        processes = self.sys_recon.scan_processes()
        table = Table(title="Process Reconnaissance (Top 20 by Memory)", box=box.ROUNDED)
        table.add_column("PID", style="cyan")
        table.add_column("Name", style="yellow")
        table.add_column("User", style="blue")
        table.add_column("Memory %", style="red")
        table.add_column("CPU %", style="green")
        
        for proc in processes[:20]:
            table.add_row(
                str(proc.get('pid', 'N/A')),
                proc.get('name', 'N/A')[:30],
                proc.get('username', 'N/A')[:15],
                f"{proc.get('memory_percent', 0):.2f}%",
                f"{proc.get('cpu_percent', 0):.2f}%"
            )
        
        return table
    
    def get_network_recon(self):
        connections = self.sys_recon.scan_network_connections()
        
        table = Table(title="Network Connections (Active)", box=box.ROUNDED)
        table.add_column("Local Address", style="cyan")
        table.add_column("Remote Address", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("PID", style="magenta")
        
        if not connections:
            table.add_row("No connections found", "", "", "")
            table.caption = "[dim]Note: On macOS, run with sudo to see all connections[/dim]"
        else:
            for conn in connections[:20]:
                table.add_row(
                    conn['local'],
                    conn['remote'],
                    conn['status'],
                    str(conn.get('pid', 'N/A'))
                )
        
        return table
    
    def get_network_stats(self):
        """Get network I/O statistics."""
        io_counters = self.srv_recon.get_network_io_stats()
        
        table = Table(title="Network I/O Statistics", box=box.ROUNDED)
        table.add_column("Interface", style="cyan")
        table.add_column("Bytes Sent", style="yellow")
        table.add_column("Bytes Recv", style="green")
        table.add_column("Packets Sent", style="blue")
        table.add_column("Packets Recv", style="magenta")
        table.add_column("Errors In", style="red")
        table.add_column("Errors Out", style="red")
        
        for stat in io_counters[:10]:
            table.add_row(
                stat['interface'],
                self.format_bytes(stat['bytes_sent']),
                self.format_bytes(stat['bytes_recv']),
                str(stat['packets_sent']),
                str(stat['packets_recv']),
                str(stat['errin']),
                str(stat['errout'])
            )
        
        return table
    
    def get_connection_summary(self):
        """Get connection summary by status."""
        summary = self.srv_recon.get_connection_summary()
        
        table = Table(title="Connection Summary by Status", box=box.ROUNDED)
        table.add_column("Status", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Protocol", style="yellow")
        
        for item in summary:
            table.add_row(
                item['status'],
                str(item['count']),
                item['protocol']
            )
        
        return table
    
    def get_listening_ports(self):
        listening = self.srv_recon.scan_listening_ports()
        
        table = Table(title="Listening Ports", box=box.ROUNDED)
        table.add_column("Address", style="cyan")
        table.add_column("Port", style="yellow")
        table.add_column("PID", style="green")
        table.add_column("Protocol", style="magenta")
        table.add_column("Process Name", style="blue")
        
        if not listening:
            table.add_row("No listening ports found", "", "", "", "")
        else:
            for port in listening[:20]:
                table.add_row(
                    port['address'],
                    str(port['port']),
                    str(port.get('pid', 'N/A')),
                    port['protocol'],
                    port.get('process_name', 'N/A')[:25]
                )
        
        return table
    
    def get_external_connections(self):
        """Get external (non-local) connections."""
        external = self.srv_recon.get_external_connections()
        
        table = Table(title="External Connections", box=box.ROUNDED)
        table.add_column("Remote IP", style="cyan")
        table.add_column("Remote Port", style="yellow")
        table.add_column("Local Port", style="blue")
        table.add_column("Status", style="green")
        table.add_column("Process", style="magenta")
        
        if not external:
            table.add_row("No external connections", "", "", "", "")
        else:
            for conn in external[:15]:
                table.add_row(
                    conn['remote_ip'],
                    str(conn['remote_port']),
                    str(conn['local_port']),
                    conn['status'],
                    conn.get('process_name', 'N/A')[:20]
                )
        
        return table
    
    def get_network_interfaces(self):
        interfaces = self.srv_recon.scan_network_interfaces()
        
        output = []
        for iface in interfaces[:5]:  # Limit to 5 interfaces
            table = Table(title=f"Interface: {iface['name']}", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Status", "Up" if iface['is_up'] else "Down")
            table.add_row("Speed", f"{iface['speed']} Mbps" if iface['speed'] else "N/A")
            table.add_row("MTU", str(iface['mtu']))
            
            if 'bytes_sent' in iface:
                table.add_row("Bytes Sent", self.format_bytes(iface['bytes_sent']))
                table.add_row("Bytes Received", self.format_bytes(iface['bytes_recv']))
            
            for addr in iface['addresses'][:3]:  # Limit addresses
                table.add_row(f"{addr['type']} Address", addr['address'])
            
            output.append(table)
        
        return output
    
    def get_server_recon(self):
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
        
        return table
    
    def generate_view(self):
        """Generate the current view based on selected option."""
        with self.lock:
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=5),
                Layout(name="body")
            )
            
            layout["header"].update(self.get_header())
            
            if self.current_view == '1':  # Full system diagnostics
                body_layout = Layout()
                body_layout.split_column(
                    Layout(self.get_cpu_diagnostics()),
                    Layout(self.get_memory_diagnostics()),
                    Layout(self.get_disk_diagnostics())
                )
                layout["body"].update(body_layout)
                
            elif self.current_view == '2':  # Processes
                layout["body"].update(self.get_process_recon())
                
            elif self.current_view == '3':  # Network connections
                layout["body"].update(self.get_network_recon())
            
            elif self.current_view == '4':  # Advanced network recon
                body_layout = Layout()
                body_layout.split_column(
                    Layout(self.get_connection_summary()),
                    Layout(self.get_network_stats()),
                    Layout(self.get_external_connections())
                )
                layout["body"].update(body_layout)
                
            elif self.current_view == '5':  # Server info
                body_layout = Layout()
                body_layout.split_column(
                    Layout(self.get_server_recon()),
                    Layout(self.get_listening_ports())
                )
                layout["body"].update(body_layout)
                
            elif self.current_view == '6':  # Network interfaces
                interfaces = self.get_network_interfaces()
                if interfaces:
                    layout["body"].update(interfaces[0])
                
            return layout
    
    def show_menu(self):
        """Show the menu and get user selection."""
        console.clear()
        console.print(self.get_header())
        
        menu = Panel(
            "[bold yellow]DIAGNOSTICS[/bold yellow]\n"
            "[1] System Diagnostics (Full)\n"
            "[2] Process Reconnaissance\n"
            "[3] Network Connections\n"
            "[4] Advanced Network Reconnaissance\n"
            "[5] Server User & Permissions\n"
            "[6] Network Interfaces Detail\n\n"
            "[bold yellow]STATIC VIEWS[/bold yellow]\n"
            "[7] Firmware & Hardware Info\n"
            "[8] Software Inventory\n"
            "[9] Directory Scan\n\n"
            "[q] Quit",
            title="[bold cyan]Main Menu[/bold cyan]",
            box=box.ROUNDED
        )
        console.print(menu)
        
        choice = Prompt.ask("\n[bold cyan]Select option[/bold cyan]", default="1")
        return choice
    
    def run_auto_refresh_view(self, view):
        """Run a view with auto-refresh."""
        self.current_view = view
        
        try:
            with Live(self.generate_view(), refresh_per_second=0.5, console=console) as live:
                while self.running:
                    time.sleep(self.refresh_interval)
                    live.update(self.generate_view())
        except KeyboardInterrupt:
            pass
    
    def run(self):
        """Main run loop."""
        while self.running:
            try:
                choice = self.show_menu()
                
                if choice.lower() == 'q':
                    self.running = False
                    console.print("\n[yellow]Exiting diagnosys...[/yellow]")
                    break
                
                # Auto-refreshing views
                if choice in ['1', '2', '3', '4', '5', '6']:
                    console.clear()
                    self.run_auto_refresh_view(choice)
                
                # Static views
                elif choice == '7':
                    console.clear()
                    console.print(self.get_header())
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
                    
                    Prompt.ask("\n[dim]Press Enter to continue[/dim]")
                
                elif choice == '8':
                    console.clear()
                    console.print(self.get_header())
                    packages = self.fw_diag.get_software_inventory()
                    
                    if not packages:
                        console.print("[yellow]No package managers found or accessible[/yellow]")
                    else:
                        table = Table(title="Software Inventory", box=box.ROUNDED)
                        table.add_column("Package Manager", style="cyan")
                        table.add_column("Package Count", style="green")
                        
                        for pkg in packages:
                            table.add_row(pkg['manager'], str(pkg['count']))
                        
                        console.print(table)
                    
                    Prompt.ask("\n[dim]Press Enter to continue[/dim]")
                
                elif choice == '9':
                    console.clear()
                    console.print(self.get_header())
                    path = Prompt.ask("[cyan]Enter directory path[/cyan]", default=".")
                    result = self.sys_recon.scan_directory(path)
                    if result:
                        console.print(f"\n[green]Scanned {result['count']} items, "
                                    f"Total size: {self.format_bytes(result['total_size'])}[/green]")
                    else:
                        console.print("[red]Invalid path or permission denied[/red]")
                    
                    Prompt.ask("\n[dim]Press Enter to continue[/dim]")
                
                else:
                    console.print("[red]Invalid option[/red]")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                continue
            except Exception as e:
                console.print(f"\n[red]Error: {str(e)}[/red]")
                Prompt.ask("\n[dim]Press Enter to continue[/dim]")
