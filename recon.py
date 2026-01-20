import psutil
import os
import pwd
import grp
import platform
from pathlib import Path


class SystemRecon:
    """System reconnaissance for processes, network connections, and file scanning."""
    
    @staticmethod
    def scan_processes():
        """Scan and return information about running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
            try:
                pinfo = proc.info
                # Ensure numeric values are not None
                mem_percent = pinfo.get('memory_percent', 0)
                cpu_percent = pinfo.get('cpu_percent', 0)
                
                processes.append({
                    'pid': pinfo.get('pid', 0),
                    'name': pinfo.get('name', 'Unknown'),
                    'username': pinfo.get('username', 'Unknown'),
                    'memory_percent': mem_percent if mem_percent is not None else 0.0,
                    'cpu_percent': cpu_percent if cpu_percent is not None else 0.0
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception:
                pass
        
        # Sort by memory usage, handling None values
        processes.sort(key=lambda x: x.get('memory_percent', 0) or 0, reverse=True)
        return processes
    
    @staticmethod
    def scan_network_connections():
        """Scan active network connections."""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    
                    connections.append({
                        'local': local,
                        'remote': remote,
                        'status': conn.status if conn.status else 'UNKNOWN',
                        'pid': conn.pid if conn.pid else 0
                    })
                except (AttributeError, TypeError):
                    continue
                except Exception:
                    continue
        except psutil.AccessDenied:
            pass
        except Exception:
            pass
        
        return connections
    
    @staticmethod
    def scan_directory(path):
        """Scan a directory and return file count and total size."""
        try:
            directory = Path(path)
            if not directory.exists() or not directory.is_dir():
                return None
            
            total_size = 0
            count = 0
            
            for item in directory.rglob('*'):
                if item.is_file():
                    try:
                        total_size += item.stat().st_size
                        count += 1
                    except (PermissionError, FileNotFoundError):
                        continue
            
            return {
                'path': str(directory),
                'count': count,
                'total_size': total_size
            }
        except (PermissionError, FileNotFoundError):
            return None


class ServerRecon:
    """Server reconnaissance for user info, permissions, and network details."""
    
    @staticmethod
    def get_user_info():
        """Get current user information and permissions."""
        try:
            username = os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', 'unknown')
        except Exception:
            username = os.environ.get('USER', 'unknown')
        
        user_info = {
            'username': username,
            'uid': os.getuid() if hasattr(os, 'getuid') else 'N/A',
            'gid': os.getgid() if hasattr(os, 'getgid') else 'N/A',
            'home': os.path.expanduser('~'),
            'shell': os.environ.get('SHELL', 'N/A'),
            'is_root': os.getuid() == 0 if hasattr(os, 'getuid') else False,
            'groups': [],
            'primary_group': 'N/A'
        }
        
        # Get group information (Unix/Linux/Mac only)
        if platform.system() != 'Windows':
            try:
                user_info['primary_group'] = grp.getgrgid(os.getgid()).gr_name
                user_info['groups'] = [grp.getgrgid(gid).gr_name for gid in os.getgroups()]
            except (KeyError, AttributeError, OSError):
                pass
        
        return user_info
    
    @staticmethod
    def scan_listening_ports():
        """Scan for listening ports on the system."""
        listening = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.status == 'LISTEN' and conn.laddr:
                        listening.append({
                            'address': conn.laddr.ip if conn.laddr.ip else '0.0.0.0',
                            'port': conn.laddr.port if conn.laddr.port else 0,
                            'pid': conn.pid if conn.pid else 0,
                            'protocol': 'TCP'
                        })
                except (AttributeError, TypeError):
                    continue
                except Exception:
                    continue
        except psutil.AccessDenied:
            pass
        except Exception:
            pass
        
        return listening
    
    @staticmethod
    def scan_network_interfaces():
        """Get detailed network interface information."""
        interfaces = []
        
        try:
            # Get interface addresses
            addrs = psutil.net_if_addrs()
            # Get interface stats
            stats = psutil.net_if_stats()
            # Get IO counters
            try:
                io_counters = psutil.net_io_counters(pernic=True)
            except Exception:
                io_counters = {}
            
            for iface_name, iface_addrs in addrs.items():
                iface_info = {
                    'name': iface_name,
                    'is_up': False,
                    'speed': None,
                    'mtu': 0,
                    'addresses': []
                }
                
                # Get stats for this interface
                if iface_name in stats:
                    iface_info['is_up'] = stats[iface_name].isup
                    iface_info['speed'] = stats[iface_name].speed
                    iface_info['mtu'] = stats[iface_name].mtu
                
                # Get IO counters if available
                if iface_name in io_counters:
                    iface_info['bytes_sent'] = io_counters[iface_name].bytes_sent
                    iface_info['bytes_recv'] = io_counters[iface_name].bytes_recv
                    iface_info['packets_sent'] = io_counters[iface_name].packets_sent
                    iface_info['packets_recv'] = io_counters[iface_name].packets_recv
                
                # Process addresses
                for addr in iface_addrs:
                    addr_type = str(addr.family).split('.')[-1] if hasattr(addr.family, '__str__') else 'Unknown'
                    iface_info['addresses'].append({
                        'type': addr_type,
                        'address': addr.address if addr.address else 'N/A',
                        'netmask': addr.netmask if hasattr(addr, 'netmask') and addr.netmask else None
                    })
                
                interfaces.append(iface_info)
        except Exception:
            pass
        
        return interfaces
