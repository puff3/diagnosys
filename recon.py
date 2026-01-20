import psutil
import socket
import subprocess
import os
import pwd
import grp
from pathlib import Path
from datetime import datetime


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


class ServerRecon:
    
    @staticmethod
    def get_user_info():
        current_user = os.getlogin() if hasattr(os, 'getlogin') else 'unknown'
        uid = os.getuid()
        gid = os.getgid()
        
        try:
            user_info = pwd.getpwuid(uid)
            group_info = grp.getgrgid(gid)
            groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        except KeyError:
            user_info = None
            group_info = None
            groups = []
        
        return {
            'username': current_user,
            'uid': uid,
            'gid': gid,
            'home': user_info.pw_dir if user_info else 'N/A',
            'shell': user_info.pw_shell if user_info else 'N/A',
            'primary_group': group_info.gr_name if group_info else 'N/A',
            'groups': groups,
            'is_root': uid == 0
        }
    
    @staticmethod
    def scan_file_permissions(path):
        path_obj = Path(path)
        if not path_obj.exists():
            return None
        
        permissions = []
        for item in path_obj.rglob('*'):
            try:
                stat_info = item.stat()
                permissions.append({
                    'path': str(item),
                    'mode': oct(stat_info.st_mode)[-3:],
                    'owner_uid': stat_info.st_uid,
                    'group_gid': stat_info.st_gid,
                    'size': stat_info.st_size if item.is_file() else 0
                })
                if len(permissions) >= 100:
                    break
            except (PermissionError, OSError):
                continue
        
        return permissions
    
    @staticmethod
    def scan_listening_ports():
        connections = psutil.net_connections(kind='inet')
        listening = []
        
        for conn in connections:
            if conn.status == 'LISTEN':
                listening.append({
                    'address': conn.laddr.ip,
                    'port': conn.laddr.port,
                    'pid': conn.pid,
                    'protocol': 'TCP'
                })
        
        return listening
    
    @staticmethod
    def scan_network_interfaces():
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)
        
        interface_data = []
        for iface, addrs in interfaces.items():
            iface_info = {
                'name': iface,
                'is_up': stats[iface].isup if iface in stats else False,
                'speed': stats[iface].speed if iface in stats else 0,
                'mtu': stats[iface].mtu if iface in stats else 0,
                'addresses': []
            }
            
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    iface_info['addresses'].append({
                        'type': 'IPv4',
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                elif addr.family == socket.AF_INET6:
                    iface_info['addresses'].append({
                        'type': 'IPv6',
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
            
            if iface in io_counters:
                io = io_counters[iface]
                iface_info['bytes_sent'] = io.bytes_sent
                iface_info['bytes_recv'] = io.bytes_recv
                iface_info['packets_sent'] = io.packets_sent
                iface_info['packets_recv'] = io.packets_recv
            
            interface_data.append(iface_info)
        
        return interface_data
    
    @staticmethod
    def get_sudo_privileges():
        try:
            result = subprocess.run(['sudo', '-n', 'true'], 
                                  capture_output=True, timeout=2)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
