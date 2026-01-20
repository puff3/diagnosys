import psutil
import platform
import subprocess
from datetime import datetime


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


class FirmwareDiagnostics:
    
    @staticmethod
    def get_firmware_info():
        system = platform.system()
        firmware_data = {
            'platform': system,
            'machine': platform.machine(),
            'processor': platform.processor(),
        }
        
        if system == 'Linux':
            try:
                result = subprocess.run(['dmidecode', '-t', 'bios'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    firmware_data['bios_output'] = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
                firmware_data['bios_output'] = 'Requires root privileges'
        
        elif system == 'Darwin':
            try:
                result = subprocess.run(['system_profiler', 'SPHardwareDataType'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    firmware_data['hardware_output'] = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                firmware_data['hardware_output'] = 'Not available'
        
        return firmware_data
    
    @staticmethod
    def get_software_inventory():
        system = platform.system()
        packages = []
        
        if system == 'Linux':
            package_managers = [
                (['dpkg', '-l'], 'dpkg'),
                (['rpm', '-qa'], 'rpm'),
                (['pacman', '-Q'], 'pacman'),
            ]
            
            for cmd, pm_type in package_managers:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        packages.append({
                            'manager': pm_type,
                            'count': len(result.stdout.strip().split('\n')),
                            'output': result.stdout[:1000]
                        })
                        break
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
        
        elif system == 'Darwin':
            try:
                result = subprocess.run(['brew', 'list'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    packages.append({
                        'manager': 'homebrew',
                        'count': len(result.stdout.strip().split('\n')),
                        'output': result.stdout[:1000]
                    })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        
        return packages
