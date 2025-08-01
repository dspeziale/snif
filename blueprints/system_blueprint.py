from flask import Blueprint, jsonify
import psutil
import time
from datetime import datetime
import platform


def create_system_blueprint():
    system_bp = Blueprint('system', __name__)

    # Store startup time for uptime calculation
    startup_time = time.time()

    @system_bp.route('/status', methods=['GET'])
    def get_system_status():
        """Get comprehensive system status"""
        try:
            # Memory information
            memory = psutil.virtual_memory()

            # CPU information
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()

            # Disk information
            disk = psutil.disk_usage('/')

            # Network information (if available)
            try:
                network = psutil.net_io_counters()
                network_data = {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                }
            except:
                network_data = None

            # System uptime
            uptime_seconds = time.time() - startup_time
            uptime_hours = uptime_seconds // 3600
            uptime_minutes = (uptime_seconds % 3600) // 60

            # Process information
            process = psutil.Process()
            process_memory = process.memory_info()

            system_info = {
                'timestamp': datetime.now().isoformat(),
                'system': {
                    'platform': platform.system(),
                    'platform_release': platform.release(),
                    'platform_version': platform.version(),
                    'architecture': platform.machine(),
                    'processor': platform.processor(),
                    'python_version': platform.python_version()
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'free': memory.free,
                    'total_gb': round(memory.total / (1024 ** 3), 2),
                    'available_gb': round(memory.available / (1024 ** 3), 2),
                    'used_gb': round(memory.used / (1024 ** 3), 2)
                },
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.used / disk.total * 100,
                    'total_gb': round(disk.total / (1024 ** 3), 2),
                    'used_gb': round(disk.used / (1024 ** 3), 2),
                    'free_gb': round(disk.free / (1024 ** 3), 2)
                },
                'network': network_data,
                'uptime': {
                    'seconds': uptime_seconds,
                    'hours': uptime_hours,
                    'minutes': uptime_minutes,
                    'formatted': f"{int(uptime_hours)}h {int(uptime_minutes)}m"
                },
                'process': {
                    'pid': process.pid,
                    'memory_mb': round(process_memory.rss / (1024 ** 2), 2),
                    'memory_percent': process.memory_percent(),
                    'cpu_percent': process.cpu_percent(),
                    'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                    'num_threads': process.num_threads()
                }
            }

            return jsonify({
                'success': True,
                'data': system_info
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @system_bp.route('/health', methods=['GET'])
    def health_check():
        """Simple health check endpoint"""
        try:
            return jsonify({
                'success': True,
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'uptime_seconds': time.time() - startup_time
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'status': 'unhealthy',
                'error': str(e)
            }), 500

    @system_bp.route('/performance', methods=['GET'])
    def get_performance_metrics():
        """Get performance metrics"""
        try:
            # Get CPU usage over a short interval
            cpu_times = psutil.cpu_times_percent(interval=1)

            # Get load average (Unix-like systems only)
            try:
                load_avg = psutil.getloadavg()
            except AttributeError:
                load_avg = None

            # Get running processes count
            process_count = len(psutil.pids())

            performance_data = {
                'cpu': {
                    'user': cpu_times.user,
                    'system': cpu_times.system,
                    'idle': cpu_times.idle,
                    'load_average': load_avg
                },
                'processes': {
                    'count': process_count,
                    'running': len([p for p in psutil.process_iter(['status']) if p.info['status'] == 'running'])
                },
                'memory_pressure': {
                    'high': psutil.virtual_memory().percent > 85,
                    'medium': 70 < psutil.virtual_memory().percent <= 85,
                    'low': psutil.virtual_memory().percent <= 70
                }
            }

            return jsonify({
                'success': True,
                'data': performance_data
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return system_bp