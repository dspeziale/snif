# scanner/windows_setup.py - Windows-specific setup and fixes
import os
import sys
import subprocess
import platform
import json
import ctypes
from pathlib import Path


class WindowsScannerSetup:
    """Windows-specific setup and configuration for the network scanner"""

    def __init__(self):
        self.is_admin = self.is_running_as_admin()
        self.nmap_path = self.find_nmap_installation()

    def is_running_as_admin(self):
        """Check if running as administrator"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def find_nmap_installation(self):
        """Find nmap installation on Windows"""
        # Common installation paths
        common_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Tools\nmap\nmap.exe",
            r"C:\nmap\nmap.exe"
        ]

        # Check if nmap is in PATH
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True)
            if result.returncode == 0:
                return 'nmap'
        except:
            pass

        # Check common installation paths
        for path in common_paths:
            if os.path.exists(path):
                return path

        return None

    def create_optimized_config(self):
        """Create Windows-optimized configuration"""
        config = {
            "network": {
                "scan_range": self.detect_local_networks(),
                "timeout": 300,
                "single_range_timeout": 120,
                "max_retries": 2,
                "parallel_scans": 2,  # Conservative for Windows
                "auto_detect_local_networks": True
            },
            "nmap": {
                "path": self.nmap_path or "nmap",
                "discovery_args": "-sn -PE -PS80,443,22",  # Simplified for Windows
                "services_args": "-sS -sV --version-intensity 3",
                "vuln_args": "--script vuln",
                "snmp_args": "-sU -p 161 --script snmp-info",
                "timing": "2",  # Conservative timing for Windows
                "windows_safe_mode": True,
                "max_host_timeout": "60s",
                "max_scan_delay": "20ms"
            },
            "snmp": {
                "community_strings": ["public", "private", "community"],
                "version": "2c",
                "timeout": 10,  # Longer timeout for Windows
                "retries": 1
            },
            "database": {
                "path": "data/network_scanner.db"
            },
            "cache": {
                "oui_url": "http://standards-oui.ieee.org/oui/oui.txt",
                "nvd_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "update_interval_days": 30
            },
            "scanning": {
                "discovery_interval_minutes": 15,
                "services_scan_delay_hours": 2,
                "os_scan_delay_hours": 4,
                "vuln_scan_delay_hours": 8,
                "snmp_scan_delay_hours": 6
            },
            "logging": {
                "level": "INFO",
                "file": "scanner/log/scanner.log",
                "max_file_size": 10485760,
                "backup_count": 5
            },
            "windows": {
                "use_safe_mode": True,
                "disable_rst_ratelimit": False,  # Causes issues on Windows
                "prefer_icmp_ping": True,
                "encoding": "utf-8"
            }
        }

        return config

    def detect_local_networks(self):
        """Detect local networks on Windows"""
        networks = []

        try:
            # Use ipconfig to get network information
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode == 0:
                networks = self.parse_ipconfig_output(result.stdout)
        except Exception as e:
            print(f"Error detecting networks: {e}")

        # Add common default networks if none found
        if not networks:
            networks = [
                "192.168.1.0/24",
                "192.168.0.0/24",
                "10.0.0.0/24"
            ]

        return networks

    def parse_ipconfig_output(self, output):
        """Parse ipconfig output to extract network ranges"""
        networks = []
        import re
        import ipaddress

        # Look for IPv4 addresses
        ip_pattern = r'IPv4.*?(\d+\.\d+\.\d+\.\d+)'
        subnet_pattern = r'Subnet Mask.*?(\d+\.\d+\.\d+\.\d+)'

        lines = output.split('\n')
        current_ip = None

        for i, line in enumerate(lines):
            # Find IPv4 address
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)

                # Skip loopback
                if ip.startswith('127.'):
                    continue

                # Look for subnet mask in next few lines
                subnet_mask = '255.255.255.0'  # Default assumption
                for j in range(i + 1, min(i + 5, len(lines))):
                    mask_match = re.search(subnet_pattern, lines[j])
                    if mask_match:
                        subnet_mask = mask_match.group(1)
                        break

                try:
                    # Calculate network
                    ip_obj = ipaddress.IPv4Address(ip)
                    if ip_obj.is_private:
                        # Convert subnet mask to CIDR
                        mask_obj = ipaddress.IPv4Address(subnet_mask)
                        cidr = sum(bin(int(x)).count('1') for x in str(mask_obj).split('.'))

                        network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
                        network_str = str(network)

                        if network_str not in networks:
                            networks.append(network_str)

                except Exception as e:
                    print(f"Error processing IP {ip}: {e}")

        return networks

    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            'scanner/xml',
            'scanner/log',
            'scanner/reports',
            'data',
            'scanner/templates'
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"✓ Created directory: {directory}")

    def create_windows_config_file(self):
        """Create Windows-optimized config file"""
        config = self.create_optimized_config()
        config_path = 'scanner/config.json'

        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✓ Created Windows-optimized config: {config_path}")
        return config_path

    def create_startup_script(self):
        """Create Windows startup batch file"""
        batch_content = f'''@echo off
title Network Scanner
echo ================================================
echo Network Scanner - Windows Setup
echo ================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✓ Running as Administrator
) else (
    echo ⚠ WARNING: Not running as Administrator
    echo Some scans may not work properly
    echo.
)

REM Check Python
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo ✓ Python found
) else (
    echo ✗ Python not found in PATH
    pause
    exit /b 1
)

REM Check Nmap
"{self.nmap_path or 'nmap'}" --version >nul 2>&1
if %errorLevel% == 0 (
    echo ✓ Nmap found
) else (
    echo ✗ Nmap not found
    echo Please install Nmap from https://nmap.org/download.html
    pause
    exit /b 1
)

echo.
echo Starting Network Scanner...
echo Dashboard will be available at: http://localhost:5000
echo Press Ctrl+C to stop
echo.

cd /d "{os.getcwd()}"
python scanner/app.py

pause
'''

        with open('start_scanner.bat', 'w') as f:
            f.write(batch_content)

        print("✓ Created startup script: start_scanner.bat")

    def check_firewall_settings(self):
        """Check Windows Firewall settings"""
        try:
            # Check if Windows Firewall is blocking Python
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            python_rules = [line for line in result.stdout.split('\n')
                            if 'python' in line.lower()]

            if not python_rules:
                print("⚠ No Python firewall rules found")
                print("  You may need to allow Python through Windows Firewall")
            else:
                print("✓ Python firewall rules found")

        except Exception as e:
            print(f"Could not check firewall settings: {e}")

    def run_setup(self):
        """Run complete Windows setup"""
        print("=" * 60)
        print("Network Scanner - Windows Setup")
        print("=" * 60)

        # Check admin privileges
        if self.is_admin:
            print("✓ Running as Administrator")
        else:
            print("⚠ Not running as Administrator")
            print("  Some network scans may not work properly")
            print("  Consider running as Administrator for best results")

        print()

        # Check Nmap
        if self.nmap_path:
            print(f"✓ Nmap found at: {self.nmap_path}")
        else:
            print("✗ Nmap not found!")
            print("  Please install Nmap from: https://nmap.org/download.html")
            return False

        # Setup directories
        print("\nSetting up directories...")
        self.setup_directories()

        # Create config
        print("\nCreating Windows-optimized configuration...")
        config_file = self.create_windows_config_file()

        # Create startup script
        print("\nCreating startup script...")
        self.create_startup_script()

        # Check firewall
        print("\nChecking Windows Firewall...")
        self.check_firewall_settings()

        print("\n" + "=" * 60)
        print("Setup completed successfully!")
        print("\nTo start the scanner:")
        print("1. Double-click 'start_scanner.bat', or")
        print("2. Run 'python scanner/app.py'")
        print("\nDashboard will be available at: http://localhost:5000")
        print("=" * 60)

        return True


def main():
    """Main setup function"""
    if platform.system().lower() != 'windows':
        print("This setup script is designed for Windows.")
        print("For other operating systems, use the standard setup.")
        return

    setup = WindowsScannerSetup()
    success = setup.run_setup()

    if not success:
        input("\nPress Enter to exit...")
        sys.exit(1)


if __name__ == '__main__':
    main()