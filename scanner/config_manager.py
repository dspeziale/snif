# scanner/config_manager.py
import json
import os
from pathlib import Path


class ConfigManager:
    """Gestisce la configurazione dell'applicazione"""

    def __init__(self, config_file='scanner/config.json'):
        self.config_file = config_file
        self.config = self.load_config()

    def load_config(self):
        """Carica la configurazione dal file JSON"""
        default_config = {
            "network": {
                "scan_ranges": [
                    "192.168.20.0/24",
                    "192.168.30.0/24",
                    "192.168.40.0/24",
                    "192.168.50.0/24",
                    "192.168.60.0/24",
                    "192.168.70.0/24"
                ],
                "auto_detect_local_networks": 'true',
                "timeout": 300,
                "max_retries": 3,
                "parallel_scans": 'true',
                "max_concurrent_ranges": 3
            },
            "nmap": {
                "path": "nmap",
                "discovery_args": "-sn -PE -PS22,23,25,53,80,110,443,993,995,1723,3389,5900,8080",
                "services_args": "-sS -sV -O --version-intensity 5",
                "vuln_args": "--script vuln",
                "snmp_args": "-sU -p 161 --script snmp-info,snmp-interfaces,snmp-processes",
                "timing": "T4"
            },
            "snmp": {
                "community_strings": ["public", "private", "community"],
                "version": "2c",
                "timeout": 5,
                "retries": 2
            },
            "database": {
                "path": "data/network_scanner.db"
            },
            "cache": {
                "oui_url": "http://standards-oui.ieee.org/oui/oui.txt",
                "nvd_url": "https://services.nvd.nist.gov/rest/json/cves/1.0",
                "update_interval_days": 30
            },
            "scanning": {
                "discovery_interval_minutes": 10,
                "services_scan_delay_hours": 1,
                "os_scan_delay_hours": 2,
                "vuln_scan_delay_hours": 6,
                "snmp_scan_delay_hours": 4
            },
            "logging": {
                "level": "INFO",
                "file": "scanner/log/scanner.log",
                "max_file_size": 10485760,
                "backup_count": 5
            }
        }

        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge con configurazione di default
                    self._merge_config(default_config, loaded_config)
                    return default_config
            except Exception as e:
                print(f"Errore caricamento config: {e}")
                return default_config
        else:
            # Crea file di configurazione con valori di default
            self.save_config(default_config)
            return default_config

    def _merge_config(self, default, loaded):
        """Unisce configurazione caricata con quella di default"""
        for key, value in loaded.items():
            if isinstance(value, dict) and key in default:
                self._merge_config(default[key], value)
            else:
                default[key] = value

    def save_config(self, config=None):
        """Salva la configurazione su file"""
        if config is None:
            config = self.config

        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)

        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)

    def get(self, key_path, default=None):
        """Ottiene valore dalla configurazione usando path separato da punti"""
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, key_path, value):
        """Imposta valore nella configurazione usando path separato da punti"""
        keys = key_path.split('.')
        config = self.config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value
        self.save_config()