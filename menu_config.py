# Configurazione completa del menu per Network Analysis Tool
# Basato sui parser: XML, Vulnerability, Device Classifier, Software, Main Processor

MENU_STRUCTURE = {
    # ===========================
    # HEADER - DASHBOARD PRINCIPALE
    # ===========================
    '_header_main': {
        'type': 'header',
        'label': 'DASHBOARD PRINCIPALE'
    },

    # Dashboard generale
    'dashboard': {
        'icon': 'bi bi-speedometer2',
        'label': 'Dashboard Generale',
        'url': '/',
        'endpoint': 'index'
    },

    # ===========================
    # HEADER - NETWORK DISCOVERY
    # ===========================
    '_header_network': {
        'type': 'header',
        'label': 'NETWORK DISCOVERY'
    },

    # Network Overview
    'network_overview': {
        'icon': 'bi bi-diagram-3',
        'label': 'Network Overview',
        'url': '/network/overview',
        'endpoint': 'network.overview',
        'children': {
            'scan_info': {
                'icon': 'bi bi-info-circle',
                'label': 'Scan Information',
                'url': '/network/scan-info',
                'endpoint': 'network.scan_info'
            },
            'network_topology': {
                'icon': 'bi bi-share',
                'label': 'Network Topology',
                'url': '/network/topology',
                'endpoint': 'network.topology'
            },
            'traceroute': {
                'icon': 'bi bi-arrow-repeat',
                'label': 'Traceroute Data',
                'url': '/network/traceroute',
                'endpoint': 'network.traceroute'
            }
        }
    },

    # Host Management
    'hosts': {
        'icon': 'bi bi-pc-display',
        'label': 'Host Management',
        'url': '/network/hosts',
        'endpoint': 'network.hosts',
        'badge': {
            'text': 'Hot',
            'class': 'text-bg-danger'
        },
        'children': {
            'hosts_active': {
                'icon': 'bi bi-circle-fill text-success',
                'label': 'Host Attivi',
                'url': '/network/hosts?status=up',
                'endpoint': 'network.hosts'
            },
            'hosts_inactive': {
                'icon': 'bi bi-circle text-secondary',
                'label': 'Host Inattivi',
                'url': '/network/hosts?status=down',
                'endpoint': 'network.hosts'
            },
            'hosts_with_hostname': {
                'icon': 'bi bi-tag',
                'label': 'Host con Hostname',
                'url': '/network/hosts?has_hostname=true',
                'endpoint': 'network.hosts'
            },
            'os_information': {
                'icon': 'bi bi-hdd-stack',
                'label': 'OS Information',
                'url': '/network/os-info',
                'endpoint': 'network.os_info'
            },
            'hostname_discovery': {
                'icon': 'bi bi-search',
                'label': 'Hostname Discovery',
                'url': '/network/hostnames',
                'endpoint': 'network.hostnames'
            }
        }
    },

    # ===========================
    # HEADER - SERVICES & PORTS
    # ===========================
    '_header_services': {
        'type': 'header',
        'label': 'SERVICES & PORTS'
    },

    # Network Services
    'services': {
        'icon': 'bi bi-hdd-network',
        'label': 'Network Services',
        'url': '/network/services',
        'endpoint': 'network.services',
        'children': {
            'ports_overview': {
                'icon': 'bi bi-door-open',
                'label': 'Ports Overview',
                'url': '/network/ports',
                'endpoint': 'network.ports'
            },
            'open_ports': {
                'icon': 'bi bi-door-open-fill text-success',
                'label': 'Porte Aperte',
                'url': '/network/ports?state=open',
                'endpoint': 'network.ports'
            },
            'filtered_ports': {
                'icon': 'bi bi-door-closed text-warning',
                'label': 'Porte Filtrate',
                'url': '/network/ports?state=filtered',
                'endpoint': 'network.ports'
            },
            'service_detection': {
                'icon': 'bi bi-search',
                'label': 'Service Detection',
                'url': '/network/service-detection',
                'endpoint': 'network.service_detection'
            },
            'nse_scripts': {
                'icon': 'bi bi-code-square',
                'label': 'NSE Scripts Results',
                'url': '/network/nse-scripts',
                'endpoint': 'network.nse_scripts'
            }
        }
    },

    # ===========================
    # HEADER - SECURITY ANALYSIS
    # ===========================
    '_header_security': {
        'type': 'header',
        'label': 'SECURITY ANALYSIS'
    },

    # Vulnerability Assessment
    'vulnerabilities': {
        'icon': 'bi bi-shield-exclamation',
        'label': 'Vulnerability Assessment',
        'url': '/security/vulnerabilities',
        'endpoint': 'security.vulnerabilities',
        'badge': {
            'text': 'Critical',
            'class': 'text-bg-danger'
        },
        'children': {
            'vuln_overview': {
                'icon': 'bi bi-pie-chart',
                'label': 'Vulnerabilities Overview',
                'url': '/security/vulnerabilities/overview',
                'endpoint': 'security.vulnerabilities_overview'
            },
            'vuln_critical': {
                'icon': 'bi bi-exclamation-triangle-fill text-danger',
                'label': 'Critical Vulnerabilities',
                'url': '/security/vulnerabilities?severity=CRITICAL',
                'endpoint': 'security.vulnerabilities'
            },
            'vuln_high': {
                'icon': 'bi bi-exclamation-triangle text-warning',
                'label': 'High Vulnerabilities',
                'url': '/security/vulnerabilities?severity=HIGH',
                'endpoint': 'security.vulnerabilities'
            },
            'vuln_web': {
                'icon': 'bi bi-globe',
                'label': 'Web Vulnerabilities',
                'url': '/security/vulnerabilities?type=web',
                'endpoint': 'security.vulnerabilities'
            },
            'vuln_smb': {
                'icon': 'bi bi-folder-symlink',
                'label': 'SMB Vulnerabilities',
                'url': '/security/vulnerabilities?type=smb',
                'endpoint': 'security.vulnerabilities'
            },
            'vuln_ssl': {
                'icon': 'bi bi-shield-lock',
                'label': 'SSL/TLS Vulnerabilities',
                'url': '/security/vulnerabilities?type=ssl',
                'endpoint': 'security.vulnerabilities'
            },
            'cve_database': {
                'icon': 'bi bi-database',
                'label': 'CVE Database',
                'url': '/security/cve-database',
                'endpoint': 'security.cve_database'
            }
        }
    },

    # ===========================
    # HEADER - DEVICE ANALYSIS
    # ===========================
    '_header_devices': {
        'type': 'header',
        'label': 'DEVICE ANALYSIS'
    },

    # Device Classification
    'device_classification': {
        'icon': 'bi bi-diagram-2',
        'label': 'Device Classification',
        'url': '/devices/classification',
        'endpoint': 'devices.classification',
        'children': {
            'classification_overview': {
                'icon': 'bi bi-bar-chart',
                'label': 'Classification Overview',
                'url': '/devices/classification/overview',
                'endpoint': 'devices.classification_overview'
            },
            'servers': {
                'icon': 'bi bi-server',
                'label': 'Servers',
                'url': '/devices/classification?type=Server',
                'endpoint': 'devices.classification'
            },
            'workstations': {
                'icon': 'bi bi-pc-display',
                'label': 'Workstations',
                'url': '/devices/classification?type=Workstation',
                'endpoint': 'devices.classification'
            },
            'network_devices': {
                'icon': 'bi bi-router',
                'label': 'Network Devices',
                'url': '/devices/classification?type=Network Device',
                'endpoint': 'devices.classification'
            },
            'iot_devices': {
                'icon': 'bi bi-cpu',
                'label': 'IoT Devices',
                'url': '/devices/classification?type=IoT Device',
                'endpoint': 'devices.classification'
            },
            'printers': {
                'icon': 'bi bi-printer',
                'label': 'Printers',
                'url': '/devices/classification?type=Printer',
                'endpoint': 'devices.classification'
            },
            'vendor_analysis': {
                'icon': 'bi bi-building',
                'label': 'Vendor Analysis',
                'url': '/devices/vendors',
                'endpoint': 'devices.vendors'
            },
            'confidence_scores': {
                'icon': 'bi bi-graph-up',
                'label': 'Confidence Scores',
                'url': '/devices/confidence',
                'endpoint': 'devices.confidence'
            }
        }
    },

    # ===========================
    # HEADER - SYSTEM ANALYSIS
    # ===========================
    '_header_system': {
        'type': 'header',
        'label': 'SYSTEM ANALYSIS'
    },

    # Software & Processes
    'software_analysis': {
        'icon': 'bi bi-app-indicator',
        'label': 'Software & Processes',
        'url': '/system/software',
        'endpoint': 'system.software',
        'children': {
            'installed_software': {
                'icon': 'bi bi-box',
                'label': 'Installed Software',
                'url': '/system/software/installed',
                'endpoint': 'system.installed_software'
            },
            'running_processes': {
                'icon': 'bi bi-play-circle',
                'label': 'Running Processes',
                'url': '/system/processes',
                'endpoint': 'system.processes'
            },
            'software_statistics': {
                'icon': 'bi bi-graph-up',
                'label': 'Software Statistics',
                'url': '/system/software/statistics',
                'endpoint': 'system.software_statistics'
            },
            'process_statistics': {
                'icon': 'bi bi-bar-chart',
                'label': 'Process Statistics',
                'url': '/system/processes/statistics',
                'endpoint': 'system.process_statistics'
            }
        }
    },

    # ===========================
    # HEADER - REPORTING
    # ===========================
    '_header_reporting': {
        'type': 'header',
        'label': 'REPORTING & ANALYTICS'
    },

    # Reports & Analytics
    'reports': {
        'icon': 'bi bi-file-earmark-text',
        'label': 'Reports & Analytics',
        'url': '/reports',
        'endpoint': 'reports.overview',
        'children': {
            'executive_summary': {
                'icon': 'bi bi-file-earmark-richtext',
                'label': 'Executive Summary',
                'url': '/reports/executive-summary',
                'endpoint': 'reports.executive_summary'
            },
            'detailed_reports': {
                'icon': 'bi bi-file-earmark-spreadsheet',
                'label': 'Detailed Reports',
                'url': '/reports/detailed',
                'endpoint': 'reports.detailed'
            },
            'vulnerability_report': {
                'icon': 'bi bi-shield-exclamation',
                'label': 'Vulnerability Report',
                'url': '/reports/vulnerabilities',
                'endpoint': 'reports.vulnerabilities'
            },
            'compliance_report': {
                'icon': 'bi bi-check2-square',
                'label': 'Compliance Report',
                'url': '/reports/compliance',
                'endpoint': 'reports.compliance'
            },
            # ✅ AGGIUNGI QUESTA SEZIONE:
            'history': {
                'icon': 'bi bi-clock-history',
                'label': 'Report History',
                'url': '/reports/history',
                'endpoint': 'reports.history'
            },
            'export_data': {
                'icon': 'bi bi-download',
                'label': 'Export Data',
                'url': '/reports/export',
                'endpoint': 'reports.export'
            }
        }
    },

    # Statistics & Metrics
    'analytics': {
        'icon': 'bi bi-graph-up-arrow',
        'label': 'Analytics & Metrics',
        'url': '/analytics',
        'endpoint': 'analytics.overview',
        'children': {
            'network_metrics': {
                'icon': 'bi bi-speedometer2',
                'label': 'Network Metrics',
                'url': '/analytics/network',
                'endpoint': 'analytics.network'
            },
            'security_metrics': {
                'icon': 'bi bi-shield-check',
                'label': 'Security Metrics',
                'url': '/analytics/security',
                'endpoint': 'analytics.security'
            },
            'performance_trends': {
                'icon': 'bi bi-graph-down',
                'label': 'Performance Trends',
                'url': '/analytics/trends',
                'endpoint': 'analytics.trends'
            },
            'comparative_analysis': {
                'icon': 'bi bi-bar-chart-steps',
                'label': 'Comparative Analysis',
                'url': '/analytics/comparative',
                'endpoint': 'analytics.comparative'
            }
        }
    },

    # ===========================
    # HEADER - TOOLS & UTILITIES
    # ===========================
    '_header_tools': {
        'type': 'header',
        'label': 'TOOLS & UTILITIES'
    },

    # Database Tools
    'database_tools': {
        'icon': 'bi bi-database-gear',
        'label': 'Database Tools',
        'url': '/tools/database',
        'endpoint': 'tools.database',
        'children': {
            'database_status': {
                'icon': 'bi bi-database-check',
                'label': 'Database Status',
                'url': '/tools/database/status',
                'endpoint': 'tools.database_status'
            },
            'data_import': {
                'icon': 'bi bi-upload',
                'label': 'Data Import',
                'url': '/tools/database/import',
                'endpoint': 'tools.data_import'
            },
            'data_export': {
                'icon': 'bi bi-download',
                'label': 'Data Export',
                'url': '/tools/database/export',
                'endpoint': 'tools.data_export'
            },
            'backup_restore': {
                'icon': 'bi bi-archive',
                'label': 'Backup & Restore',
                'url': '/tools/database/backup',
                'endpoint': 'tools.backup_restore'
            }
        }
    },

    # Search & Filters
    'search_tools': {
        'icon': 'bi bi-search-heart',
        'label': 'Search & Filters',
        'url': '/tools/search',
        'endpoint': 'tools.search',
        'children': {
            'global_search': {
                'icon': 'bi bi-search',
                'label': 'Global Search',
                'url': '/tools/search/global',
                'endpoint': 'tools.global_search'
            },
            'advanced_filters': {
                'icon': 'bi bi-funnel',
                'label': 'Advanced Filters',
                'url': '/tools/search/filters',
                'endpoint': 'tools.advanced_filters'
            },
            'saved_searches': {
                'icon': 'bi bi-bookmark-star',
                'label': 'Saved Searches',
                'url': '/tools/search/saved',
                'endpoint': 'tools.saved_searches'
            }
        }
    },

    # ===========================
    # HEADER - ADMINISTRATION
    # ===========================
    '_header_admin': {
        'type': 'header',
        'label': 'ADMINISTRATION'
    },

    # System Configuration
    'system_config': {
        'icon': 'bi bi-gear',
        'label': 'System Configuration',
        'url': '/admin/config',
        'endpoint': 'admin.config',
        'children': {
            'parser_settings': {
                'icon': 'bi bi-sliders',
                'label': 'Parser Settings',
                'url': '/admin/config/parsers',
                'endpoint': 'admin.parser_settings'
            },
            'classification_rules': {
                'icon': 'bi bi-list-check',
                'label': 'Classification Rules',
                'url': '/admin/config/classification',
                'endpoint': 'admin.classification_rules'
            },
            'alert_thresholds': {
                'icon': 'bi bi-exclamation-circle',
                'label': 'Alert Thresholds',
                'url': '/admin/config/alerts',
                'endpoint': 'admin.alert_thresholds'
            }
        }
    },

    # System Logs
    'system_logs': {
        'icon': 'bi bi-journal-text',
        'label': 'System Logs',
        'url': '/admin/logs',
        'endpoint': 'admin.logs',
        'children': {
            'parsing_logs': {
                'icon': 'bi bi-file-text',
                'label': 'Parsing Logs',
                'url': '/admin/logs/parsing',
                'endpoint': 'admin.parsing_logs'
            },
            'error_logs': {
                'icon': 'bi bi-exclamation-triangle',
                'label': 'Error Logs',
                'url': '/admin/logs/errors',
                'endpoint': 'admin.error_logs'
            },
            'system_activity': {
                'icon': 'bi bi-activity',
                'label': 'System Activity',
                'url': '/admin/logs/activity',
                'endpoint': 'admin.system_activity'
            }
        }
    },

    # ===========================
    # FOOTER ITEMS
    # ===========================
    '_header_help': {
        'type': 'header',
        'label': 'HELP & SUPPORT'
    },

    # Documentation
    'documentation': {
        'icon': 'bi bi-book',
        'label': 'Documentation',
        'url': '/help/docs',
        'endpoint': 'help.documentation',
        'children': {
            'user_guide': {
                'icon': 'bi bi-person-check',
                'label': 'User Guide',
                'url': '/help/docs/user-guide',
                'endpoint': 'help.user_guide'
            },
            'api_reference': {
                'icon': 'bi bi-code-square',
                'label': 'API Reference',
                'url': '/help/docs/api',
                'endpoint': 'help.api_reference'
            },
            'troubleshooting': {
                'icon': 'bi bi-tools',
                'label': 'Troubleshooting',
                'url': '/help/docs/troubleshooting',
                'endpoint': 'help.troubleshooting'
            }
        }
    },

    # About
    'about': {
        'icon': 'bi bi-info-circle',
        'label': 'About',
        'url': '/about',
        'endpoint': 'about.index',
        'children': {
            'version_info': {
                'icon': 'bi bi-tag',
                'label': 'Version Info',
                'url': '/about/version',
                'endpoint': 'about.version'
            },
            'credits': {
                'icon': 'bi bi-people',
                'label': 'Credits',
                'url': '/about/credits',
                'endpoint': 'about.credits'
            },
            'license': {
                'icon': 'bi bi-file-text',
                'label': 'License',
                'url': '/about/license',
                'endpoint': 'about.license'
            }
        }
    }
}