# Configurazione del menu separata per facilità di gestione
MENU_STRUCTURE = {
    'dashboard': {
        'icon': 'bi bi-speedometer',
        'label': 'Dashboard',
        'url': None,
        'badge': None,
        'children': {
            'dashboard_v1': {
                'icon': 'bi bi-circle',
                'label': 'Dashboard v1',
                'url': '/',
                'endpoint': 'index'
            },
            'dashboard_v2': {
                'icon': 'bi bi-circle',
                'label': 'Dashboard v2',
                'url': '#'
            },
            'dashboard_v3': {
                'icon': 'bi bi-circle',
                'label': 'Dashboard v3',
                'url': '#'
            }
        }
    },
    'theme_generate': {
        'icon': 'bi bi-palette',
        'label': 'Theme Generate',
        'url': '#'
    },
    '_header_multilevel': {
        'type': 'header',
        'label': 'MULTI LEVEL EXAMPLE'
    },
    'level1_single': {
        'icon': 'bi bi-circle-fill',
        'label': 'Level 1',
        'url': '#'
    },
    'level1_multi': {
        'icon': 'bi bi-circle-fill',
        'label': 'Level 1',
        'url': None,
        'children': {
            'level2_single': {
                'icon': 'bi bi-circle',
                'label': 'Level 2',
                'url': '#'
            },
            'level2_multi': {
                'icon': 'bi bi-circle',
                'label': 'Level 2',
                'url': None,
                'children': {
                    'level3_1': {
                        'icon': 'bi bi-record-circle-fill',
                        'label': 'Level 3',
                        'url': '#'
                    },
                    'level3_2': {
                        'icon': 'bi bi-record-circle-fill',
                        'label': 'Level 3',
                        'url': '#'
                    },
                    'level3_3': {
                        'icon': 'bi bi-record-circle-fill',
                        'label': 'Level 3',
                        'url': '#'
                    }
                }
            },
            'level2_single2': {
                'icon': 'bi bi-circle',
                'label': 'Level 2',
                'url': '#'
            }
        }
    },
    'level1_single2': {
        'icon': 'bi bi-circle-fill',
        'label': 'Level 1',
        'url': '#'
    },
}