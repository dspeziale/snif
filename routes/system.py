from flask import Blueprint, render_template, request, jsonify, g, current_app
import sqlite3
from datetime import datetime
from collections import Counter

# Blueprint per System Analysis
system_bp = Blueprint('system', __name__, url_prefix='/system')


def get_db():
    """Ottiene connessione al database"""
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(current_app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db


# ===========================
# SOFTWARE OVERVIEW
# ===========================

@system_bp.route('/software')
def software():
    """Overview software e processi"""
    try:
        db = get_db()

        # Statistiche generali
        software_stats = {
            'total_software_entries': db.execute('SELECT COUNT(*) FROM installed_software').fetchone()[0],
            'unique_software': db.execute('SELECT COUNT(DISTINCT software_name) FROM installed_software').fetchone()[0],
            'hosts_with_software': db.execute('SELECT COUNT(DISTINCT ip_address) FROM installed_software').fetchone()[
                0],
            'total_processes': db.execute('SELECT COUNT(*) FROM running_processes').fetchone()[0],
            'unique_processes': db.execute('SELECT COUNT(DISTINCT process_name) FROM running_processes').fetchone()[0],
            'hosts_with_processes': db.execute('SELECT COUNT(DISTINCT ip_address) FROM running_processes').fetchone()[0]
        }

        # Top 10 software più installati
        top_software = db.execute('''
            SELECT software_name, COUNT(*) as install_count,
                   COUNT(DISTINCT ip_address) as unique_hosts
            FROM installed_software 
            WHERE software_name IS NOT NULL AND software_name != ""
            GROUP BY software_name 
            ORDER BY install_count DESC 
            LIMIT 10
        ''').fetchall()

        # Top 10 processi più comuni
        top_processes = db.execute('''
            SELECT process_name, COUNT(*) as process_count,
                   COUNT(DISTINCT ip_address) as unique_hosts
            FROM running_processes 
            WHERE process_name IS NOT NULL AND process_name != ""
            GROUP BY process_name 
            ORDER BY process_count DESC 
            LIMIT 10
        ''').fetchall()

        # Host con più software
        hosts_most_software = db.execute('''
            SELECT s.ip_address, h.hostname, COUNT(*) as software_count
            FROM installed_software s
            LEFT JOIN hosts h ON s.ip_address = h.ip_address
            GROUP BY s.ip_address, h.hostname
            ORDER BY software_count DESC
            LIMIT 10
        ''').fetchall()

        # Host con più processi
        hosts_most_processes = db.execute('''
            SELECT p.ip_address, h.hostname, COUNT(*) as process_count
            FROM running_processes p
            LEFT JOIN hosts h ON p.ip_address = h.ip_address
            GROUP BY p.ip_address, h.hostname
            ORDER BY process_count DESC
            LIMIT 10
        ''').fetchall()

        # Software con versioni multiple
        software_versions = db.execute('''
            SELECT software_name, COUNT(DISTINCT version) as version_count,
                   GROUP_CONCAT(DISTINCT version) as versions
            FROM installed_software 
            WHERE software_name IS NOT NULL AND version IS NOT NULL
            GROUP BY software_name
            HAVING version_count > 1
            ORDER BY version_count DESC
            LIMIT 10
        ''').fetchall()

        # Distribuzione per publisher (se disponibile)
        publishers = db.execute('''
            SELECT publisher, COUNT(*) as software_count,
                   COUNT(DISTINCT software_name) as unique_software
            FROM installed_software 
            WHERE publisher IS NOT NULL AND publisher != ""
            GROUP BY publisher 
            ORDER BY software_count DESC 
            LIMIT 10
        ''').fetchall()

        return render_template('system/overview.html',
                               software_stats=software_stats,
                               top_software=top_software,
                               top_processes=top_processes,
                               hosts_most_software=hosts_most_software,
                               hosts_most_processes=hosts_most_processes,
                               software_versions=software_versions,
                               publishers=publishers)

    except Exception as e:
        current_app.logger.error(f"Errore in system overview: {e}")
        return render_template('system/overview.html', error=str(e))


# ===========================
# INSTALLED SOFTWARE
# ===========================

@system_bp.route('/software/installed')
def installed_software():
    """Lista software installato"""
    try:
        db = get_db()

        # Filtri dalla query string
        software_name = request.args.get('software')
        host_ip = request.args.get('host')
        publisher = request.args.get('publisher')
        has_version = request.args.get('has_version')
        search = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # Query base
        query = '''
            SELECT s.*, h.hostname, h.vendor
            FROM installed_software s
            LEFT JOIN hosts h ON s.ip_address = h.ip_address
        '''

        params = []
        conditions = []

        # Applica filtri
        if software_name:
            conditions.append('s.software_name LIKE ?')
            params.append(f'%{software_name}%')

        if host_ip:
            conditions.append('s.ip_address = ?')
            params.append(host_ip)

        if publisher:
            conditions.append('s.publisher LIKE ?')
            params.append(f'%{publisher}%')

        if has_version == 'true':
            conditions.append('s.version IS NOT NULL AND s.version != ""')
        elif has_version == 'false':
            conditions.append('(s.version IS NULL OR s.version = "")')

        if search:
            conditions.append('''(
                s.software_name LIKE ? OR 
                s.version LIKE ? OR 
                s.publisher LIKE ? OR
                h.hostname LIKE ?
            )''')
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param, search_param])

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY s.software_name, s.ip_address'

        # Conteggio totale
        count_query = query.replace('SELECT s.*, h.hostname, h.vendor', 'SELECT COUNT(*)')
        total_count = db.execute(count_query, params).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        software_data = db.execute(paginated_query, params).fetchall()

        # Informazioni paginazione
        total_pages = (total_count + per_page - 1) // per_page
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages
        }

        # Ottieni valori per filtri dropdown
        available_software = db.execute('''
            SELECT DISTINCT software_name 
            FROM installed_software 
            WHERE software_name IS NOT NULL 
            ORDER BY software_name
            LIMIT 100
        ''').fetchall()

        available_publishers = db.execute('''
            SELECT DISTINCT publisher 
            FROM installed_software 
            WHERE publisher IS NOT NULL AND publisher != ""
            ORDER BY publisher
        ''').fetchall()

        hosts_with_software = db.execute('''
            SELECT DISTINCT s.ip_address, h.hostname
            FROM installed_software s
            LEFT JOIN hosts h ON s.ip_address = h.ip_address
            ORDER BY s.ip_address
        ''').fetchall()

        current_filters = {
            'software': software_name,
            'host': host_ip,
            'publisher': publisher,
            'has_version': has_version,
            'search': search
        }

        return render_template('system/installed_software.html',
                               software_data=software_data,
                               pagination=pagination,
                               current_filters=current_filters,
                               available_software=available_software,
                               available_publishers=available_publishers,
                               hosts_with_software=hosts_with_software)

    except Exception as e:
        current_app.logger.error(f"Errore in installed_software: {e}")
        return render_template('system/installed_software.html',
                               software_data=[], pagination={}, error=str(e))


@system_bp.route('/software/<software_name>')
def software_detail(software_name):
    """Dettaglio software specifico"""
    try:
        db = get_db()

        # Tutte le installazioni di questo software
        installations = db.execute('''
            SELECT s.*, h.hostname, h.vendor, h.status
            FROM installed_software s
            LEFT JOIN hosts h ON s.ip_address = h.ip_address
            WHERE s.software_name = ?
            ORDER BY s.version DESC, s.ip_address
        ''', (software_name,)).fetchall()

        if not installations:
            return render_template('errors/404.html'), 404

        # Statistiche per questo software
        software_info = {
            'software_name': software_name,
            'total_installations': len(installations),
            'unique_hosts': len(set(inst['ip_address'] for inst in installations)),
            'versions': list(set(inst['version'] for inst in installations if inst['version'])),
            'publishers': list(set(inst['publisher'] for inst in installations if inst['publisher'])),
            'install_dates': [inst['install_date'] for inst in installations if inst['install_date']]
        }

        # Distribuzione per versione
        version_distribution = {}
        for inst in installations:
            version = inst['version'] or 'Unknown'
            version_distribution[version] = version_distribution.get(version, 0) + 1

        # Host con questo software
        hosts_with_software = []
        for inst in installations:
            hosts_with_software.append({
                'ip_address': inst['ip_address'],
                'hostname': inst['hostname'],
                'version': inst['version'],
                'publisher': inst['publisher'],
                'install_date': inst['install_date'],
                'status': inst['status']
            })

        # Timeline installazioni (se ci sono date)
        install_timeline = {}
        for inst in installations:
            if inst['install_date']:
                try:
                    # Estrai solo l'anno dalla data
                    date_obj = datetime.fromisoformat(inst['install_date'].replace('Z', '+00:00'))
                    year = date_obj.year
                    install_timeline[year] = install_timeline.get(year, 0) + 1
                except:
                    pass

        return render_template('system/software_detail.html',
                               software_info=software_info,
                               installations=installations,
                               version_distribution=version_distribution,
                               hosts_with_software=hosts_with_software,
                               install_timeline=dict(sorted(install_timeline.items())))

    except Exception as e:
        current_app.logger.error(f"Errore in software_detail per {software_name}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# RUNNING PROCESSES
# ===========================

@system_bp.route('/processes')
def processes():
    """Lista processi in esecuzione"""
    try:
        db = get_db()

        # Filtri dalla query string
        process_name = request.args.get('process')
        host_ip = request.args.get('host')
        has_path = request.args.get('has_path')
        search = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # Query base
        query = '''
            SELECT p.*, h.hostname, h.vendor
            FROM running_processes p
            LEFT JOIN hosts h ON p.ip_address = h.ip_address
        '''

        params = []
        conditions = []

        # Applica filtri
        if process_name:
            conditions.append('p.process_name LIKE ?')
            params.append(f'%{process_name}%')

        if host_ip:
            conditions.append('p.ip_address = ?')
            params.append(host_ip)

        if has_path == 'true':
            conditions.append('p.process_path IS NOT NULL AND p.process_path != ""')
        elif has_path == 'false':
            conditions.append('(p.process_path IS NULL OR p.process_path = "")')

        if search:
            conditions.append('''(
                p.process_name LIKE ? OR 
                p.process_path LIKE ? OR 
                p.process_params LIKE ? OR
                h.hostname LIKE ?
            )''')
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param, search_param])

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY p.process_name, p.ip_address, p.pid'

        # Conteggio totale
        count_query = query.replace('SELECT p.*, h.hostname, h.vendor', 'SELECT COUNT(*)')
        total_count = db.execute(count_query, params).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        processes_data = db.execute(paginated_query, params).fetchall()

        # Informazioni paginazione
        total_pages = (total_count + per_page - 1) // per_page
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages
        }

        # Ottieni valori per filtri dropdown
        available_processes = db.execute('''
            SELECT DISTINCT process_name 
            FROM running_processes 
            WHERE process_name IS NOT NULL 
            ORDER BY process_name
            LIMIT 100
        ''').fetchall()

        hosts_with_processes = db.execute('''
            SELECT DISTINCT p.ip_address, h.hostname
            FROM running_processes p
            LEFT JOIN hosts h ON p.ip_address = h.ip_address
            ORDER BY p.ip_address
        ''').fetchall()

        current_filters = {
            'process': process_name,
            'host': host_ip,
            'has_path': has_path,
            'search': search
        }

        return render_template('system/processes.html',
                               processes_data=processes_data,
                               pagination=pagination,
                               current_filters=current_filters,
                               available_processes=available_processes,
                               hosts_with_processes=hosts_with_processes)

    except Exception as e:
        current_app.logger.error(f"Errore in processes: {e}")
        return render_template('system/processes.html',
                               processes_data=[], pagination={}, error=str(e))


@system_bp.route('/process/<process_name>')
def process_detail(process_name):
    """Dettaglio processo specifico"""
    try:
        db = get_db()

        # Tutte le istanze di questo processo
        process_instances = db.execute('''
            SELECT p.*, h.hostname, h.vendor, h.status
            FROM running_processes p
            LEFT JOIN hosts h ON p.ip_address = h.ip_address
            WHERE p.process_name = ?
            ORDER BY p.ip_address, p.pid
        ''', (process_name,)).fetchall()

        if not process_instances:
            return render_template('errors/404.html'), 404

        # Statistiche per questo processo
        process_info = {
            'process_name': process_name,
            'total_instances': len(process_instances),
            'unique_hosts': len(set(inst['ip_address'] for inst in process_instances)),
            'unique_paths': list(set(inst['process_path'] for inst in process_instances if inst['process_path'])),
            'pid_range': {
                'min': min((inst['pid'] for inst in process_instances if inst['pid']), default=0),
                'max': max((inst['pid'] for inst in process_instances if inst['pid']), default=0)
            }
        }

        # Distribuzione per path
        path_distribution = {}
        for inst in process_instances:
            path = inst['process_path'] or 'Unknown'
            path_distribution[path] = path_distribution.get(path, 0) + 1

        # Host con questo processo
        hosts_with_process = []
        for inst in process_instances:
            hosts_with_process.append({
                'ip_address': inst['ip_address'],
                'hostname': inst['hostname'],
                'pid': inst['pid'],
                'process_path': inst['process_path'],
                'process_params': inst['process_params'],
                'status': inst['status']
            })

        # Analisi parametri (se disponibili)
        params_analysis = {}
        for inst in process_instances:
            if inst['process_params']:
                params = inst['process_params']
                # Conta parametri comuni
                if params in params_analysis:
                    params_analysis[params] += 1
                else:
                    params_analysis[params] = 1

        return render_template('system/process_detail.html',
                               process_info=process_info,
                               process_instances=process_instances,
                               path_distribution=path_distribution,
                               hosts_with_process=hosts_with_process,
                               params_analysis=params_analysis)

    except Exception as e:
        current_app.logger.error(f"Errore in process_detail per {process_name}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# STATISTICS
# ===========================

@system_bp.route('/software/statistics')
def software_statistics():
    """Statistiche dettagliate software"""
    try:
        db = get_db()

        # Software più diffuso
        most_common_software = db.execute('''
            SELECT software_name, COUNT(*) as install_count,
                   COUNT(DISTINCT ip_address) as unique_hosts,
                   COUNT(DISTINCT version) as version_count
            FROM installed_software 
            WHERE software_name IS NOT NULL
            GROUP BY software_name 
            ORDER BY install_count DESC 
            LIMIT 20
        ''').fetchall()

        # Publisher più attivi
        top_publishers = db.execute('''
            SELECT publisher, 
                   COUNT(*) as software_count,
                   COUNT(DISTINCT software_name) as unique_software,
                   COUNT(DISTINCT ip_address) as unique_hosts
            FROM installed_software 
            WHERE publisher IS NOT NULL AND publisher != ""
            GROUP BY publisher 
            ORDER BY software_count DESC 
            LIMIT 15
        ''').fetchall()

        # Analisi versioni
        version_analysis = db.execute('''
            SELECT software_name,
                   COUNT(DISTINCT version) as version_count,
                   GROUP_CONCAT(DISTINCT version) as versions,
                   COUNT(*) as total_installs
            FROM installed_software 
            WHERE software_name IS NOT NULL AND version IS NOT NULL
            GROUP BY software_name
            HAVING version_count > 1
            ORDER BY version_count DESC, total_installs DESC
            LIMIT 15
        ''').fetchall()

        # Timeline installazioni (per anno)
        install_timeline = {}
        timeline_data = db.execute('''
            SELECT install_date 
            FROM installed_software 
            WHERE install_date IS NOT NULL
        ''').fetchall()

        for row in timeline_data:
            try:
                date_obj = datetime.fromisoformat(row['install_date'].replace('Z', '+00:00'))
                year = date_obj.year
                install_timeline[year] = install_timeline.get(year, 0) + 1
            except:
                pass

        # Software senza versione
        unversioned_software = db.execute('''
            SELECT software_name, COUNT(*) as count
            FROM installed_software 
            WHERE (version IS NULL OR version = "")
            GROUP BY software_name 
            ORDER BY count DESC 
            LIMIT 10
        ''').fetchall()

        # Distribuzione per host
        software_per_host = db.execute('''
            SELECT COUNT(*) as software_count, COUNT(ip_address) as frequency
            FROM (
                SELECT ip_address, COUNT(*) as software_count
                FROM installed_software 
                GROUP BY ip_address
            ) 
            GROUP BY software_count 
            ORDER BY software_count
        ''').fetchall()

        return render_template('system/software_statistics.html',
                               most_common_software=most_common_software,
                               top_publishers=top_publishers,
                               version_analysis=version_analysis,
                               install_timeline=dict(sorted(install_timeline.items())),
                               unversioned_software=unversioned_software,
                               software_per_host=software_per_host)

    except Exception as e:
        current_app.logger.error(f"Errore in software_statistics: {e}")
        return render_template('system/software_statistics.html', error=str(e))


@system_bp.route('/processes/statistics')
def process_statistics():
    """Statistiche dettagliate processi"""
    try:
        db = get_db()

        # Processi più comuni
        most_common_processes = db.execute('''
            SELECT process_name, COUNT(*) as instance_count,
                   COUNT(DISTINCT ip_address) as unique_hosts,
                   AVG(CAST(pid AS FLOAT)) as avg_pid
            FROM running_processes 
            WHERE process_name IS NOT NULL
            GROUP BY process_name 
            ORDER BY instance_count DESC 
            LIMIT 20
        ''').fetchall()

        # Analisi percorsi eseguibili
        executable_paths = db.execute('''
            SELECT process_path, COUNT(*) as count,
                   COUNT(DISTINCT process_name) as unique_processes
            FROM running_processes 
            WHERE process_path IS NOT NULL AND process_path != ""
            GROUP BY process_path 
            ORDER BY count DESC 
            LIMIT 15
        ''').fetchall()

        # Distribuzione PID
        pid_distribution = db.execute('''
            SELECT 
                CASE 
                    WHEN pid < 1000 THEN '0-999 (System)'
                    WHEN pid < 5000 THEN '1000-4999 (Services)'
                    WHEN pid < 10000 THEN '5000-9999 (Applications)'
                    WHEN pid < 20000 THEN '10000-19999 (User Apps)'
                    ELSE '20000+ (High PID)'
                END as pid_range,
                COUNT(*) as count
            FROM running_processes 
            WHERE pid IS NOT NULL
            GROUP BY pid_range
            ORDER BY MIN(pid)
        ''').fetchall()

        # Processi con parametri
        processes_with_params = db.execute('''
            SELECT process_name, COUNT(*) as count,
                   COUNT(DISTINCT process_params) as unique_params
            FROM running_processes 
            WHERE process_params IS NOT NULL AND process_params != ""
            GROUP BY process_name 
            ORDER BY count DESC 
            LIMIT 10
        ''').fetchall()

        # Host con più processi
        hosts_most_processes = db.execute('''
            SELECT p.ip_address, h.hostname, COUNT(*) as process_count,
                   COUNT(DISTINCT p.process_name) as unique_processes
            FROM running_processes p
            LEFT JOIN hosts h ON p.ip_address = h.ip_address
            GROUP BY p.ip_address, h.hostname
            ORDER BY process_count DESC
            LIMIT 15
        ''').fetchall()

        # Analisi directory eseguibili
        executable_dirs = {}
        dir_data = db.execute('''
            SELECT process_path 
            FROM running_processes 
            WHERE process_path IS NOT NULL AND process_path != ""
        ''').fetchall()

        for row in dir_data:
            path = row['process_path']
            if path:
                # Estrai directory
                if '\\' in path:  # Windows
                    directory = '\\'.join(path.split('\\')[:-1])
                elif '/' in path:  # Unix/Linux
                    directory = '/'.join(path.split('/')[:-1])
                else:
                    directory = 'Root'

                if directory:
                    executable_dirs[directory] = executable_dirs.get(directory, 0) + 1

        # Prendi top 15 directory
        top_executable_dirs = sorted(executable_dirs.items(), key=lambda x: x[1], reverse=True)[:15]

        return render_template('system/process_statistics.html',
                               most_common_processes=most_common_processes,
                               executable_paths=executable_paths,
                               pid_distribution=pid_distribution,
                               processes_with_params=processes_with_params,
                               hosts_most_processes=hosts_most_processes,
                               top_executable_dirs=top_executable_dirs)

    except Exception as e:
        current_app.logger.error(f"Errore in process_statistics: {e}")
        return render_template('system/process_statistics.html', error=str(e))


# ===========================
# API ENDPOINTS
# ===========================

@system_bp.route('/api/software')
def api_software():
    """API endpoint per software in formato JSON"""
    try:
        db = get_db()

        software_name = request.args.get('software')
        limit = int(request.args.get('limit', 100))

        query = '''
            SELECT s.software_name, s.version, s.publisher, s.install_date,
                   s.ip_address, h.hostname
            FROM installed_software s
            LEFT JOIN hosts h ON s.ip_address = h.ip_address
        '''

        params = []
        if software_name:
            query += ' WHERE s.software_name LIKE ?'
            params.append(f'%{software_name}%')

        query += ' ORDER BY s.software_name LIMIT ?'
        params.append(limit)

        software_data = db.execute(query, params).fetchall()

        # Converti in lista di dizionari
        software_list = []
        for software in software_data:
            software_list.append({
                'software_name': software['software_name'],
                'version': software['version'],
                'publisher': software['publisher'],
                'install_date': software['install_date'],
                'ip_address': software['ip_address'],
                'hostname': software['hostname']
            })

        return jsonify(software_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/api/processes')
def api_processes():
    """API endpoint per processi in formato JSON"""
    try:
        db = get_db()

        process_name = request.args.get('process')
        limit = int(request.args.get('limit', 100))

        query = '''
            SELECT p.process_name, p.pid, p.process_path, p.process_params,
                   p.ip_address, h.hostname
            FROM running_processes p
            LEFT JOIN hosts h ON p.ip_address = h.ip_address
        '''

        params = []
        if process_name:
            query += ' WHERE p.process_name LIKE ?'
            params.append(f'%{process_name}%')

        query += ' ORDER BY p.process_name LIMIT ?'
        params.append(limit)

        processes_data = db.execute(query, params).fetchall()

        # Converti in lista di dizionari
        processes_list = []
        for process in processes_data:
            processes_list.append({
                'process_name': process['process_name'],
                'pid': process['pid'],
                'process_path': process['process_path'],
                'process_params': process['process_params'],
                'ip_address': process['ip_address'],
                'hostname': process['hostname']
            })

        return jsonify(processes_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/api/system-stats')
def api_system_stats():
    """API endpoint per statistiche sistema"""
    try:
        db = get_db()

        stats = {
            'software': {
                'total_entries': db.execute('SELECT COUNT(*) FROM installed_software').fetchone()[0],
                'unique_software':
                    db.execute('SELECT COUNT(DISTINCT software_name) FROM installed_software').fetchone()[0],
                'hosts_with_software':
                    db.execute('SELECT COUNT(DISTINCT ip_address) FROM installed_software').fetchone()[0]
            },
            'processes': {
                'total_entries': db.execute('SELECT COUNT(*) FROM running_processes').fetchone()[0],
                'unique_processes': db.execute('SELECT COUNT(DISTINCT process_name) FROM running_processes').fetchone()[
                    0],
                'hosts_with_processes':
                    db.execute('SELECT COUNT(DISTINCT ip_address) FROM running_processes').fetchone()[0]
            }
        }

        # Top software
        top_software = db.execute('''
            SELECT software_name, COUNT(*) as count
            FROM installed_software 
            WHERE software_name IS NOT NULL
            GROUP BY software_name 
            ORDER BY count DESC 
            LIMIT 5
        ''').fetchall()

        stats['top_software'] = [{'name': s['software_name'], 'count': s['count']} for s in top_software]

        # Top processi
        top_processes = db.execute('''
            SELECT process_name, COUNT(*) as count
            FROM running_processes 
            WHERE process_name IS NOT NULL
            GROUP BY process_name 
            ORDER BY count DESC 
            LIMIT 5
        ''').fetchall()

        stats['top_processes'] = [{'name': p['process_name'], 'count': p['count']} for p in top_processes]

        return jsonify(stats)

    except Exception as e:
        return jsonify({'error': str(e)}), 500