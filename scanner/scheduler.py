# ===================================================================
# scanner/scheduler.py - Scheduler avanzato per scansioni
import threading
import time
from datetime import datetime, timedelta
import heapq


class ScanScheduler:
    """Scheduler avanzato per gestire scansioni programmate"""

    def __init__(self, scanner, db_manager):
        self.scanner = scanner
        self.db = db_manager
        self.running = False
        self.scheduler_thread = None
        self.task_queue = []  # Priority queue
        self.lock = threading.Lock()

    def start(self):
        """Avvia lo scheduler"""
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()

    def stop(self):
        """Ferma lo scheduler"""
        self.running = False

    def schedule_task(self, task_type, target, priority=5, delay_seconds=0):
        """Programma una nuova attività"""
        execute_time = datetime.now() + timedelta(seconds=delay_seconds)

        task = {
            'type': task_type,
            'target': target,
            'priority': priority,
            'execute_time': execute_time,
            'created_time': datetime.now()
        }

        with self.lock:
            heapq.heappush(self.task_queue, (execute_time.timestamp(), priority, task))

    def _scheduler_loop(self):
        """Loop principale dello scheduler"""
        while self.running:
            try:
                current_time = datetime.now()
                tasks_to_execute = []

                with self.lock:
                    # Estrae task pronti per l'esecuzione
                    while (self.task_queue and
                           datetime.fromtimestamp(self.task_queue[0][0]) <= current_time):
                        _, _, task = heapq.heappop(self.task_queue)
                        tasks_to_execute.append(task)

                # Esegue i task
                for task in tasks_to_execute:
                    self._execute_task(task)

                # Attende prima del prossimo controllo
                time.sleep(10)

            except Exception as e:
                print(f"Errore nello scheduler: {e}")
                time.sleep(30)

    def _execute_task(self, task):
        """Esegue un singolo task"""
        try:
            task_type = task['type']
            target = task['target']

            print(f"Esecuzione task {task_type} su {target}")

            if task_type == 'discovery':
                self.scanner.run_discovery_scan()

            elif task_type == 'services':
                self.scanner.run_services_scan(target)

            elif task_type == 'os':
                self.scanner.run_os_scan(target)

            elif task_type == 'vulnerabilities':
                self.scanner.run_vulnerability_scan(target)

            elif task_type == 'snmp':
                self.scanner.run_snmp_scan(target)

            else:
                print(f"Task type sconosciuto: {task_type}")

        except Exception as e:
            print(f"Errore esecuzione task {task['type']}: {e}")

    def get_scheduled_tasks(self):
        """Ottiene lista task programmati"""
        with self.lock:
            return [task for _, _, task in self.task_queue]

    def auto_schedule_maintenance(self):
        """Programma automaticamente scansioni di mantenimento"""
        # Programma discovery ogni 10 minuti
        self.schedule_recurring_task('discovery', 'network', minutes=10, priority=1)

        # Programma scansioni follow-up per nuovi dispositivi
        self._schedule_device_follow_ups()

    def schedule_recurring_task(self, task_type, target, minutes=60, priority=5):
        """Programma task ricorrente"""

        def recurring_scheduler():
            while self.running:
                self.schedule_task(task_type, target, priority)
                time.sleep(minutes * 60)

        thread = threading.Thread(target=recurring_scheduler, daemon=True)
        thread.start()

    def _schedule_device_follow_ups(self):
        """Programma scansioni di follow-up per dispositivi"""
        conn = self.db.get_connection()
        cursor = conn.cursor()

        # Dispositivi senza scansione servizi recente
        cursor.execute('''
            SELECT d.id, d.ip_address
            FROM devices d
            LEFT JOIN scan_history sh ON d.id = sh.target AND sh.scan_type = 'services'
            WHERE d.is_active = 1 
            AND (sh.id IS NULL OR sh.start_time < datetime('now', '-6 hours'))
            LIMIT 10
        ''')

        for row in cursor.fetchall():
            # Programma scansione servizi con delay casuale
            delay = hash(row['ip_address']) % 3600  # 0-60 minuti
            self.schedule_task('services', row['id'], priority=3, delay_seconds=delay)

        conn.close()