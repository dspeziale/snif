/**
 * AdminLTE Custom Utilities - Fixed Version
 * Gestisce form, notifiche e DataTables
 */

// Namespace globale AdminLTE
window.AdminLTE = window.AdminLTE || {};

// ===============================
// GESTIONE FORM
// ===============================
AdminLTE.Forms = {
    /**
     * Valida e invia un form via AJAX
     */
    validateAndSubmit: function(formSelector, apiUrl, options = {}) {
        const form = document.querySelector(formSelector);
        if (!form) {
            console.error('Form not found:', formSelector);
            return;
        }

        // Opzioni di default
        const defaults = {
            method: 'POST',
            successMessage: 'Operation completed successfully',
            errorMessage: 'An error occurred',
            closeModal: null,
            onSuccess: null,
            onError: null,
            validateForm: true
        };

        const config = { ...defaults, ...options };

        // Validazione form se richiesta
        if (config.validateForm && !form.checkValidity()) {
            form.reportValidity();
            return;
        }

        // Raccogli i dati del form
        const formData = new FormData(form);
        const jsonData = {};

        // Converti FormData in oggetto JSON
        for (let [key, value] of formData.entries()) {
            // Gestisci checkbox
            if (form.querySelector(`[name="${key}"]`).type === 'checkbox') {
                jsonData[key] = form.querySelector(`[name="${key}"]`).checked;
            } else {
                jsonData[key] = value;
            }
        }

        // Aggiungi dati da input non in FormData (come i select)
        form.querySelectorAll('input, select, textarea').forEach(input => {
            if (!jsonData.hasOwnProperty(input.name) && input.name) {
                if (input.type === 'checkbox') {
                    jsonData[input.name] = input.checked;
                } else {
                    jsonData[input.name] = input.value;
                }
            }
        });

        console.log('Sending data:', jsonData);

        // Invia richiesta AJAX
        fetch(apiUrl, {
            method: config.method,
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(jsonData)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Successo
                if (window.NotificationUtils) {
                    window.NotificationUtils.success(data.message || config.successMessage);
                } else {
                    alert(data.message || config.successMessage);
                }

                // Chiudi modal se specificato
                if (config.closeModal) {
                    const modal = bootstrap.Modal.getInstance(document.querySelector(config.closeModal));
                    if (modal) {
                        modal.hide();
                    }
                }

                // Callback di successo
                if (config.onSuccess) {
                    config.onSuccess(data);
                }

                // Reset form
                form.reset();

            } else {
                throw new Error(data.error || 'Operation failed');
            }
        })
        .catch(error => {
            console.error('Form submission error:', error);

            if (window.NotificationUtils) {
                window.NotificationUtils.error(error.message || config.errorMessage);
            } else {
                alert(error.message || config.errorMessage);
            }

            // Callback di errore
            if (config.onError) {
                config.onError(error);
            }
        });
    }
};

// ===============================
// GESTIONE NOTIFICHE
// ===============================
AdminLTE.Notifications = {
    success: function(message, title = 'Success') {
        if (window.NotificationUtils) {
            return window.NotificationUtils.success(message, title);
        } else {
            alert(`${title}: ${message}`);
        }
    },

    error: function(message, title = 'Error') {
        if (window.NotificationUtils) {
            return window.NotificationUtils.error(message, title);
        } else {
            alert(`${title}: ${message}`);
        }
    },

    warning: function(message, title = 'Warning') {
        if (window.NotificationUtils) {
            return window.NotificationUtils.warning(message, title);
        } else {
            alert(`${title}: ${message}`);
        }
    },

    info: function(message, title = 'Info') {
        if (window.NotificationUtils) {
            return window.NotificationUtils.info(message, title);
        } else {
            alert(`${title}: ${message}`);
        }
    },

    confirm: function(message, title = 'Confirm', onConfirm, onCancel) {
        if (window.NotificationUtils) {
            return window.NotificationUtils.confirm(message, title, onConfirm, onCancel);
        } else {
            if (confirm(`${title}: ${message}`)) {
                if (onConfirm) onConfirm();
            } else {
                if (onCancel) onCancel();
            }
        }
    },

    async: function(promise, loadingMessage = 'Processing...', successMessage = 'Completed') {
        if (window.NotificationUtils) {
            return window.NotificationUtils.async(promise, loadingMessage, successMessage);
        } else {
            return promise.then(result => {
                alert(successMessage);
                return result;
            }).catch(error => {
                alert('Error: ' + error.message);
                throw error;
            });
        }
    }
};

// ===============================
// GESTIONE DATATABLES
// ===============================
AdminLTE.DataTables = {
    /**
     * Inizializza una DataTable per i messaggi
     */
    initMessagesTable: function(selector, ajaxUrl = null) {
        const tableOptions = {
            responsive: true,
            processing: true,
            pageLength: 25,
            order: [[8, 'desc']], // Ordina per data (colonna Time)
            columnDefs: [
                { orderable: false, targets: [0, 1, 9] }, // Checkbox, Avatar, Actions
                { searchable: false, targets: [0, 1, 9] }
            ],
            language: {
                processing: '<i class="bi bi-arrow-clockwise"></i> Loading messages...',
                emptyTable: 'No messages found',
                zeroRecords: 'No matching messages found'
            }
        };

        // Se è specificato un URL AJAX, usa server-side processing
        if (ajaxUrl) {
            tableOptions.serverSide = true;
            tableOptions.ajax = {
                url: ajaxUrl,
                type: 'GET',
                error: function(xhr, error, thrown) {
                    console.error('DataTables AJAX error:', error);
                    AdminLTE.Notifications.error('Failed to load messages: ' + error);
                }
            };
        }

        return $(selector).DataTable(tableOptions);
    },

    /**
     * Inizializza una DataTable per le notifiche
     */
    initNotificationsTable: function(selector, ajaxUrl = null) {
        const tableOptions = {
            responsive: true,
            processing: true,
            pageLength: 25,
            order: [[8, 'desc']], // Ordina per data
            columnDefs: [
                { orderable: false, targets: [0, 1, 9] }, // Checkbox, Icon, Actions
                { searchable: false, targets: [0, 1, 9] }
            ],
            language: {
                processing: '<i class="bi bi-arrow-clockwise"></i> Loading notifications...',
                emptyTable: 'No notifications found',
                zeroRecords: 'No matching notifications found'
            }
        };

        if (ajaxUrl) {
            tableOptions.serverSide = true;
            tableOptions.ajax = {
                url: ajaxUrl,
                type: 'GET',
                error: function(xhr, error, thrown) {
                    console.error('DataTables AJAX error:', error);
                    AdminLTE.Notifications.error('Failed to load notifications: ' + error);
                }
            };
        }

        return $(selector).DataTable(tableOptions);
    },

    /**
     * Aggiorna una DataTable
     */
    refreshTable: function(table) {
        if (table && table.ajax) {
            table.ajax.reload(null, false); // Mantieni la pagina corrente
        } else if (table) {
            table.draw(false);
        }
    },

    /**
     * Esporta una DataTable
     */
    exportTable: function(table, format = 'excel') {
        if (table && table.button) {
            switch (format) {
                case 'excel':
                    table.button('.buttons-excel').trigger();
                    break;
                case 'csv':
                    table.button('.buttons-csv').trigger();
                    break;
                case 'pdf':
                    table.button('.buttons-pdf').trigger();
                    break;
                default:
                    console.warn('Unknown export format:', format);
            }
        }
    }
};

// ===============================
// GESTIONE AZIONI
// ===============================
AdminLTE.Actions = {
    /**
     * Segna un messaggio come letto
     */
    markMessageRead: function(messageId) {
        fetch(`/api/messages/${messageId}/read`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                AdminLTE.Notifications.success('Message marked as read');
                // Rimuovi la classe unread dalla riga
                const row = document.querySelector(`[data-message-id="${messageId}"]`);
                if (row) {
                    row.classList.remove('table-row-unread');
                    // Rimuovi il badge "Unread"
                    const unreadBadge = row.querySelector('.badge.bg-warning');
                    if (unreadBadge && unreadBadge.textContent === 'Unread') {
                        unreadBadge.textContent = 'Read';
                        unreadBadge.className = 'badge bg-success';
                    }
                }
            } else {
                AdminLTE.Notifications.error(data.error || 'Failed to mark message as read');
            }
        })
        .catch(error => {
            AdminLTE.Notifications.error('Error: ' + error.message);
        });
    },

    /**
     * Visualizza un messaggio
     */
    viewMessage: function(messageId) {
        fetch(`/api/messages/${messageId}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const message = data.data || data.message;

                // Mostra il messaggio in un modal
                const modalHtml = `
                    <div class="modal fade" id="viewMessageModal" tabindex="-1">
                        <div class="modal-dialog modal-lg">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title">Message from ${message.sender}</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                </div>
                                <div class="modal-body">
                                    <h6>${message.subject || 'No Subject'}</h6>
                                    <p>${message.content}</p>
                                    <small class="text-muted">Received: ${message.time}</small>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                </div>
                            </div>
                        </div>
                    </div>
                `;

                // Aggiungi il modal al DOM se non esiste
                let existingModal = document.getElementById('viewMessageModal');
                if (existingModal) {
                    existingModal.remove();
                }

                document.body.insertAdjacentHTML('beforeend', modalHtml);

                // Mostra il modal
                const modal = new bootstrap.Modal(document.getElementById('viewMessageModal'));
                modal.show();

                // Segna come letto se non lo è già
                if (message.unread) {
                    this.markMessageRead(messageId);
                }
            } else {
                AdminLTE.Notifications.error(data.error || 'Failed to load message');
            }
        })
        .catch(error => {
            AdminLTE.Notifications.error('Error: ' + error.message);
        });
    },

    /**
     * Archivia un messaggio
     */
    archiveMessage: function(messageId) {
        AdminLTE.Notifications.confirm(
            'Archive this message?',
            'Confirm Archive',
            () => {
                fetch(`/api/messages/${messageId}/archive`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        AdminLTE.Notifications.success('Message archived');
                        // Rimuovi la riga o aggiorna lo stato
                        const row = document.querySelector(`[data-message-id="${messageId}"]`);
                        if (row) {
                            row.style.opacity = '0.5';
                            // Aggiorna il badge di stato
                            const statusBadge = row.querySelector('.badge.bg-success, .badge.bg-warning');
                            if (statusBadge) {
                                statusBadge.textContent = 'Archived';
                                statusBadge.className = 'badge bg-secondary';
                            }
                        }
                    } else {
                        AdminLTE.Notifications.error(data.error || 'Failed to archive message');
                    }
                })
                .catch(error => {
                    AdminLTE.Notifications.error('Error: ' + error.message);
                });
            }
        );
    },

    /**
     * Elimina un messaggio
     */
    deleteMessage: function(messageId) {
        AdminLTE.Notifications.confirm(
            'Delete this message permanently?',
            'Confirm Delete',
            () => {
                fetch(`/api/messages/${messageId}`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        AdminLTE.Notifications.success('Message deleted');
                        // Rimuovi la riga
                        const row = document.querySelector(`[data-message-id="${messageId}"]`);
                        if (row) {
                            row.remove();
                        }
                    } else {
                        AdminLTE.Notifications.error(data.error || 'Failed to delete message');
                    }
                })
                .catch(error => {
                    AdminLTE.Notifications.error('Error: ' + error.message);
                });
            }
        );
    },

    // Azioni per le notifiche (simili ai messaggi)
    markNotificationRead: function(notificationId) {
        fetch(`/api/notifications/${notificationId}/read`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                AdminLTE.Notifications.success('Notification marked as read');
                const row = document.querySelector(`[data-notification-id="${notificationId}"]`);
                if (row) {
                    row.classList.remove('table-row-unread');
                }
            } else {
                AdminLTE.Notifications.error(data.error || 'Failed to mark notification as read');
            }
        })
        .catch(error => {
            AdminLTE.Notifications.error('Error: ' + error.message);
        });
    },

    viewNotification: function(notificationId) {
        fetch(`/api/notifications/${notificationId}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const notification = data.data || data.notification;

                const modalHtml = `
                    <div class="modal fade" id="viewNotificationModal" tabindex="-1">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title">Notification</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                </div>
                                <div class="modal-body">
                                    <p>${notification.message}</p>
                                    <small class="text-muted">Time: ${notification.time}</small>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                </div>
                            </div>
                        </div>
                    </div>
                `;

                let existingModal = document.getElementById('viewNotificationModal');
                if (existingModal) {
                    existingModal.remove();
                }

                document.body.insertAdjacentHTML('beforeend', modalHtml);
                const modal = new bootstrap.Modal(document.getElementById('viewNotificationModal'));
                modal.show();

                if (!notification.read) {
                    this.markNotificationRead(notificationId);
                }
            } else {
                AdminLTE.Notifications.error(data.error || 'Failed to load notification');
            }
        })
        .catch(error => {
            AdminLTE.Notifications.error('Error: ' + error.message);
        });
    },

    dismissNotification: function(notificationId) {
        AdminLTE.Notifications.confirm(
            'Dismiss this notification?',
            'Confirm Dismiss',
            () => {
                fetch(`/api/notifications/${notificationId}/dismiss`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        AdminLTE.Notifications.success('Notification dismissed');
                        const row = document.querySelector(`[data-notification-id="${notificationId}"]`);
                        if (row) {
                            row.style.opacity = '0.5';
                        }
                    } else {
                        AdminLTE.Notifications.error(data.error || 'Failed to dismiss notification');
                    }
                })
                .catch(error => {
                    AdminLTE.Notifications.error('Error: ' + error.message);
                });
            }
        );
    },

    deleteNotification: function(notificationId) {
        AdminLTE.Notifications.confirm(
            'Delete this notification permanently?',
            'Confirm Delete',
            () => {
                fetch(`/api/notifications/${notificationId}`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        AdminLTE.Notifications.success('Notification deleted');
                        const row = document.querySelector(`[data-notification-id="${notificationId}"]`);
                        if (row) {
                            row.remove();
                        }
                    } else {
                        AdminLTE.Notifications.error(data.error || 'Failed to delete notification');
                    }
                })
                .catch(error => {
                    AdminLTE.Notifications.error('Error: ' + error.message);
                });
            }
        );
    }
};

// ===============================
// UTILITÀ GLOBALI
// ===============================
AdminLTE.Utils = {
    /**
     * Formatta una data
     */
    formatDate: function(dateString) {
        try {
            const date = new Date(dateString);
            return date.toLocaleString();
        } catch (error) {
            return dateString;
        }
    },

    /**
     * Debounce function
     */
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Aggiorna i contatori della navbar
     */
    updateNavbarCounters: function() {
        // Aggiorna contatore messaggi
        fetch('/api/messages?limit=1&unread_only=true')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const counter = document.getElementById('messages-count');
                if (counter) {
                    counter.textContent = data.unread_count || 0;
                    if (data.unread_count === 0) {
                        counter.style.display = 'none';
                    } else {
                        counter.style.display = 'inline';
                    }
                }
            }
        })
        .catch(error => console.error('Error updating message counter:', error));

        // Aggiorna contatore notifiche
        fetch('/api/notifications?limit=1&unread_only=true')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const counter = document.getElementById('notifications-count');
                if (counter) {
                    counter.textContent = data.unread_count || 0;
                    if (data.unread_count === 0) {
                        counter.style.display = 'none';
                    } else {
                        counter.style.display = 'inline';
                    }
                }
            }
        })
        .catch(error => console.error('Error updating notification counter:', error));
    }
};

// ===============================
// INIZIALIZZAZIONE
// ===============================
document.addEventListener('DOMContentLoaded', function() {
    console.log('AdminLTE Custom Utilities loaded successfully');

    // Aggiorna i contatori ogni 30 secondi
    setInterval(AdminLTE.Utils.updateNavbarCounters, 30000);

    // Setup globale per i form
    document.querySelectorAll('form[data-ajax="true"]').forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const apiUrl = this.getAttribute('data-url') || this.action;
            AdminLTE.Forms.validateAndSubmit(`#${this.id}`, apiUrl);
        });
    });
});

// ===============================
// FUNZIONI GLOBALI PER COMPATIBILITÀ
// ===============================

// Funzioni globali per i template
window.createMessage = function() {
    // Raccogli i dati manualmente dai campi del form
    const messageData = {
        sender: document.getElementById('messageSender').value,
        subject: document.getElementById('messageSubject').value,
        content: document.getElementById('messageContent').value,
        type: document.getElementById('messageType').value,
        priority: document.getElementById('messagePriority').value,
        avatar: document.getElementById('messageAvatar').value
    };

    // Validazione di base
    if (!messageData.sender || !messageData.content) {
        AdminLTE.Notifications.warning('Please fill in sender and content fields');
        return;
    }

    if (messageData.content.length > 1000) {
        AdminLTE.Notifications.warning('Message content is too long (max 1000 characters)');
        return;
    }

    console.log('Creating message with data:', messageData);

    // Invia i dati
    fetch('/api/messages', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(messageData)
    })
    .then(response => {
        console.log('Response status:', response.status);
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.error || `HTTP ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('Success response:', data);
        if (data.success) {
            AdminLTE.Notifications.success(data.message || 'Message created successfully');

            // Chiudi il modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('newMessageModal'));
            if (modal) {
                modal.hide();
            }

            // Aggiorna la tabella se esiste
            if (typeof messagesTable !== 'undefined' && messagesTable) {
                AdminLTE.DataTables.refreshTable(messagesTable);
            }

            // Aggiorna i contatori
            AdminLTE.Utils.updateNavbarCounters();
        } else {
            throw new Error(data.error || 'Operation failed');
        }
    })
    .catch(error => {
        console.error('Error creating message:', error);
        AdminLTE.Notifications.error(error.message || 'Failed to create message');
    });
};

window.createNotification = function() {
    const notificationData = {
        message: document.getElementById('notificationMessage').value,
        type: document.getElementById('notificationType').value,
        category: document.getElementById('notificationCategory').value,
        priority: document.getElementById('notificationPriority').value,
        icon: 'bi-' + document.getElementById('notificationIcon').value,
        action_url: document.getElementById('notificationActionUrl').value
    };

    if (!notificationData.message) {
        AdminLTE.Notifications.warning('Please enter a notification message');
        return;
    }

    fetch('/api/notifications', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(notificationData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            AdminLTE.Notifications.success(data.message || 'Notification created successfully');

            const modal = bootstrap.Modal.getInstance(document.getElementById('newNotificationModal'));
            if (modal) {
                modal.hide();
            }

            if (typeof notificationsTable !== 'undefined' && notificationsTable) {
                AdminLTE.DataTables.refreshTable(notificationsTable);
            }

            AdminLTE.Utils.updateNavbarCounters();
        } else {
            throw new Error(data.error || 'Operation failed');
        }
    })
    .catch(error => {
        console.error('Error creating notification:', error);
        AdminLTE.Notifications.error(error.message || 'Failed to create notification');
    });
};