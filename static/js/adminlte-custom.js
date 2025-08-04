/**
 * AdminLTE Flask Dashboard - Custom JavaScript Utilities
 * Provides utilities for DataTables, Notifications, Forms, and Actions
 */

// Wait for DOM and jQuery to be ready
$(document).ready(function() {
    'use strict';

    // Initialize AdminLTE namespace
    window.AdminLTE = window.AdminLTE || {};

    /**
     * DataTables Utilities
     */
    AdminLTE.DataTables = {
        // Default configuration for all DataTables
        defaultConfig: {
            responsive: true,
            processing: true,
            pageLength: 25,
            lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
            order: [],
            language: {
                processing: '<i class="bi bi-arrow-clockwise spin"></i> Loading...',
                search: "",
                searchPlaceholder: "Search...",
                lengthMenu: "Show _MENU_ entries",
                info: "Showing _START_ to _END_ of _TOTAL_ entries",
                infoEmpty: "Showing 0 to 0 of 0 entries",
                infoFiltered: "(filtered from _MAX_ total entries)",
                emptyTable: "No data available",
                paginate: {
                    first: "First",
                    last: "Last",
                    next: "Next",
                    previous: "Previous"
                }
            },
            dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>' +
                 '<"row"<"col-sm-12"tr>>' +
                 '<"row"<"col-sm-12 col-md-5"i><"col-sm-12 col-md-7"p>>',
            columnDefs: [
                { orderable: false, targets: 'no-sort' },
                { searchable: false, targets: 'no-search' }
            ]
        },

        // Initialize Messages DataTable
        initMessagesTable: function(selector, ajaxUrl = null) {
            const config = $.extend(true, {}, this.defaultConfig, {
                ajax: ajaxUrl ? {
                    url: ajaxUrl,
                    type: 'GET',
                    error: function(xhr, error, code) {
                        console.error('DataTables Ajax error:', error);
                        AdminLTE.Notifications.error('Failed to load messages: ' + error);
                    }
                } : null,
                columns: ajaxUrl ? [
                    { data: null, render: function(data, type, row) {
                        return `<input type="checkbox" class="message-checkbox" value="${row.id}">`;
                    }},
                    { data: 'avatar', render: function(data, type, row) {
                        return `<img src="${data || '/static/assets/img/user-default.jpg'}" alt="Avatar" class="img-circle" width="40" height="40">`;
                    }},
                    { data: 'sender' },
                    { data: 'subject', render: function(data, type, row) {
                        return data || 'No Subject';
                    }},
                    { data: 'content', render: function(data, type, row) {
                        return data.length > 100 ? data.substring(0, 100) + '...' : data;
                    }},
                    { data: 'type_info', render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}"><i class="bi ${data.icon} me-1"></i>${data.label}</span>`;
                        }
                        return '<span class="badge bg-secondary">Unknown</span>';
                    }},
                    { data: 'priority_info', render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}"><i class="bi ${data.icon} me-1"></i>${data.label}</span>`;
                        }
                        return '<span class="badge bg-secondary">Normal</span>';
                    }},
                    { data: 'unread', render: function(data, type, row) {
                        if (data) {
                            return '<span class="badge bg-warning">Unread</span>';
                        } else if (row.archived) {
                            return '<span class="badge bg-secondary">Archived</span>';
                        } else {
                            return '<span class="badge bg-success">Read</span>';
                        }
                    }},
                    { data: 'time' },
                    { data: null, render: function(data, type, row) {
                        let buttons = '<div class="btn-group btn-group-sm" role="group">';

                        if (row.unread) {
                            buttons += `<button class="btn btn-outline-success" onclick="AdminLTE.Actions.markMessageRead(${row.id})" title="Mark as Read">
                                <i class="bi bi-check"></i>
                            </button>`;
                        }

                        buttons += `<button class="btn btn-outline-primary" onclick="AdminLTE.Actions.viewMessage(${row.id})" title="View">
                            <i class="bi bi-eye"></i>
                        </button>`;

                        if (!row.archived) {
                            buttons += `<button class="btn btn-outline-warning" onclick="AdminLTE.Actions.archiveMessage(${row.id})" title="Archive">
                                <i class="bi bi-archive"></i>
                            </button>`;
                        }

                        buttons += `<button class="btn btn-outline-danger" onclick="AdminLTE.Actions.deleteMessage(${row.id})" title="Delete">
                            <i class="bi bi-trash"></i>
                        </button>`;

                        buttons += '</div>';
                        return buttons;
                    }}
                ] : null
            });

            return $(selector).DataTable(config);
        },

        // Initialize Notifications DataTable
        initNotificationsTable: function(selector, ajaxUrl = null) {
            const config = $.extend(true, {}, this.defaultConfig, {
                ajax: ajaxUrl ? {
                    url: ajaxUrl,
                    type: 'GET',
                    error: function(xhr, error, code) {
                        console.error('DataTables Ajax error:', error);
                        AdminLTE.Notifications.error('Failed to load notifications: ' + error);
                    }
                } : null,
                columns: ajaxUrl ? [
                    { data: null, render: function(data, type, row) {
                        return `<input type="checkbox" class="notification-checkbox" value="${row.id}">`;
                    }},
                    { data: 'icon', render: function(data, type, row) {
                        const iconClass = data || 'bi-bell';
                        const color = row.type_info ? `text-${row.type_info.color}` : 'text-info';
                        return `<i class="bi ${iconClass} ${color}" style="font-size: 1.5em;"></i>`;
                    }},
                    { data: 'message', render: function(data, type, row) {
                        const truncated = data.length > 150 ? data.substring(0, 150) + '...' : data;
                        let html = `<div class="notification-message">${truncated}</div>`;
                        if (!row.read) {
                            html += '<span class="badge bg-danger badge-sm">New</span>';
                        }
                        return html;
                    }},
                    { data: 'type_info', render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}"><i class="bi ${data.icon} me-1"></i>${data.label}</span>`;
                        }
                        return '<span class="badge bg-secondary">Unknown</span>';
                    }},
                    { data: 'category_info', render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}"><i class="bi ${data.icon} me-1"></i>${data.label}</span>`;
                        }
                        return '<span class="badge bg-secondary">General</span>';
                    }},
                    { data: 'priority_info', render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}"><i class="bi ${data.icon} me-1"></i>${data.label}</span>`;
                        }
                        return '<span class="badge bg-secondary">Normal</span>';
                    }},
                    { data: 'read', render: function(data, type, row) {
                        if (!data) {
                            return '<span class="badge bg-warning">Unread</span>';
                        } else if (row.dismissed) {
                            return '<span class="badge bg-secondary">Dismissed</span>';
                        } else {
                            return '<span class="badge bg-success">Read</span>';
                        }
                    }},
                    { data: 'action_url', render: function(data, type, row) {
                        if (data) {
                            const truncated = data.length > 30 ? data.substring(0, 30) + '...' : data;
                            return `<small><a href="${data}" class="text-decoration-none" target="_blank">
                                ${truncated} <i class="bi bi-box-arrow-up-right"></i>
                            </a></small>`;
                        }
                        return '<small class="text-muted">No action</small>';
                    }},
                    { data: 'time' },
                    { data: null, render: function(data, type, row) {
                        let buttons = '<div class="btn-group btn-group-sm" role="group">';

                        if (!row.read) {
                            buttons += `<button class="btn btn-outline-success" onclick="AdminLTE.Actions.markNotificationRead(${row.id})" title="Mark as Read">
                                <i class="bi bi-check"></i>
                            </button>`;
                        }

                        buttons += `<button class="btn btn-outline-primary" onclick="AdminLTE.Actions.viewNotification(${row.id})" title="View">
                            <i class="bi bi-eye"></i>
                        </button>`;

                        if (!row.dismissed) {
                            buttons += `<button class="btn btn-outline-warning" onclick="AdminLTE.Actions.dismissNotification(${row.id})" title="Dismiss">
                                <i class="bi bi-x-circle"></i>
                            </button>`;
                        }

                        buttons += `<button class="btn btn-outline-danger" onclick="AdminLTE.Actions.deleteNotification(${row.id})" title="Delete">
                            <i class="bi bi-trash"></i>
                        </button>`;

                        buttons += '</div>';
                        return buttons;
                    }}
                ] : null
            });

            return $(selector).DataTable(config);
        },

        // Refresh table data
        refreshTable: function(table) {
            if (table && table.ajax) {
                table.ajax.reload(null, false);
            } else if (table) {
                table.draw();
            }
        },

        // Export table data
        exportTable: function(table, format) {
            if (!table) return;

            switch (format.toLowerCase()) {
                case 'excel':
                    table.button('.buttons-excel').trigger();
                    break;
                case 'csv':
                    table.button('.buttons-csv').trigger();
                    break;
                case 'pdf':
                    table.button('.buttons-pdf').trigger();
                    break;
                case 'print':
                    table.button('.buttons-print').trigger();
                    break;
                default:
                    AdminLTE.Notifications.warning('Unsupported export format: ' + format);
            }
        }
    };

    /**
     * Notification Utilities (using Awesome Notifications)
     */
    AdminLTE.Notifications = {
        success: function(message, title = 'Success') {
            if (window.NotificationUtils) {
                return window.NotificationUtils.success(message, title);
            } else {
                console.log('Success:', message);
                alert(title + ': ' + message);
            }
        },

        error: function(message, title = 'Error') {
            if (window.NotificationUtils) {
                return window.NotificationUtils.error(message, title);
            } else {
                console.error('Error:', message);
                alert(title + ': ' + message);
            }
        },

        warning: function(message, title = 'Warning') {
            if (window.NotificationUtils) {
                return window.NotificationUtils.warning(message, title);
            } else {
                console.warn('Warning:', message);
                alert(title + ': ' + message);
            }
        },

        info: function(message, title = 'Info') {
            if (window.NotificationUtils) {
                return window.NotificationUtils.info(message, title);
            } else {
                console.info('Info:', message);
                alert(title + ': ' + message);
            }
        },

        confirm: function(message, title = 'Confirm', onOk, onCancel) {
            if (window.NotificationUtils) {
                return window.NotificationUtils.confirm(message, title, onOk, onCancel);
            } else {
                const result = confirm(title + ': ' + message);
                if (result && onOk) onOk();
                else if (!result && onCancel) onCancel();
                return result;
            }
        },

        async: function(promise, loadingMessage = 'Processing...', successMessage = 'Operation completed successfully') {
            if (window.NotificationUtils) {
                return window.NotificationUtils.async(promise, loadingMessage, successMessage);
            } else {
                console.log(loadingMessage);
                return promise.then(result => {
                    console.log(successMessage);
                    return result;
                }).catch(error => {
                    console.error('Error:', error);
                    throw error;
                });
            }
        }
    };

    /**
     * Form Utilities
     */
    AdminLTE.Forms = {
        // Validate and submit form via AJAX
        validateAndSubmit: function(formSelector, url, options = {}) {
            const form = $(formSelector);
            const formData = this.serializeForm(form);

            // Basic validation
            if (options.validate && !options.validate(formData)) {
                return;
            }

            // Submit via AJAX
            AdminLTE.Notifications.async(
                fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                })
                .then(response => response.json())
                .then(data => {
                    if (!data.success) {
                        throw new Error(data.error || 'Operation failed');
                    }

                    // Close modal if specified
                    if (options.closeModal) {
                        const modal = bootstrap.Modal.getInstance(document.querySelector(options.closeModal));
                        if (modal) modal.hide();
                    }

                    // Reset form if specified
                    if (options.resetForm !== false) {
                        form[0].reset();
                    }

                    // Call success callback
                    if (options.onSuccess) {
                        options.onSuccess(data);
                    }

                    return data;
                }),
                'Submitting...',
                options.successMessage || 'Operation completed successfully'
            );
        },

        // Serialize form to object
        serializeForm: function(form) {
            const formData = {};
            const arrayData = form.serializeArray();

            $.each(arrayData, function(i, field) {
                if (formData[field.name]) {
                    if (!Array.isArray(formData[field.name])) {
                        formData[field.name] = [formData[field.name]];
                    }
                    formData[field.name].push(field.value);
                } else {
                    formData[field.name] = field.value;
                }
            });

            // Handle checkboxes
            form.find('input[type="checkbox"]').each(function() {
                formData[this.name] = this.checked;
            });

            return formData;
        }
    };

    /**
     * Action Utilities
     */
    AdminLTE.Actions = {
        // Message actions
        markMessageRead: function(messageId) {
            AdminLTE.Notifications.async(
                fetch(`/api/messages/${messageId}/read`, { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (!data.success) throw new Error(data.error);
                        return data;
                    }),
                'Marking message as read...',
                'Message marked as read'
            );
        },

        viewMessage: function(messageId) {
            AdminLTE.Notifications.info('View message functionality would be implemented here');
        },

        archiveMessage: function(messageId) {
            AdminLTE.Notifications.confirm(
                'Archive this message?',
                'Confirm Archive',
                () => {
                    AdminLTE.Notifications.async(
                        fetch(`/api/messages/${messageId}/archive`, { method: 'POST' })
                            .then(response => response.json())
                            .then(data => {
                                if (!data.success) throw new Error(data.error);
                                return data;
                            }),
                        'Archiving message...',
                        'Message archived'
                    );
                }
            );
        },

        deleteMessage: function(messageId) {
            AdminLTE.Notifications.confirm(
                'Delete this message? This action cannot be undone.',
                'Confirm Delete',
                () => {
                    AdminLTE.Notifications.async(
                        fetch(`/api/messages/${messageId}`, { method: 'DELETE' })
                            .then(response => response.json())
                            .then(data => {
                                if (!data.success) throw new Error(data.error);
                                return data;
                            }),
                        'Deleting message...',
                        'Message deleted'
                    );
                }
            );
        },

        // Notification actions
        markNotificationRead: function(notificationId) {
            AdminLTE.Notifications.async(
                fetch(`/api/notifications/${notificationId}/read`, { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (!data.success) throw new Error(data.error);
                        return data;
                    }),
                'Marking notification as read...',
                'Notification marked as read'
            );
        },

        viewNotification: function(notificationId) {
            AdminLTE.Notifications.info('View notification functionality would be implemented here');
        },

        dismissNotification: function(notificationId) {
            AdminLTE.Notifications.confirm(
                'Dismiss this notification?',
                'Confirm Dismiss',
                () => {
                    AdminLTE.Notifications.async(
                        fetch(`/api/notifications/${notificationId}/dismiss`, { method: 'POST' })
                            .then(response => response.json())
                            .then(data => {
                                if (!data.success) throw new Error(data.error);
                                return data;
                            }),
                        'Dismissing notification...',
                        'Notification dismissed'
                    );
                }
            );
        },

        deleteNotification: function(notificationId) {
            AdminLTE.Notifications.confirm(
                'Delete this notification? This action cannot be undone.',
                'Confirm Delete',
                () => {
                    AdminLTE.Notifications.async(
                        fetch(`/api/notifications/${notificationId}`, { method: 'DELETE' })
                            .then(response => response.json())
                            .then(data => {
                                if (!data.success) throw new Error(data.error);
                                return data;
                            }),
                        'Deleting notification...',
                        'Notification deleted'
                    );
                }
            );
        },

        // Bulk actions
        bulkMarkMessagesRead: function(messageIds) {
            if (!messageIds || messageIds.length === 0) {
                AdminLTE.Notifications.warning('No messages selected');
                return;
            }

            AdminLTE.Notifications.confirm(
                `Mark ${messageIds.length} message(s) as read?`,
                'Confirm Bulk Action',
                () => {
                    const promises = messageIds.map(id =>
                        fetch(`/api/messages/${id}/read`, { method: 'POST' })
                    );

                    AdminLTE.Notifications.async(
                        Promise.all(promises),
                        'Marking messages as read...',
                        `${messageIds.length} messages marked as read`
                    );
                }
            );
        },

        bulkDeleteMessages: function(messageIds) {
            if (!messageIds || messageIds.length === 0) {
                AdminLTE.Notifications.warning('No messages selected');
                return;
            }

            AdminLTE.Notifications.confirm(
                `Delete ${messageIds.length} message(s)? This action cannot be undone.`,
                'Confirm Bulk Delete',
                () => {
                    const promises = messageIds.map(id =>
                        fetch(`/api/messages/${id}`, { method: 'DELETE' })
                    );

                    AdminLTE.Notifications.async(
                        Promise.all(promises),
                        'Deleting messages...',
                        `${messageIds.length} messages deleted`
                    );
                }
            );
        },

        bulkMarkNotificationsRead: function(notificationIds) {
            if (!notificationIds || notificationIds.length === 0) {
                AdminLTE.Notifications.warning('No notifications selected');
                return;
            }

            AdminLTE.Notifications.confirm(
                `Mark ${notificationIds.length} notification(s) as read?`,
                'Confirm Bulk Action',
                () => {
                    const promises = notificationIds.map(id =>
                        fetch(`/api/notifications/${id}/read`, { method: 'POST' })
                    );

                    AdminLTE.Notifications.async(
                        Promise.all(promises),
                        'Marking notifications as read...',
                        `${notificationIds.length} notifications marked as read`
                    );
                }
            );
        },

        bulkDeleteNotifications: function(notificationIds) {
            if (!notificationIds || notificationIds.length === 0) {
                AdminLTE.Notifications.warning('No notifications selected');
                return;
            }

            AdminLTE.Notifications.confirm(
                `Delete ${notificationIds.length} notification(s)? This action cannot be undone.`,
                'Confirm Bulk Delete',
                () => {
                    const promises = notificationIds.map(id =>
                        fetch(`/api/notifications/${id}`, { method: 'DELETE' })
                    );

                    AdminLTE.Notifications.async(
                        Promise.all(promises),
                        'Deleting notifications...',
                        `${notificationIds.length} notifications deleted`
                    );
                }
            );
        }
    };

    /**
     * General Utilities
     */
    AdminLTE.Utils = {
        // Format numbers
        formatNumber: function(num, decimals = 0) {
            return new Intl.NumberFormat('en-US', {
                minimumFractionDigits: decimals,
                maximumFractionDigits: decimals
            }).format(num);
        },

        // Format dates
        formatDate: function(date, format = 'short') {
            if (!date) return '';

            const dateObj = typeof date === 'string' ? new Date(date) : date;

            switch (format) {
                case 'short':
                    return dateObj.toLocaleDateString();
                case 'long':
                    return dateObj.toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                    });
                case 'time':
                    return dateObj.toLocaleTimeString();
                case 'datetime':
                    return dateObj.toLocaleString();
                default:
                    return dateObj.toString();
            }
        },

        // Debounce function
        debounce: function(func, wait, immediate) {
            let timeout;
            return function executedFunction() {
                const context = this;
                const args = arguments;
                const later = function() {
                    timeout = null;
                    if (!immediate) func.apply(context, args);
                };
                const callNow = immediate && !timeout;
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
                if (callNow) func.apply(context, args);
            };
        },

        // Generate random ID
        generateId: function(prefix = 'id') {
            return prefix + '_' + Math.random().toString(36).substr(2, 9);
        },

        // Check if element is in viewport
        isInViewport: function(element) {
            const rect = element.getBoundingClientRect();
            return (
                rect.top >= 0 &&
                rect.left >= 0 &&
                rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
                rect.right <= (window.innerWidth || document.documentElement.clientWidth)
            );
        }
    };

    // Add CSS for spinning animation
    if (!document.getElementById('adminlte-custom-styles')) {
        const style = document.createElement('style');
        style.id = 'adminlte-custom-styles';
        style.textContent = `
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .spin { animation: spin 1s linear infinite; }

            .table-row-unread {
                background-color: rgba(var(--bs-info-rgb), 0.1);
            }

            .table-row-high-priority {
                border-left: 4px solid var(--bs-danger);
            }

            .table-row-medium-priority {
                border-left: 4px solid var(--bs-warning);
            }

            .table-row-low-priority {
                border-left: 4px solid var(--bs-success);
            }
        `;
        document.head.appendChild(style);
    }

    console.log('AdminLTE Custom Utilities loaded successfully');
});