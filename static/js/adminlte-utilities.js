/**
 * AdminLTE Flask Dashboard - Utilities
 * DataTables and Awesome Notifications integration
 */

// DataTables Advanced Utilities
window.AdminLTE = window.AdminLTE || {};

AdminLTE.DataTables = {
    // Default configurations
    defaultConfig: {
        responsive: true,
        processing: true,
        pageLength: 25,
        lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
        language: {
            processing: '<i class="bi bi-arrow-clockwise spin"></i> Loading data...',
            search: "",
            searchPlaceholder: "Search records...",
            lengthMenu: "Show _MENU_ entries",
            info: "Showing _START_ to _END_ of _TOTAL_ entries",
            infoEmpty: "No entries found",
            infoFiltered: "(filtered from _MAX_ total entries)",
            emptyTable: "No data available in table",
            zeroRecords: "No matching records found",
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
        order: [],
        columnDefs: [
            { orderable: false, targets: 'no-sort' },
            { searchable: false, targets: 'no-search' }
        ]
    },

    // Initialize Messages DataTable
    initMessagesTable: function(selector, ajaxUrl = null) {
        const config = {
            ...this.defaultConfig,
            columns: [
                {
                    data: null,
                    width: "30px",
                    className: "text-center no-sort no-search",
                    render: function(data, type, row) {
                        return `<input type="checkbox" class="message-checkbox" value="${row.id}">`;
                    }
                },
                {
                    data: 'avatar',
                    width: "50px",
                    className: "text-center no-sort",
                    render: function(data, type, row) {
                        const avatar = data || '/static/assets/img/user-default.jpg';
                        return `<img src="${avatar}" alt="Avatar" class="img-circle" width="40" height="40">`;
                    }
                },
                {
                    data: 'sender',
                    render: function(data, type, row) {
                        let html = `<strong>${data}</strong>`;
                        if (row.unread) {
                            html += ` <span class="badge bg-danger badge-sm ms-1">Unread</span>`;
                        }
                        return html;
                    }
                },
                {
                    data: 'subject',
                    render: function(data, type, row) {
                        return `<strong>${data || 'No Subject'}</strong>`;
                    }
                },
                {
                    data: 'content',
                    render: function(data, type, row) {
                        if (type === 'display') {
                            const truncated = data.length > 100 ? data.substring(0, 100) + '...' : data;
                            return `<div class="message-content" style="max-width: 300px;">${truncated}</div>`;
                        }
                        return data;
                    }
                },
                {
                    data: 'type_info',
                    className: "text-center",
                    render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}">
                                      <i class="bi ${data.icon} me-1"></i>${data.label}
                                    </span>`;
                        }
                        return '<span class="badge bg-secondary">Unknown</span>';
                    }
                },
                {
                    data: 'priority_info',
                    className: "text-center",
                    render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}">
                                      <i class="bi ${data.icon} me-1"></i>${data.label}
                                    </span>`;
                        }
                        return '<span class="badge bg-secondary">Normal</span>';
                    }
                },
                {
                    data: null,
                    className: "text-center",
                    render: function(data, type, row) {
                        if (row.unread) {
                            return '<span class="badge bg-warning">Unread</span>';
                        } else if (row.archived) {
                            return '<span class="badge bg-secondary">Archived</span>';
                        } else {
                            return '<span class="badge bg-success">Read</span>';
                        }
                    }
                },
                {
                    data: 'time',
                    width: "120px"
                },
                {
                    data: null,
                    width: "150px",
                    className: "text-center no-sort",
                    render: function(data, type, row) {
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
                    }
                }
            ],
            createdRow: function(row, data, dataIndex) {
                if (data.unread) {
                    $(row).addClass('table-row-unread');
                }
                if (data.priority_info) {
                    $(row).addClass(`table-row-${data.priority_info.level}-priority`);
                }
            }
        };

        if (ajaxUrl) {
            config.ajax = {
                url: ajaxUrl,
                type: 'GET',
                error: function(xhr, error, code) {
                    console.error('DataTables Ajax error:', error);
                    AdminLTE.Notifications.error('Failed to load messages: ' + error);
                }
            };
            config.serverSide = true;
        }

        return $(selector).DataTable(config);
    },

    // Initialize Notifications DataTable
    initNotificationsTable: function(selector, ajaxUrl = null) {
        const config = {
            ...this.defaultConfig,
            columns: [
                {
                    data: null,
                    width: "30px",
                    className: "text-center no-sort no-search",
                    render: function(data, type, row) {
                        return `<input type="checkbox" class="notification-checkbox" value="${row.id}">`;
                    }
                },
                {
                    data: 'icon',
                    width: "50px",
                    className: "text-center no-sort",
                    render: function(data, type, row) {
                        const icon = data || 'bi-bell';
                        const color = row.type_info ? row.type_info.color : 'info';
                        return `<i class="bi ${icon} text-${color}" style="font-size: 1.5em;"></i>`;
                    }
                },
                {
                    data: 'message',
                    render: function(data, type, row) {
                        if (type === 'display') {
                            let html = data.length > 150 ? data.substring(0, 150) + '...' : data;
                            if (!row.read) {
                                html += ` <span class="badge bg-danger badge-sm">New</span>`;
                            }
                            return html;
                        }
                        return data;
                    }
                },
                {
                    data: 'type_info',
                    className: "text-center",
                    render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}">
                                      <i class="bi ${data.icon} me-1"></i>${data.label}
                                    </span>`;
                        }
                        return '<span class="badge bg-secondary">Unknown</span>';
                    }
                },
                {
                    data: 'category_info',
                    className: "text-center",
                    render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}">
                                      <i class="bi ${data.icon} me-1"></i>${data.label}
                                    </span>`;
                        }
                        return '<span class="badge bg-secondary">General</span>';
                    }
                },
                {
                    data: 'priority_info',
                    className: "text-center",
                    render: function(data, type, row) {
                        if (data) {
                            return `<span class="badge bg-${data.color}">
                                      <i class="bi ${data.icon} me-1"></i>${data.label}
                                    </span>`;
                        }
                        return '<span class="badge bg-secondary">Normal</span>';
                    }
                },
                {
                    data: null,
                    className: "text-center",
                    render: function(data, type, row) {
                        if (!row.read) {
                            return '<span class="badge bg-warning">Unread</span>';
                        } else if (row.dismissed) {
                            return '<span class="badge bg-secondary">Dismissed</span>';
                        } else {
                            return '<span class="badge bg-success">Read</span>';
                        }
                    }
                },
                {
                    data: 'action_url',
                    render: function(data, type, row) {
                        if (data) {
                            const shortUrl = data.length > 30 ? data.substring(0, 30) + '...' : data;
                            return `<small><a href="${data}" class="text-decoration-none" target="_blank">
                                      ${shortUrl} <i class="bi bi-box-arrow-up-right"></i>
                                    </a></small>`;
                        }
                        return '<small class="text-muted">No action</small>';
                    }
                },
                {
                    data: 'time',
                    width: "120px"
                },
                {
                    data: null,
                    width: "150px",
                    className: "text-center no-sort",
                    render: function(data, type, row) {
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
                    }
                }
            ],
            createdRow: function(row, data, dataIndex) {
                if (!data.read) {
                    $(row).addClass('table-row-unread');
                }
                if (data.priority_info) {
                    $(row).addClass(`table-row-${data.priority_info.level}-priority`);
                }
            }
        };

        if (ajaxUrl) {
            config.ajax = {
                url: ajaxUrl,
                type: 'GET',
                error: function(xhr, error, code) {
                    console.error('DataTables Ajax error:', error);
                    AdminLTE.Notifications.error('Failed to load notifications: ' + error);
                }
            };
            config.serverSide = true;
        }

        return $(selector).DataTable(config);
    },

    // Initialize DataTable with buttons and search builder
    initAdvancedTable: function(selector, options = {}) {
        const config = {
            ...this.defaultConfig,
            dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>' +
                 '<"row"<"col-sm-12"Q>>' +
                 '<"row"<"col-sm-12"B>>' +
                 '<"row"<"col-sm-12"tr>>' +
                 '<"row"<"col-sm-12 col-md-5"i><"col-sm-12 col-md-7"p>>',
            buttons: [
                {
                    extend: 'copy',
                    text: '<i class="bi bi-clipboard me-1"></i>Copy',
                    className: 'btn btn-outline-primary btn-sm'
                },
                {
                    extend: 'csv',
                    text: '<i class="bi bi-filetype-csv me-1"></i>CSV',
                    className: 'btn btn-outline-success btn-sm'
                },
                {
                    extend: 'excel',
                    text: '<i class="bi bi-file-earmark-excel me-1"></i>Excel',
                    className: 'btn btn-outline-success btn-sm'
                },
                {
                    extend: 'pdf',
                    text: '<i class="bi bi-filetype-pdf me-1"></i>PDF',
                    className: 'btn btn-outline-danger btn-sm'
                },
                {
                    extend: 'print',
                    text: '<i class="bi bi-printer me-1"></i>Print',
                    className: 'btn btn-outline-secondary btn-sm'
                },
                {
                    extend: 'colvis',
                    text: '<i class="bi bi-eye me-1"></i>Columns',
                    className: 'btn btn-outline-info btn-sm'
                }
            ],
            searchBuilder: {
                conditions: {
                    string: {
                        'contains': {
                            conditionName: 'Contains'
                        },
                        '!contains': {
                            conditionName: 'Does Not Contain'
                        },
                        'starts': {
                            conditionName: 'Starts With'
                        },
                        'ends': {
                            conditionName: 'Ends With'
                        },
                        '=': {
                            conditionName: 'Equals'
                        },
                        '!=': {
                            conditionName: 'Does Not Equal'
                        }
                    }
                }
            },
            select: {
                style: 'multi',
                selector: '.row-select'
            },
            ...options
        };

        return $(selector).DataTable(config);
    },

    // Utility functions
    refreshTable: function(table) {
        if (table.ajax) {
            table.ajax.reload(null, false);
        } else {
            table.draw();
        }
    },

    getSelectedRows: function(table) {
        return table.rows('.selected').data().toArray();
    },

    selectAllRows: function(table) {
        table.rows().select();
    },

    deselectAllRows: function(table) {
        table.rows().deselect();
    },

    exportTable: function(table, format = 'excel') {
        table.button(`.buttons-${format}`).trigger();
    }
};

// Actions Utilities
AdminLTE.Actions = {
    // Message actions
    markMessageRead: function(messageId) {
        return fetch(`/api/messages/${messageId}/read`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (AdminLTE.Notifications.handleApiResponse(data)) {
                // Refresh the table if it exists
                const table = $('#messagesTable').DataTable();
                if (table) {
                    AdminLTE.DataTables.refreshTable(table);
                }
                return true;
            }
            return false;
        })
        .catch(error => {
            console.error('Error:', error);
            AdminLTE.Notifications.error('An error occurred while marking message as read');
            return false;
        });
    },

    archiveMessage: function(messageId) {
        return AdminLTE.Notifications.confirm(
            'Archive this message?',
            'Confirm Archive',
            () => {
                return fetch(`/api/messages/${messageId}/archive`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (AdminLTE.Notifications.handleApiResponse(data)) {
                        const table = $('#messagesTable').DataTable();
                        if (table) {
                            AdminLTE.DataTables.refreshTable(table);
                        }
                        return true;
                    }
                    return false;
                });
            }
        );
    },

    deleteMessage: function(messageId) {
        return AdminLTE.Notifications.confirm(
            '⚠️ Are you sure you want to delete this message? This action cannot be undone.',
            'Confirm Delete',
            () => {
                return fetch(`/api/messages/${messageId}`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (AdminLTE.Notifications.handleApiResponse(data)) {
                        const table = $('#messagesTable').DataTable();
                        if (table) {
                            AdminLTE.DataTables.refreshTable(table);
                        }
                        return true;
                    }
                    return false;
                });
            }
        );
    },

    viewMessage: function(messageId) {
        AdminLTE.Notifications.async(
            fetch(`/api/messages/${messageId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const message = data.data;
                        const content = `
                            <div class="row">
                                <div class="col-md-2">
                                    <img src="${message.avatar || '/static/assets/img/user-default.jpg'}"
                                         class="img-circle" width="60" height="60">
                                </div>
                                <div class="col-md-10">
                                    <h5>${message.sender}</h5>
                                    <h6 class="text-muted">${message.subject || 'No Subject'}</h6>
                                    <small class="text-muted">${message.time}</small>
                                    ${message.type_info ? `<span class="badge bg-${message.type_info.color} ms-2">${message.type_info.label}</span>` : ''}
                                    ${message.priority_info ? `<span class="badge bg-${message.priority_info.color} ms-1">${message.priority_info.label}</span>` : ''}
                                </div>
                            </div>
                            <hr>
                            <div class="message-content">
                                ${message.content}
                            </div>
                        `;

                        AdminLTE.Notifications.modal(content, 'Message Details');

                        // Mark as read if unread
                        if (message.unread) {
                            this.markMessageRead(messageId);
                        }
                    } else {
                        AdminLTE.Notifications.error('Failed to load message: ' + data.error);
                    }
                }),
            'Loading message...',
            null // No success message for modal
        );
    },

    // Notification actions
    markNotificationRead: function(notificationId) {
        return fetch(`/api/notifications/${notificationId}/read`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (AdminLTE.Notifications.handleApiResponse(data)) {
                const table = $('#notificationsTable').DataTable();
                if (table) {
                    AdminLTE.DataTables.refreshTable(table);
                }
                return true;
            }
            return false;
        })
        .catch(error => {
            console.error('Error:', error);
            AdminLTE.Notifications.error('An error occurred while marking notification as read');
            return false;
        });
    },

    dismissNotification: function(notificationId) {
        return AdminLTE.Notifications.confirm(
            'Dismiss this notification?',
            'Confirm Dismiss',
            () => {
                return fetch(`/api/notifications/${notificationId}/dismiss`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (AdminLTE.Notifications.handleApiResponse(data)) {
                        const table = $('#notificationsTable').DataTable();
                        if (table) {
                            AdminLTE.DataTables.refreshTable(table);
                        }
                        return true;
                    }
                    return false;
                });
            }
        );
    },

    deleteNotification: function(notificationId) {
        return AdminLTE.Notifications.confirm(
            '⚠️ Are you sure you want to delete this notification? This action cannot be undone.',
            'Confirm Delete',
            () => {
                return fetch(`/api/notifications/${notificationId}`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (AdminLTE.Notifications.handleApiResponse(data)) {
                        const table = $('#notificationsTable').DataTable();
                        if (table) {
                            AdminLTE.DataTables.refreshTable(table);
                        }
                        return true;
                    }
                    return false;
                });
            }
        );
    },

    viewNotification: function(notificationId) {
        AdminLTE.Notifications.async(
            fetch(`/api/notifications/${notificationId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const notification = data.data;
                        const content = `
                            <div class="row">
                                <div class="col-md-2 text-center">
                                    <i class="bi ${notification.icon || 'bi-bell'}
                                       ${notification.type_info ? 'text-' + notification.type_info.color : 'text-info'}"
                                       style="font-size: 3em;"></i>
                                </div>
                                <div class="col-md-10">
                                    <h6 class="text-muted">Notification Details</h6>
                                    <small class="text-muted">${notification.time}</small>
                                    ${notification.type_info ? `<span class="badge bg-${notification.type_info.color} ms-2">${notification.type_info.label}</span>` : ''}
                                    ${notification.category_info ? `<span class="badge bg-${notification.category_info.color} ms-1">${notification.category_info.label}</span>` : ''}
                                    ${notification.priority_info ? `<span class="badge bg-${notification.priority_info.color} ms-1">${notification.priority_info.label}</span>` : ''}
                                </div>
                            </div>
                            <hr>
                            <div class="notification-content">
                                <h6>Message:</h6>
                                <p>${notification.message}</p>
                                ${notification.action_url ? `
                                    <h6>Action URL:</h6>
                                    <p><a href="${notification.action_url}" target="_blank" class="btn btn-sm btn-outline-primary">
                                        <i class="bi bi-box-arrow-up-right me-1"></i>Open Action
                                    </a></p>
                                ` : ''}
                            </div>
                        `;

                        AdminLTE.Notifications.modal(content, 'Notification Details');

                        // Mark as read if unread
                        if (!notification.read) {
                            this.markNotificationRead(notificationId);
                        }
                    } else {
                        AdminLTE.Notifications.error('Failed to load notification: ' + data.error);
                    }
                }),
            'Loading notification...',
            null // No success message for modal
        );
    },

    // Bulk actions
    bulkMarkMessagesRead: function(messageIds) {
        if (!messageIds || messageIds.length === 0) {
            AdminLTE.Notifications.warning('No messages selected');
            return;
        }

        return AdminLTE.Notifications.confirm(
            `Mark ${messageIds.length} message(s) as read?`,
            'Confirm Bulk Action',
            () => {
                const promises = messageIds.map(id =>
                    fetch(`/api/messages/${id}/read`, { method: 'POST' })
                );

                return AdminLTE.Notifications.async(
                    Promise.all(promises),
                    'Marking messages as read...',
                    `${messageIds.length} messages marked as read`
                ).then(() => {
                    const table = $('#messagesTable').DataTable();
                    if (table) {
                        AdminLTE.DataTables.refreshTable(table);
                    }
                });
            }
        );
    },

    bulkDeleteMessages: function(messageIds) {
        if (!messageIds || messageIds.length === 0) {
            AdminLTE.Notifications.warning('No messages selected');
            return;
        }

        return AdminLTE.Notifications.confirm(
            `⚠️ Delete ${messageIds.length} message(s)? This action cannot be undone.`,
            'Confirm Bulk Delete',
            () => {
                const promises = messageIds.map(id =>
                    fetch(`/api/messages/${id}`, { method: 'DELETE' })
                );

                return AdminLTE.Notifications.async(
                    Promise.all(promises),
                    'Deleting messages...',
                    `${messageIds.length} messages deleted`
                ).then(() => {
                    const table = $('#messagesTable').DataTable();
                    if (table) {
                        AdminLTE.DataTables.refreshTable(table);
                    }
                });
            }
        );
    },

    bulkMarkNotificationsRead: function(notificationIds) {
        if (!notificationIds || notificationIds.length === 0) {
            AdminLTE.Notifications.warning('No notifications selected');
            return;
        }

        return AdminLTE.Notifications.confirm(
            `Mark ${notificationIds.length} notification(s) as read?`,
            'Confirm Bulk Action',
            () => {
                const promises = notificationIds.map(id =>
                    fetch(`/api/notifications/${id}/read`, { method: 'POST' })
                );

                return AdminLTE.Notifications.async(
                    Promise.all(promises),
                    'Marking notifications as read...',
                    `${notificationIds.length} notifications marked as read`
                ).then(() => {
                    const table = $('#notificationsTable').DataTable();
                    if (table) {
                        AdminLTE.DataTables.refreshTable(table);
                    }
                });
            }
        );
    },

    bulkDeleteNotifications: function(notificationIds) {
        if (!notificationIds || notificationIds.length === 0) {
            AdminLTE.Notifications.warning('No notifications selected');
            return;
        }

        return AdminLTE.Notifications.confirm(
            `⚠️ Delete ${notificationIds.length} notification(s)? This action cannot be undone.`,
            'Confirm Bulk Delete',
            () => {
                const promises = notificationIds.map(id =>
                    fetch(`/api/notifications/${id}`, { method: 'DELETE' })
                );

                return AdminLTE.Notifications.async(
                    Promise.all(promises),
                    'Deleting notifications...',
                    `${notificationIds.length} notifications deleted`
                ).then(() => {
                    const table = $('#notificationsTable').DataTable();
                    if (table) {
                        AdminLTE.DataTables.refreshTable(table);
                    }
                });
            }
        );
    }
};

// Notifications Utilities (Enhanced version of NotificationUtils)
AdminLTE.Notifications = {
    instance: null,

    init: function() {
        this.instance = new AWN({
            position: 'top-right',
            maxNotifications: 5,
            animationDuration: 300,
            displayDuration: 5000,
            icons: {
                enabled: true,
                suffix: '-circle-fill'
            },
            labels: {
                success: 'Success',
                info: 'Information',
                warning: 'Warning',
                alert: 'Error',
                confirm: 'Confirm',
                modal: 'Details'
            }
        });
    },

    success: function(message, title = 'Success', options = {}) {
        return this.instance.success(message, {
            labels: { success: title },
            ...options
        });
    },

    error: function(message, title = 'Error', options = {}) {
        return this.instance.alert(message, {
            labels: { alert: title },
            ...options
        });
    },

    warning: function(message, title = 'Warning', options = {}) {
        return this.instance.warning(message, {
            labels: { warning: title },
            ...options
        });
    },

    info: function(message, title = 'Info', options = {}) {
        return this.instance.info(message, {
            labels: { info: title },
            ...options
        });
    },

    confirm: function(message, title = 'Confirm', onOk, onCancel) {
        return this.instance.confirm(message, onOk, onCancel, {
            labels: { confirm: title }
        });
    },

    modal: function(message, title = 'Information') {
        return this.instance.modal(message, {
            labels: { modal: title }
        });
    },

    async: function(promise, loadingMessage = 'Processing...', successMessage = 'Operation completed successfully') {
        return this.instance.async(promise, loadingMessage, successMessage);
    },

    // Custom notification for API responses
    handleApiResponse: function(response, successMessage = 'Operation completed successfully') {
        if (response.success) {
            this.success(response.message || successMessage);
            return true;
        } else {
            this.error(response.error || 'An error occurred');
            return false;
        }
    },

    // Progress notification
    progress: function(message, progressFunction, title = 'Processing') {
        const notification = this.info(message, title, {
            displayDuration: 0
        });

        if (typeof progressFunction === 'function') {
            progressFunction(notification);
        }

        return notification;
    },

    // Batch notification for multiple operations
    batch: function(operations, successMessage = 'All operations completed', errorMessage = 'Some operations failed') {
        return Promise.allSettled(operations)
            .then(results => {
                const successful = results.filter(r => r.status === 'fulfilled').length;
                const failed = results.filter(r => r.status === 'rejected').length;

                if (failed === 0) {
                    this.success(`${successMessage} (${successful} items)`);
                } else if (successful === 0) {
                    this.error(`${errorMessage} (${failed} items)`);
                } else {
                    this.warning(`Completed with mixed results: ${successful} successful, ${failed} failed`);
                }

                return results;
            });
    }
};

// Form Utilities
AdminLTE.Forms = {
    // Validate form and show notifications
    validateAndSubmit: function(formSelector, submitUrl, options = {}) {
        const form = $(formSelector);
        const formData = new FormData(form[0]);

        // Convert FormData to JSON if needed
        let submitData;
        if (options.json !== false) {
            submitData = {};
            for (let [key, value] of formData.entries()) {
                submitData[key] = value;
            }
            submitData = JSON.stringify(submitData);
        } else {
            submitData = formData;
        }

        const fetchOptions = {
            method: 'POST',
            headers: options.json !== false ? { 'Content-Type': 'application/json' } : {},
            body: submitData
        };

        return AdminLTE.Notifications.async(
            fetch(submitUrl, fetchOptions)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        if (options.onSuccess) {
                            options.onSuccess(data);
                        }
                        if (options.resetForm !== false) {
                            form[0].reset();
                        }
                        if (options.closeModal) {
                            const modal = bootstrap.Modal.getInstance(document.querySelector(options.closeModal));
                            if (modal) modal.hide();
                        }
                        return data;
                    } else {
                        throw new Error(data.error || 'Operation failed');
                    }
                }),
            options.loadingMessage || 'Submitting...',
            options.successMessage || 'Form submitted successfully'
        );
    },

    // Clear form with confirmation
    clearForm: function(formSelector, confirmMessage = 'Clear all form data?') {
        AdminLTE.Notifications.confirm(
            confirmMessage,
            'Confirm Clear',
            () => {
                $(formSelector)[0].reset();
                AdminLTE.Notifications.info('Form cleared');
            }
        );
    }
};

// Initialize everything when DOM is ready
$(document).ready(function() {
    // Initialize notifications
    AdminLTE.Notifications.init();

    // Add global styles for animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spin {
            animation: spin 1s linear infinite;
        }
        .fade-in {
            animation: fadeIn 0.3s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
    `;
    document.head.appendChild(style);

    // Global error handler for AJAX requests
    $(document).ajaxError(function(event, jqXHR, ajaxSettings, thrownError) {
        if (jqXHR.status !== 200) {
            AdminLTE.Notifications.error('Network error: ' + thrownError);
        }
    });

    // Auto-initialize DataTables on tables with data-table attribute
    $('[data-table="standard"]').each(function() {
        AdminLTE.DataTables.initStandardTable(this);
    });

    $('[data-table="messages"]').each(function() {
        const ajaxUrl = $(this).data('ajax-url');
        AdminLTE.DataTables.initMessagesTable(this, ajaxUrl);
    });

    $('[data-table="notifications"]').each(function() {
        const ajaxUrl = $(this).data('ajax-url');
        AdminLTE.DataTables.initNotificationsTable(this, ajaxUrl);
    });

    $('[data-table="advanced"]').each(function() {
        AdminLTE.DataTables.initAdvancedTable(this);
    });

    console.log('AdminLTE Utilities initialized successfully');
});