/**
 * Custom JavaScript for Flask AdminLTE Application
 */

// Global variables
let globalNotifier;

$(document).ready(function() {
    // Initialize global notifier
    initializeNotifications();

    // Initialize tooltips
    initializeTooltips();

    // Initialize custom event handlers
    initializeEventHandlers();

    // Initialize theme toggle if needed
//    initializeThemeToggle();

    console.log('Custom JavaScript initialized successfully');
});

/**
 * Initialize Awesome Notifications
 */
function initializeNotifications() {
    if (typeof AWN !== 'undefined') {
        globalNotifier = new AWN({
            position: 'top-right',
            duration: 1000,
            icons: {
                enabled: true
            },
            labels: {
                success: 'Success',
                info: 'Info',
                warning: 'Warning',
                alert: 'Error'
            }
        });
    }
}

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    // Initialize tooltips for elements with data-bs-toggle="tooltip"
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Initialize custom event handlers
 */
function initializeEventHandlers() {
    // Handle sidebar toggle
    $(document).on('click', '[data-lte-toggle="sidebar"]', function(e) {
        e.preventDefault();
        // AdminLTE handles this automatically, but we can add custom logic here
    });

    // Handle card collapse
    $(document).on('click', '[data-lte-toggle="card-collapse"]', function(e) {
        e.preventDefault();
        const card = $(this).closest('.card');
        const cardBody = card.find('.card-body');

        if (cardBody.is(':visible')) {
            cardBody.slideUp();
            $(this).find('[data-lte-icon="collapse"]').hide();
            $(this).find('[data-lte-icon="expand"]').show();
        } else {
            cardBody.slideDown();
            $(this).find('[data-lte-icon="expand"]').hide();
            $(this).find('[data-lte-icon="collapse"]').show();
        }
    });

    // Handle fullscreen toggle
    $(document).on('click', '[data-lte-toggle="fullscreen"]', function(e) {
        e.preventDefault();
        toggleFullscreen();
    });
}

/**
 * Initialize theme toggle functionality
 */
function initializeThemeToggle() {
    // Check for saved theme preference or default to 'light'
    const currentTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-bs-theme', currentTheme);

    // Add theme toggle button if it doesn't exist
    if (!document.getElementById('theme-toggle')) {
        const themeToggle = document.createElement('li');
        themeToggle.className = 'nav-item';
        themeToggle.innerHTML = `
            <a class="nav-link" href="#" id="theme-toggle" title="Toggle Theme">
                <i class="bi bi-moon-fill" id="theme-icon"></i>
            </a>
        `;

        // Insert before fullscreen toggle
        const fullscreenToggle = document.querySelector('[data-lte-toggle="fullscreen"]').closest('li');
        if (fullscreenToggle) {
            fullscreenToggle.parentNode.insertBefore(themeToggle, fullscreenToggle);
        }
    }

    // Update icon based on current theme
    updateThemeIcon(currentTheme);

    // Handle theme toggle click
    $(document).on('click', '#theme-toggle', function(e) {
        e.preventDefault();
        toggleTheme();
    });
}

/**
 * Toggle between light and dark themes
 */
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    document.documentElement.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);

    if (globalNotifier) {
        globalNotifier.info(`Switched to ${newTheme} theme`);
    }
}

/**
 * Update theme toggle icon
 */
function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        if (theme === 'dark') {
            icon.className = 'bi bi-sun-fill';
        } else {
            icon.className = 'bi bi-moon-fill';
        }
    }
}

/**
 * Toggle fullscreen mode
 */
function toggleFullscreen() {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().then(() => {
            document.querySelector('[data-lte-icon="maximize"]').style.display = 'none';
            document.querySelector('[data-lte-icon="minimize"]').style.display = 'inline';
        });
    } else {
        if (document.exitFullscreen) {
            document.exitFullscreen().then(() => {
                document.querySelector('[data-lte-icon="minimize"]').style.display = 'none';
                document.querySelector('[data-lte-icon="maximize"]').style.display = 'inline';
            });
        }
    }
}

/**
 * Show notification helper function
 */
function showNotification(type, message, title = null) {
    if (!globalNotifier) {
        console.warn('Notifier not initialized');
        return;
    }

    const options = title ? { labels: { [type]: title } } : {};

    switch (type) {
        case 'success':
            globalNotifier.success(message, options);
            break;
        case 'warning':
            globalNotifier.warning(message, options);
            break;
        case 'error':
        case 'alert':
            globalNotifier.alert(message, options);
            break;
        case 'info':
        default:
            globalNotifier.info(message, options);
            break;
    }
}

/**
 * Initialize DataTable with custom options
 */
function initializeDataTable(selector, options = {}) {
    const defaultOptions = {
        responsive: true,
        pageLength: 10,
        lengthMenu: [[10, 25, 50, -1], [10, 25, 50, "All"]],
        language: {
            search: "Search records:",
            lengthMenu: "Show _MENU_ entries",
            info: "Showing _START_ to _END_ of _TOTAL_ entries",
            infoEmpty: "Showing 0 to 0 of 0 entries",
            infoFiltered: "(filtered from _MAX_ total entries)",
            paginate: {
                first: "First",
                last: "Last",
                next: "Next",
                previous: "Previous"
            },
            emptyTable: "No data available in table",
            zeroRecords: "No matching records found"
        },
        dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>' +
             '<"row"<"col-sm-12"tr>>' +
             '<"row"<"col-sm-12 col-md-5"i><"col-sm-12 col-md-7"p>>',
        drawCallback: function() {
            // Reinitialize tooltips after table redraw
            initializeTooltips();
        }
    };

    // Merge custom options with defaults
    const finalOptions = $.extend(true, {}, defaultOptions, options);

    return $(selector).DataTable(finalOptions);
}

/**
 * Format currency helper function
 */
function formatCurrency(amount, currency = 'USD') {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency
    }).format(amount);
}

/**
 * Format date helper function
 */
function formatDate(date, options = {}) {
    const defaultOptions = {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    };

    const finalOptions = { ...defaultOptions, ...options };
    return new Intl.DateTimeFormat('en-US', finalOptions).format(new Date(date));
}

/**
 * Debounce function to limit API calls
 */
function debounce(func, wait, immediate) {
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
}

/**
 * Loading overlay helper functions
 */
function showLoading(element) {
    const $element = $(element);
    $element.append('<div class="loading-overlay"><div class="loading-spinner"></div></div>');
    $element.css('position', 'relative');
}

function hideLoading(element) {
    $(element).find('.loading-overlay').remove();
}

/**
 * AJAX helper function with error handling
 */
function makeAjaxRequest(url, options = {}) {
    const defaultOptions = {
        method: 'GET',
        dataType: 'json',
        timeout: 30000,
        beforeSend: function() {
            // Show loading if needed
        },
        complete: function() {
            // Hide loading if needed
        },
        error: function(xhr, status, error) {
            let message = 'An error occurred';
            if (xhr.responseJSON && xhr.responseJSON.message) {
                message = xhr.responseJSON.message;
            } else if (error) {
                message = error;
            }
            showNotification('error', message, 'Request Failed');
        }
    };

    const finalOptions = $.extend({}, defaultOptions, options);
    return $.ajax(url, finalOptions);
}

// Export functions for global use
window.showNotification = showNotification;
window.initializeDataTable = initializeDataTable;
window.formatCurrency = formatCurrency;
window.formatDate = formatDate;
window.debounce = debounce;
window.showLoading = showLoading;
window.hideLoading = hideLoading;
window.makeAjaxRequest = makeAjaxRequest;