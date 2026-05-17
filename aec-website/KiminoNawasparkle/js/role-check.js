// admin/js/role-check.js
import { hasPermission, hasRole, ROLES, getCurrentUser } from './admin-config.js';

export function checkRoleAndHideElements() {
    const user = getCurrentUser();
    if (!user) return;

    if (!hasPermission('delete_classes')) {
        document.querySelectorAll('.delete-btn, .btn-delete, [data-action="delete"]').forEach(btn => {
            btn.style.display = 'none';
        });
    }

    if (!hasPermission('edit_classes')) {
        document.querySelectorAll('.edit-btn, .btn-edit, [data-action="edit"]').forEach(btn => {
            btn.style.display = 'none';
        });
    }

    if (!hasPermission('view_settings')) {
        document.querySelectorAll('a[href="settings.html"]').forEach(link => {
            if (link.parentElement) link.parentElement.style.display = 'none';
        });
    }

    if (!hasPermission('manage_admins')) {
        document.querySelectorAll('a[href="admin-users-manager.html"]').forEach(link => {
            if (link.parentElement) link.parentElement.style.display = 'none';
        });
    }

    if (!hasPermission('view_logs')) {
        document.querySelectorAll('a[href="activity-logs.html"]').forEach(link => {
            if (link.parentElement) link.parentElement.style.display = 'none';
        });
    }

    if (!hasPermission('view_payments')) {
        document.querySelectorAll('a[href="payments-manager.html"]').forEach(link => {
            if (link.parentElement) link.parentElement.style.display = 'none';
        });
    }

    if (user.role === ROLES.SUPER_ADMIN) {
        document.querySelectorAll('.super-admin-only').forEach(el => {
            el.style.display = 'block';
        });
    } else {
        document.querySelectorAll('.super-admin-only').forEach(el => {
            el.style.display = 'none';
        });
    }

    if (user.role === ROLES.SUPER_ADMIN || user.role === ROLES.ADMIN) {
        document.querySelectorAll('.admin-only').forEach(el => {
            el.style.display = 'block';
        });
    } else {
        document.querySelectorAll('.admin-only').forEach(el => {
            el.style.display = 'none';
        });
    }

    if (!hasPermission('delete_classes')) {
        document.querySelectorAll('.delete-section').forEach(el => el.style.display = 'none');
    }
}

export function showPermissionDenied() {
    return `<div class="bg-red-50 border-2 border-red-200 rounded-2xl p-8 text-center">
        <div class="text-5xl mb-4">🔒</div>
        <h2 class="text-2xl font-black text-red-900 mb-2">Access Denied</h2>
        <p class="text-red-700">You don't have permission to access this page.</p>
        <a href="dashboard.html" class="inline-block mt-4 px-6 py-3 rounded-xl font-bold text-white bg-primary-600 hover:bg-primary-700">Go to Dashboard</a>
    </div>`;
}