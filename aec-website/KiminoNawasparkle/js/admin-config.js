// admin/js/admin-config.js
const API_URL = 'https://api.assembleeducationcommunity.org';

export const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  STAFF: 'staff',
  VIEWER: 'viewer'
};

export const PERMISSIONS = {
  VIEW_CLASSES: 'view_classes',
  EDIT_CLASSES: 'edit_classes',
  DELETE_CLASSES: 'delete_classes',
  VIEW_EVENTS: 'view_events',
  EDIT_EVENTS: 'edit_events',
  DELETE_EVENTS: 'delete_events',
  VIEW_JOBS: 'view_jobs',
  EDIT_JOBS: 'edit_jobs',
  DELETE_JOBS: 'delete_jobs',
  VIEW_USERS: 'view_users',
  EDIT_USERS: 'edit_users',
  DELETE_USERS: 'delete_users',
  VIEW_SETTINGS: 'view_settings',
  EDIT_SETTINGS: 'edit_settings',
  VIEW_LOGS: 'view_logs',
  DELETE_DATA: 'delete_data',
  MANAGE_ADMINS: 'manage_admins'
};

export function checkAuth() {
  return !!localStorage.getItem('admin_token');
}

export function getCurrentUser() {
  const user = localStorage.getItem('admin_user');
  if (!user) return null;
  try { return JSON.parse(user); } catch(e) { return null; }
}

export function getUserRole() {
  const user = getCurrentUser();
  return user?.role || ROLES.VIEWER;
}

export function hasPermission(permission) {
  const user = getCurrentUser();
  if (!user) return false;
  if (user.role === ROLES.SUPER_ADMIN) return true;
  return user.permissions?.includes(permission) || false;
}

export function hasRole(role) {
  const user = getCurrentUser();
  if (!user) return false;
  if (user.role === ROLES.SUPER_ADMIN) return true;
  return user.role === role;
}

// ⭐ FIXED: HTML escaping to prevent XSS
export function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"'/]/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  }[c]));
}

// ⭐ SHA‑256 hashing (matches backend)
async function sha256(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ⭐ LOGIN – sends password_hash (SHA-256)
export async function login(username, password) {
  try {
    const password_hash = await sha256(password);
    const response = await fetch(`${API_URL}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password_hash })
    });
    const result = await response.json();
    if (result.success && result.user) {
      localStorage.setItem('admin_token', result.token);
      localStorage.setItem('admin_user', JSON.stringify(result.user));
      localStorage.setItem('admin_logged_in', 'true');
      return { success: true, user: result.user };
    }
    return { success: false, error: result.error || 'Invalid credentials' };
  } catch (error) {
    return { success: false, error: 'Connection failed' };
  }
}

export async function registerUser(userData, token) {
  try {
    const response = await fetch(`${API_URL}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(userData)
    });
    return await response.json();
  } catch (error) {
    return { success: false, error: 'Connection failed' };
  }
}

export async function getAllUsers() {
  try {
    const token = localStorage.getItem('admin_token');
    if (!token) return [];
    const response = await fetch(`${API_URL}/api/admin/users`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) return [];
    return await response.json();
  } catch (error) {
    return [];
  }
}

export async function deleteUser(userId) {
  try {
    const token = localStorage.getItem('admin_token');
    const response = await fetch(`${API_URL}/api/admin/users`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ id: userId })
    });
    return await response.json();
  } catch (error) {
    return { success: false, error: 'Connection failed' };
  }
}

export function logout() {
  localStorage.removeItem('admin_token');
  localStorage.removeItem('admin_user');
  localStorage.removeItem('admin_logged_in');
  window.location.href = 'login.html';
}

export function getAuthHeaders() {
  const token = localStorage.getItem('admin_token');
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

export async function apiCall(url, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...getAuthHeaders(), ...options.headers };
  const response = await fetch(url, { ...options, headers });
  return response.json();
}

// Public getters (no auth)
export async function getClasses() {
  const response = await fetch(`${API_URL}/api/classes`);
  return await response.json();
}
export async function getEvents() {
  const response = await fetch(`${API_URL}/api/events`);
  return await response.json();
}
export async function getJobs() {
  const response = await fetch(`${API_URL}/api/jobs`);
  return await response.json();
}
export async function getProjects() {
  const response = await fetch(`${API_URL}/api/projects`);
  return await response.json();
}
export async function getVolunteers() {
  const response = await fetch(`${API_URL}/api/volunteers`);
  return await response.json();
}
export async function getContactInfo() {
  const response = await fetch(`${API_URL}/api/contact_info`);
  return await response.json();
}

// Admin data operations
export async function getApplications() {
  const token = localStorage.getItem('admin_token');
  if (!token) throw new Error('Not authenticated');
  const response = await fetch(`${API_URL}/api/applications`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return await response.json();
}

export async function getEnrollments() {
  const token = localStorage.getItem('admin_token');
  if (!token) throw new Error('Not authenticated');
  const response = await fetch(`${API_URL}/api/enrollments`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return await response.json();
}

export async function logActivity(action, entity, details) {
  const user = getCurrentUser();
  if (!user) return;
  const log = {
    id: 'log_' + Date.now(),
    user_id: user.id,
    username: user.username,
    action,
    entity,
    details,
    created_at: new Date().toISOString()
  };
  const logs = JSON.parse(localStorage.getItem('activity_logs') || '[]');
  logs.push(log);
  localStorage.setItem('activity_logs', JSON.stringify(logs));
}