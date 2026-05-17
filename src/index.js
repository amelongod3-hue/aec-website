// aec-backend/src/index.js
// ⭐ CORS Headers ⭐
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function handleOptions(request) {
  return new Response(null, { headers: corsHeaders() });
}

// ⭐ Simple in‑memory rate limiter (resets on worker cold start)
const rateLimit = new Map();
function isRateLimited(ip, limit = 5, windowMs = 60 * 1000) {
  const now = Date.now();
  const record = rateLimit.get(ip);
  if (!record) {
    rateLimit.set(ip, { count: 1, resetTime: now + windowMs });
    return false;
  }
  if (now > record.resetTime) {
    rateLimit.set(ip, { count: 1, resetTime: now + windowMs });
    return false;
  }
  if (record.count >= limit) return true;
  record.count++;
  return false;
}

// ⭐ SHA‑256 hashing (no salt, direct hex)
async function sha256(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ⭐ JWT Helpers
async function signJWT(payload, secret) {
  const encoder = new TextEncoder();
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify(payload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(signatureInput));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${signatureInput}.${encodedSignature}`;
}

async function verifyJWT(token, secret) {
  try {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sigBuf = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(signatureInput));
    if (!isValid) return null;
    
    const payload = JSON.parse(atob(encodedPayload));
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

async function getUserFromRequest(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.substring(7);
  return await verifyJWT(token, env.JWT_SECRET);
}

function hasPermission(user, permission) {
  if (!user) return false;
  if (user.role === 'super_admin') return true;
  return user.permissions && user.permissions.includes(permission);
}

// ⭐ Helper: JSON Response
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' }
  });
}

// ==================== CRUD Functions ====================
// ⭐ CLASSES ⭐
async function getClasses(env) {
  const { results } = await env.DB.prepare('SELECT * FROM classes ORDER BY created_at DESC').all();
  return json(results || []);
}
async function createClass(request, env) {
  const data = await request.json();
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO classes ( id, title, grade, category, price, period, duration, description, full_description, requirements, color, highlight, discount_has, discount_value, discount_type, pricing_type, pricing_unit, created_at ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, data.title, data.grade, data.category, data.price,
    data.period || 'Month', data.duration, data.description,
    data.full_description || '', data.requirements || '',
    data.color || '#f97316', data.highlight ? 1 : 0,
    data.discount_has ? 1 : 0, data.discount_value || '',
    data.discount_type || 'percentage', 'monthly', 'MMK', created_at
  ).run();
  return json({ success: true, id });
}
async function updateClass(request, env, id) {
  const data = await request.json();
  await env.DB.prepare(`UPDATE classes SET title = ?, grade = ?, category = ?, price = ?, period = ?, duration = ?, description = ?, full_description = ?, requirements = ?, color = ?, highlight = ?, discount_has = ?, discount_value = ?, discount_type = ? WHERE id = ?`).bind(
    data.title, data.grade, data.category, data.price, data.period,
    data.duration, data.description, data.full_description,
    data.requirements, data.color, data.highlight ? 1 : 0,
    data.discount_has ? 1 : 0, data.discount_value, data.discount_type, id
  ).run();
  return json({ success: true });
}
async function deleteClass(env, id) {
  await env.DB.prepare('DELETE FROM classes WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ EVENTS ⭐
async function getEvents(env) {
  const { results } = await env.DB.prepare('SELECT * FROM events ORDER BY date ASC').all();
  return json(results || []);
}
async function createEvent(request, env) {
  const data = await request.json();
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO events ( id, title, date, time, location, prize, description, requirements, type, color, highlight, media_url, media_type, created_at ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, data.title, data.date, data.time, data.location,
    data.prize || '', data.description, data.requirements || '',
    data.type || 'event', data.color || '#f97316',
    data.highlight ? 1 : 0, data.media_url || '',
    data.media_type || '', created_at
  ).run();
  return json({ success: true, id });
}
async function updateEvent(request, env, id) {
  const data = await request.json();
  await env.DB.prepare(`UPDATE events SET title = ?, date = ?, time = ?, location = ?, prize = ?, description = ?, requirements = ?, type = ?, color = ?, highlight = ?, media_url = ?, media_type = ? WHERE id = ?`).bind(
    data.title, data.date, data.time, data.location, data.prize,
    data.description, data.requirements, data.type, data.color,
    data.highlight ? 1 : 0, data.media_url, data.media_type, id
  ).run();
  return json({ success: true });
}
async function deleteEvent(env, id) {
  await env.DB.prepare('DELETE FROM events WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ JOBS ⭐
async function getJobs(env) {
  const { results } = await env.DB.prepare('SELECT * FROM jobs ORDER BY created_at DESC').all();
  return json(results || []);
}
async function createJob(request, env) {
  const data = await request.json();
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO jobs ( id, title, department, type, location, salary, image, video, description, requirements, benefits, color, highlight, bonus_sign_in, bonus_monthly, bonus_other, has_bonus, media_url, media_type, created_at ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, data.title, data.department || '', data.type || 'full-time',
    data.location, data.salary || '', data.image || '', data.video || '',
    data.description, data.requirements || '', data.benefits || '',
    data.color || '#f97316', data.highlight ? 1 : 0,
    data.bonus_sign_in || '', data.bonus_monthly || '',
    data.bonus_other || '', data.has_bonus ? 1 : 0,
    data.media_url || '', data.media_type || '', created_at
  ).run();
  return json({ success: true, id });
}
async function updateJob(request, env, id) {
  const data = await request.json();
  await env.DB.prepare(`UPDATE jobs SET title = ?, department = ?, type = ?, location = ?, salary = ?, image = ?, video = ?, description = ?, requirements = ?, benefits = ?, color = ?, highlight = ?, bonus_sign_in = ?, bonus_monthly = ?, bonus_other = ?, has_bonus = ?, media_url = ?, media_type = ? WHERE id = ?`).bind(
    data.title, data.department, data.type, data.location, data.salary,
    data.image, data.video, data.description, data.requirements,
    data.benefits, data.color, data.highlight ? 1 : 0,
    data.bonus_sign_in, data.bonus_monthly, data.bonus_other,
    data.has_bonus ? 1 : 0, data.media_url, data.media_type, id
  ).run();
  return json({ success: true });
}
async function deleteJob(env, id) {
  await env.DB.prepare('DELETE FROM jobs WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ PROJECTS ⭐
async function getProjects(env) {
  const { results } = await env.DB.prepare('SELECT * FROM projects ORDER BY created_at DESC').all();
  return json(results || []);
}
async function createProject(request, env) {
  const data = await request.json();
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO projects ( id, title, description, prize_pool, places, color, highlight, media_url, media_type, created_at ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, data.title, data.description || '', data.prize_pool || '',
    data.places || '', data.color || '#f97316',
    data.highlight ? 1 : 0, data.media_url || '',
    data.media_type || '', created_at
  ).run();
  return json({ success: true, id });
}
async function updateProject(request, env, id) {
  const data = await request.json();
  await env.DB.prepare(`UPDATE projects SET title = ?, description = ?, prize_pool = ?, places = ?, color = ?, highlight = ?, media_url = ?, media_type = ? WHERE id = ?`).bind(
    data.title, data.description, data.prize_pool, data.places,
    data.color, data.highlight ? 1 : 0, data.media_url, data.media_type, id
  ).run();
  return json({ success: true });
}
async function deleteProject(env, id) {
  await env.DB.prepare('DELETE FROM projects WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ VOLUNTEERS ⭐
async function getVolunteers(env) {
  const { results } = await env.DB.prepare('SELECT * FROM volunteers ORDER BY created_at DESC').all();
  return json(results || []);
}
async function createVolunteer(request, env) {
  const data = await request.json();
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO volunteers ( id, name, role, description, media_url, media_type, highlight, created_at ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, data.name, data.role || '', data.description || '',
    data.media_url || '', data.media_type || '',
    data.highlight ? 1 : 0, created_at
  ).run();
  return json({ success: true, id });
}
async function updateVolunteer(request, env, id) {
  const data = await request.json();
  await env.DB.prepare(`UPDATE volunteers SET name = ?, role = ?, description = ?, media_url = ?, media_type = ?, highlight = ? WHERE id = ?`).bind(
    data.name, data.role, data.description,
    data.media_url, data.media_type, data.highlight ? 1 : 0, id
  ).run();
  return json({ success: true });
}
async function deleteVolunteer(env, id) {
  await env.DB.prepare('DELETE FROM volunteers WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ APPLICATIONS ⭐
async function getApplications(env) {
  const { results } = await env.DB.prepare('SELECT * FROM applications ORDER BY created_at DESC').all();
  return json(results || []);
}
async function createApplication(request, env) {
  const data = await request.json();
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO applications ( id, name, email, contact_method, contact_value, position, type, message, parent_name, status, created_at ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, data.name, data.email, data.contact_method || 'phone',
    data.contact_value || '', data.position || '',
    data.type || 'enrollment', data.message || '',
    data.parent_name || '', 'new', created_at
  ).run();
  return json({ success: true, id });
}
async function updateApplication(request, env, id) {
  const data = await request.json();
  await env.DB.prepare(`UPDATE applications SET status = ?, contact_method = ?, contact_value = ? WHERE id = ?`).bind(
    data.status || 'new', data.contact_method, data.contact_value, id
  ).run();
  return json({ success: true });
}
async function deleteApplication(env, id) {
  await env.DB.prepare('DELETE FROM applications WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ ENROLLMENTS ⭐
async function getEnrollments(env) {
  const { results } = await env.DB.prepare('SELECT * FROM enrollments ORDER BY created_at DESC').all();
  return json(results || []);
}
async function createEnrollment(request, env) {
  try {
    const data = await request.json();
    const required = [
      'student_name', 'student_gmail', 'father_name', 'mother_name',
      'parent_phone', 'student_phone', 'student_age', 'telegram',
      'desired_class', 'current_education', 'region', 'address'
    ];
    for (const field of required) {
      if (!data[field]) {
        return json({ error: `${field} is required` }, 400);
      }
    }
    const now = new Date().toISOString();
    const result = await env.DB.prepare(`INSERT INTO enrollments ( student_name, student_gmail, father_name, mother_name, parent_phone, student_phone, student_age, telegram, desired_class, current_education, region, address, email, message, status, created_at, updated_at, date_of_birth ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      data.student_name, data.student_gmail, data.father_name, data.mother_name,
      data.parent_phone, data.student_phone, data.student_age, data.telegram,
      data.desired_class, data.current_education, data.region, data.address,
      data.email || null, data.message || null, 'pending', now, now,
      data.date_of_birth || null
    ).run();
    const lastId = result.meta.last_row_id;
    return json({ success: true, id: lastId });
  } catch (error) {
    console.error('Enrollment error:', error);
    return json({ error: error.message }, 500);
  }
}
async function updateEnrollment(request, env, id) {
  const data = await request.json();
  await env.DB.prepare(`UPDATE enrollments SET status = ?, updated_at = datetime('now') WHERE id = ?`).bind(data.status || 'pending', id).run();
  return json({ success: true });
}
async function deleteEnrollment(env, id) {
  await env.DB.prepare('DELETE FROM enrollments WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ CONTACT INFO ⭐
async function getContactInfo(env) {
  const { results } = await env.DB.prepare('SELECT * FROM contact_info ORDER BY display_order ASC, id ASC').all();
  return json(results || []);
}
async function createContactInfo(request, env) {
  const data = await request.json();
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO contact_info ( id, type, label, value, display_order, is_primary, is_active, created_at ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, data.type || 'other', data.label || '', data.value,
    data.display_order || 0, data.is_primary ? 1 : 0,
    data.is_active !== undefined ? data.is_active : 1, created_at
  ).run();
  return json({ success: true, id });
}
async function updateContactInfo(request, env, id) {
  const data = await request.json();
  await env.DB.prepare(`UPDATE contact_info SET type = ?, label = ?, value = ?, display_order = ?, is_primary = ?, is_active = ? WHERE id = ?`).bind(
    data.type, data.label, data.value, data.display_order,
    data.is_primary ? 1 : 0,
    data.is_active !== undefined ? data.is_active : 1, id
  ).run();
  return json({ success: true });
}
async function deleteContactInfo(env, id) {
  await env.DB.prepare('DELETE FROM contact_info WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ ADMIN USERS ⭐
async function getAdminUsers(env) {
  const { results } = await env.DB.prepare(`SELECT id, username, email, role, permissions, status, is_active, last_login, created_at, created_by FROM admin_users ORDER BY created_at DESC`).all();
  const users = results.map(u => ({ ...u, permissions: u.permissions ? JSON.parse(u.permissions) : [] }));
  return json(users);
}
async function createAdminUser(request, env) {
  const data = await request.json();
  const password_hash = await sha256(data.password);
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO admin_users ( id, username, email, password_hash, role, permissions, status, is_active, created_at, created_by ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    id, data.username, data.email, password_hash,
    data.role || 'staff', JSON.stringify(data.permissions || []),
    data.status || 'active', 1, created_at, data.created_by || 'system'
  ).run();
  return json({ success: true, id });
}
async function updateAdminUser(request, env, id) {
  const data = await request.json();
  if (data.password) {
    const password_hash = await sha256(data.password);
    await env.DB.prepare(`UPDATE admin_users SET username = ?, email = ?, role = ?, permissions = ?, status = ?, is_active = ?, password_hash = ? WHERE id = ?`).bind(
      data.username, data.email, data.role, JSON.stringify(data.permissions || []),
      data.status, data.is_active !== undefined ? data.is_active : 1,
      password_hash, id
    ).run();
  } else {
    await env.DB.prepare(`UPDATE admin_users SET username = ?, email = ?, role = ?, permissions = ?, status = ?, is_active = ? WHERE id = ?`).bind(
      data.username, data.email, data.role, JSON.stringify(data.permissions || []),
      data.status, data.is_active !== undefined ? data.is_active : 1, id
    ).run();
  }
  return json({ success: true });
}
async function deleteAdminUser(env, id) {
  await env.DB.prepare('DELETE FROM admin_users WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ⭐ NEW ADMIN PANEL ROUTES ⭐
async function getAdminUsersList(env) {
  const { results } = await env.DB.prepare(`SELECT id, username, email, role, permissions, status, is_active, last_login, created_at, created_by FROM admin_users ORDER BY created_at DESC`).all();
  const users = results.map(u => ({ ...u, permissions: u.permissions ? JSON.parse(u.permissions) : [] }));
  return json(users);
}
async function deleteAdminUserFromBody(request, env, currentUser) {
  const { id } = await request.json();
  if (!id) return json({ error: 'User ID required' }, 400);
  if (id === currentUser.id) return json({ error: 'Cannot delete yourself' }, 400);
  await env.DB.prepare('DELETE FROM admin_users WHERE id = ?').bind(id).run();
  return json({ success: true });
}
async function createAdminUserFromAdmin(request, env, currentUser) {
  const data = await request.json();
  const { username, email, password, role, permissions } = data;
  if (!username || !email || !password) return json({ error: 'Username, email, and password required' }, 400);
  const existing = await env.DB.prepare('SELECT id FROM admin_users WHERE username = ? OR email = ?').bind(username, email).first();
  if (existing) return json({ error: 'Username or email already exists' }, 409);
  const password_hash = await sha256(password);
  const id = crypto.randomUUID();
  const permStr = JSON.stringify(permissions || []);
  await env.DB.prepare(`INSERT INTO admin_users (id, username, email, password_hash, role, permissions, status, is_active, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, username, email, password_hash, role || 'staff', permStr, 'active', 1, new Date().toISOString(), currentUser.username).run();
  return json({ success: true, id });
}

// ⭐ LOGIN ⭐
async function login(request, env) {
  try {
    const data = await request.json();
    const { username, password_hash } = data;
    if (!username || !password_hash) return json({ error: 'Username and password hash required' }, 400);
    const { results } = await env.DB.prepare(
      `SELECT id, username, email, password_hash, role, status, is_active, last_login, created_at FROM admin_users WHERE (username = ? OR email = ?) AND (status = 'active' OR is_active = 1)`
    ).bind(username, username).all();
    const user = results[0];
    if (!user) return json({ error: 'Invalid credentials' }, 401);
    if (user.password_hash !== password_hash) return json({ error: 'Invalid credentials' }, 401);
    await env.DB.prepare(`UPDATE admin_users SET last_login = datetime('now') WHERE id = ?`).bind(user.id).run();
    const token = await signJWT({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      exp: Date.now() + (24 * 60 * 60 * 1000)
    }, env.JWT_SECRET);
    return json({ success: true, token, user: { id: user.id, username: user.username, email: user.email, role: user.role, status: user.status } });
  } catch (error) {
    return json({ error: 'Login failed', message: error.message }, 500);
  }
}

async function adminLogin(request, env) {
  try {
    const data = await request.json();
    const { username, password_hash } = data;
    if (!username || !password_hash) return json({ error: 'Username and password hash required' }, 400);
    const { results } = await env.DB.prepare(
      `SELECT id, username, email, password_hash, role, permissions, status, is_active, last_login, created_at FROM admin_users WHERE (username = ? OR email = ?) AND (status = 'active' OR is_active = 1)`
    ).bind(username, username).all();
    const user = results[0];
    if (!user) return json({ error: 'Invalid credentials' }, 401);
    if (user.password_hash !== password_hash) return json({ error: 'Invalid credentials' }, 401);
    await env.DB.prepare(`UPDATE admin_users SET last_login = datetime('now') WHERE id = ?`).bind(user.id).run();
    let permissions = [];
    try { permissions = JSON.parse(user.permissions || '[]'); } catch (e) {}
    const token = await signJWT({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      permissions: permissions,
      exp: Date.now() + (24 * 60 * 60 * 1000)
    }, env.JWT_SECRET);
    return json({ success: true, token, user: { id: user.id, username: user.username, email: user.email, role: user.role, permissions: permissions, status: user.status } });
  } catch (error) {
    return json({ error: 'Login failed', message: error.message }, 500);
  }
}

// ==================== Main Worker ====================
export default {
  async fetch(request, env, ctx) {
    if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      console.error('JWT_SECRET is missing or too short');
      return json({ error: 'Server configuration error' }, 500);
    }
    
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return handleOptions(request);

    try {
      // ==================== PUBLIC ROUTES ====================
      if (path === '/api/classes' && request.method === 'GET') return await getClasses(env);
      if (path === '/api/events' && request.method === 'GET') return await getEvents(env);
      if (path === '/api/jobs' && request.method === 'GET') return await getJobs(env);
      if (path === '/api/projects' && request.method === 'GET') return await getProjects(env);
      if (path === '/api/volunteers' && request.method === 'GET') return await getVolunteers(env);
      if (path === '/api/contact_info' && request.method === 'GET') return await getContactInfo(env);
      if (path === '/api/health') return json({ status: 'ok', timestamp: new Date().toISOString(), database: env.DB ? 'connected' : 'not connected' });
      if (path === '/api/enroll' && request.method === 'POST') return await createEnrollment(request, env);
      if (path === '/api/applications' && request.method === 'POST') return await createApplication(request, env);
      
      if (path === '/api/login' && request.method === 'POST') {
        const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
        if (isRateLimited(clientIP)) return json({ error: 'Too many login attempts. Try again later.' }, 429);
        return await login(request, env);
      }
      if (path === '/api/admin/login' && request.method === 'POST') {
        const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
        if (isRateLimited(clientIP)) return json({ error: 'Too many login attempts. Try again later.' }, 429);
        return await adminLogin(request, env);
      }

      // ==================== PROTECTED ROUTES ====================
      // --- CLASSES ---
      if (path === '/api/classes' && request.method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_classes')) return json({ error: 'Forbidden' }, 403);
        return await createClass(request, env);
      }
      if (path.startsWith('/api/classes/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_classes')) return json({ error: 'Forbidden' }, 403);
        return await updateClass(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/classes/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'delete_classes')) return json({ error: 'Forbidden' }, 403);
        return await deleteClass(env, path.split('/')[3]);
      }

      // --- EVENTS ---
      if (path === '/api/events' && request.method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_events')) return json({ error: 'Forbidden' }, 403);
        return await createEvent(request, env);
      }
      if (path.startsWith('/api/events/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_events')) return json({ error: 'Forbidden' }, 403);
        return await updateEvent(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/events/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'delete_events')) return json({ error: 'Forbidden' }, 403);
        return await deleteEvent(env, path.split('/')[3]);
      }

      // --- JOBS ---
      if (path === '/api/jobs' && request.method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_jobs')) return json({ error: 'Forbidden' }, 403);
        return await createJob(request, env);
      }
      if (path.startsWith('/api/jobs/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_jobs')) return json({ error: 'Forbidden' }, 403);
        return await updateJob(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/jobs/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'delete_jobs')) return json({ error: 'Forbidden' }, 403);
        return await deleteJob(env, path.split('/')[3]);
      }

      // --- PROJECTS ---
      if (path === '/api/projects' && request.method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_projects')) return json({ error: 'Forbidden' }, 403);
        return await createProject(request, env);
      }
      if (path.startsWith('/api/projects/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_projects')) return json({ error: 'Forbidden' }, 403);
        return await updateProject(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/projects/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'delete_projects')) return json({ error: 'Forbidden' }, 403);
        return await deleteProject(env, path.split('/')[3]);
      }

      // --- VOLUNTEERS ---
      if (path === '/api/volunteers' && request.method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_volunteers')) return json({ error: 'Forbidden' }, 403);
        return await createVolunteer(request, env);
      }
      if (path.startsWith('/api/volunteers/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_volunteers')) return json({ error: 'Forbidden' }, 403);
        return await updateVolunteer(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/volunteers/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'delete_volunteers')) return json({ error: 'Forbidden' }, 403);
        return await deleteVolunteer(env, path.split('/')[3]);
      }

      // --- APPLICATIONS ---
      if (path === '/api/applications' && request.method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'view_applications')) return json({ error: 'Forbidden' }, 403);
        return await getApplications(env);
      }
      if (path.startsWith('/api/applications/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_applications')) return json({ error: 'Forbidden' }, 403);
        return await updateApplication(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/applications/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'delete_data')) return json({ error: 'Forbidden' }, 403);
        return await deleteApplication(env, path.split('/')[3]);
      }

      // --- ENROLLMENTS ---
      if (path === '/api/enrollments' && request.method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'view_applications')) return json({ error: 'Forbidden' }, 403);
        return await getEnrollments(env);
      }
      if (path.startsWith('/api/enrollments/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_applications')) return json({ error: 'Forbidden' }, 403);
        return await updateEnrollment(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/enrollments/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'delete_data')) return json({ error: 'Forbidden' }, 403);
        return await deleteEnrollment(env, path.split('/')[3]);
      }

      // --- CONTACT INFO ---
      if (path === '/api/contact_info' && request.method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_settings')) return json({ error: 'Forbidden' }, 403);
        return await createContactInfo(request, env);
      }
      if (path.startsWith('/api/contact_info/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_settings')) return json({ error: 'Forbidden' }, 403);
        return await updateContactInfo(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/contact_info/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'edit_settings')) return json({ error: 'Forbidden' }, 403);
        return await deleteContactInfo(env, path.split('/')[3]);
      }

      // --- ADMIN USERS (original) ---
      if (path === '/api/admin-users' && request.method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'view_users')) return json({ error: 'Forbidden' }, 403);
        return await getAdminUsers(env);
      }
      if (path === '/api/admin-users' && request.method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'manage_admins')) return json({ error: 'Forbidden' }, 403);
        return await createAdminUser(request, env);
      }
      if (path.startsWith('/api/admin-users/') && request.method === 'PUT') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'manage_admins')) return json({ error: 'Forbidden' }, 403);
        return await updateAdminUser(request, env, path.split('/')[3]);
      }
      if (path.startsWith('/api/admin-users/') && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'manage_admins')) return json({ error: 'Forbidden' }, 403);
        return await deleteAdminUser(env, path.split('/')[3]);
      }

      // --- ADMIN PANEL ROUTES (new) ---
      if (path === '/api/admin/users' && request.method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'view_users')) return json({ error: 'Permission denied' }, 403);
        return await getAdminUsersList(env);
      }
      if (path === '/api/admin/users' && request.method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'delete_users')) return json({ error: 'Permission denied' }, 403);
        return await deleteAdminUserFromBody(request, env, user);
      }
      if (path === '/api/admin/register' && request.method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (!hasPermission(user, 'manage_admins')) return json({ error: 'Permission denied' }, 403);
        return await createAdminUserFromAdmin(request, env, user);
      }

      // === 404 ===
      return json({ error: 'Not Found', path: path }, 404);

    } catch (error) {
      console.error('Worker error:', error);
      return json({ error: 'Internal Server Error' }, 500);
    }
  },
};