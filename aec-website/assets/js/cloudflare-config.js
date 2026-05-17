// assets/js/cloudflare-config.js
const API_URL = 'https://api.assembleeducationcommunity.org';

async function fetchWithTimeout(url, timeout = 8000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'Accept': 'application/json' }
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(id);
  }
}

export async function getClasses() {
  return fetchWithTimeout(`${API_URL}/api/classes`);
}
export async function getEvents() {
  return fetchWithTimeout(`${API_URL}/api/events`);
}
export async function getJobs() {
  return fetchWithTimeout(`${API_URL}/api/jobs`);
}
export async function getProjects() {
  return fetchWithTimeout(`${API_URL}/api/projects`);
}
export async function getVolunteers() {
  return fetchWithTimeout(`${API_URL}/api/volunteers`);
}
export async function getContactInfo() {
  return fetchWithTimeout(`${API_URL}/api/contact_info`);
}

// ⭐ Public enrollment submission (no auth required)
export async function submitEnrollment(data) {
  return fetch(`${API_URL}/api/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }).then(res => res.json());
}