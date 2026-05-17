// assets/js/load-components.js
console.log('✅ load-components.js loaded');

const DEFAULT_PRIMARY = '#1b4332';
const DEFAULT_ACCENT = '#D4AF37';

async function loadHeader() {
  const container = document.getElementById('header-container');
  if (!container) return;
  try {
    // ✅ Fetch from ROOT (not /includes/)
    const response = await fetch('header.html');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    container.innerHTML = await response.text();
    console.log('✅ Header loaded');
    initNavFeatures();
  } catch (error) {
    console.error('❌ Header failed:', error);
    container.innerHTML = '<div class="bg-red-100 text-red-800 p-4 text-center">Header failed to load. Please refresh.</div>';
  }
}

async function loadFooter() {
  const container = document.getElementById('footer-container');
  if (!container) return;
  try {
    const response = await fetch('footer.html');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    container.innerHTML = await response.text();
    console.log('✅ Footer loaded');
  } catch (error) {
    console.error('❌ Footer failed:', error);
    container.innerHTML = '<div class="bg-red-100 text-red-800 p-4 text-center">Footer failed to load. Please refresh.</div>';
  }
}

function initNavFeatures() {
  const mobileBtn = document.getElementById('mobile-menu-btn');
  const mobileMenu = document.getElementById('mobile-menu');
  const hamburgerIcon = document.getElementById('hamburger-icon');
  const closeIcon = document.getElementById('close-icon');
  const navbar = document.getElementById('navbar');

  // Prevent double-binding
  if (mobileBtn && mobileBtn._listenerAttached) return;
  if (mobileBtn) mobileBtn._listenerAttached = true;

  let isMenuOpen = false;
  if (mobileBtn && mobileMenu) {
    mobileBtn.addEventListener('click', (e) => {
      e.preventDefault();
      isMenuOpen = !isMenuOpen;
      mobileMenu.classList.toggle('hidden', !isMenuOpen);
      mobileMenu.classList.toggle('block', isMenuOpen);
      hamburgerIcon?.classList.toggle('hidden', isMenuOpen);
      closeIcon?.classList.toggle('hidden', !isMenuOpen);
      document.body.style.overflow = isMenuOpen ? 'hidden' : '';
    });

    mobileMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        if (isMenuOpen) mobileBtn.click();
      });
    });
  }

  window.addEventListener('scroll', () => {
    if (navbar) navbar.classList.toggle('shadow-lg', window.scrollY > 50);
  }, { passive: true });

  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPage || href === `./${currentPage}`) {
      link.style.color = '#1b4332';
      link.style.fontWeight = '700';
    }
  });
}

function applyDefaultColors() {
  if (!getComputedStyle(document.documentElement).getPropertyValue('--color-primary-600')) {
    document.documentElement.style.setProperty('--color-primary-600', DEFAULT_PRIMARY);
    document.documentElement.style.setProperty('--color-accent-600', DEFAULT_ACCENT);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  applyDefaultColors();
  loadHeader();
  loadFooter();
});