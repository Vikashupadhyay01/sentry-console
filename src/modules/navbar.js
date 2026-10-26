/**
 * Sentry Console — Enterprise Navbar, Mega-Menu & Trust Banner Controller
 * Manages mega-menu hover/click toggles, keyboard accessibility, outside clicks,
 * active link highlighting, and trust banner persistence.
 */

import { initAmbientBg } from './ambient_bg.js';

// Single canonical origin: sessionStorage is per-origin, so 0.0.0.0 / localhost / 127.0.0.1
// each kept their own saved results. Always redirect to 127.0.0.1 to avoid mismatches.
(function enforceCanonicalHost() {
  const h = window.location.hostname;
  if (h === '0.0.0.0' || h === 'localhost' || h === '[::1]') {
    window.location.replace(
      window.location.protocol + '//127.0.0.1' +
      (window.location.port ? ':' + window.location.port : '') +
      window.location.pathname + window.location.search + window.location.hash
    );
  }
})();

export function initNavbar() {
  try { setupActiveLinks(); } catch (e) { console.warn('[Navbar] Active links error:', e); }
  try { setupMegaMenus(); } catch (e) { console.warn('[Navbar] Mega menus error:', e); }
  try { setupTrustBanner(); } catch (e) { console.warn('[Navbar] Trust banner error:', e); }
  try { setupSecureContextWarning(); } catch (e) { console.warn('[Navbar] Secure context warning error:', e); }
  try { initAmbientBg(); } catch (e) { console.warn('[Navbar] Ambient bg error:', e); }
}

function setupActiveLinks() {
  const pathname = window.location.pathname.toLowerCase();
  const navLinks = document.querySelectorAll('.nav-link, .mega-nav-trigger');

  navLinks.forEach(link => {
    const href = link.getAttribute('href')?.toLowerCase();
    link.classList.remove('active');

    if (pathname.endsWith('/') || pathname.endsWith('index.html')) {
      if (href === 'index.html' || href === '/' || href === './') {
        link.classList.add('active');
      }
    } else if (href && href !== '#' && pathname.includes(href.replace('.html', ''))) {
      link.classList.add('active');
    }
  });
}

function setupMegaMenus() {
  const dropdownItems = document.querySelectorAll('.nav-item.has-dropdown');

  dropdownItems.forEach(item => {
    const trigger = item.querySelector('.mega-nav-trigger');
    const menu = item.querySelector('.mega-dropdown-menu');
    if (!trigger || !menu) return;

    let hoverTimeout = null;

    // Hover interactions
    item.addEventListener('mouseenter', () => {
      clearTimeout(hoverTimeout);
      closeAllMegaMenus();
      openMenu(item, trigger);
    });

    item.addEventListener('mouseleave', () => {
      hoverTimeout = setTimeout(() => {
        closeMenu(item, trigger);
      }, 150);
    });

    // Click / Touch / Keyboard interactions
    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      const isOpen = item.classList.contains('open');
      closeAllMegaMenus();
      if (!isOpen) {
        openMenu(item, trigger);
      }
    });

    // Keyboard support: Toggle on Enter / Space
    trigger.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const isOpen = item.classList.contains('open');
        closeAllMegaMenus();
        if (!isOpen) {
          openMenu(item, trigger);
        }
      }
    });
  });

  // Global Outside Click Dismiss
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.nav-item.has-dropdown')) {
      closeAllMegaMenus();
    }
  });

  // Escape key dismiss
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeAllMegaMenus();
    }
  });
}

function openMenu(item, trigger) {
  item.classList.add('open');
  trigger.setAttribute('aria-expanded', 'true');
}

function closeMenu(item, trigger) {
  item.classList.remove('open');
  trigger.setAttribute('aria-expanded', 'false');
}

function closeAllMegaMenus() {
  const dropdownItems = document.querySelectorAll('.nav-item.has-dropdown');
  dropdownItems.forEach(item => {
    const trigger = item.querySelector('.mega-nav-trigger');
    item.classList.remove('open');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  });
}

function setupTrustBanner() {
  const banner = document.getElementById('trust-announcement-bar');
  const closeBtn = document.getElementById('trust-announcement-close');

  if (!banner) return;

  if (sessionStorage.getItem('sentry_trust_banner_dismissed') === 'true') {
    banner.style.display = 'none';
  }

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      banner.style.display = 'none';
      sessionStorage.setItem('sentry_trust_banner_dismissed', 'true');
    });
  }
}

function setupSecureContextWarning() {
  const isCryptoAvailable = typeof window !== 'undefined' &&
    window.isSecureContext === true &&
    typeof crypto !== 'undefined' &&
    crypto !== null &&
    typeof crypto.subtle !== 'undefined' &&
    crypto.subtle !== null &&
    typeof crypto.subtle.digest === 'function';

  if (!isCryptoAvailable && typeof document !== 'undefined') {
    if (document.getElementById('secure-context-warning-bar')) return;

    const warningBar = document.createElement('div');
    warningBar.id = 'secure-context-warning-bar';
    warningBar.className = 'secure-context-warning-bar';
    warningBar.setAttribute('role', 'alert');
    warningBar.innerHTML = `
      <div class="secure-context-warning-content">
        <span class="warning-tag">⚠️ Non-Secure Context</span>
        <span>Running in a non-secure browser context — some hashing features are disabled. Serve via <strong>HTTPS</strong> or <strong>localhost</strong> for full functionality.</span>
      </div>
      <button class="secure-context-warning-close" aria-label="Dismiss warning">✕</button>
    `;

    if (document.body) {
      document.body.prepend(warningBar);
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        if (!document.getElementById('secure-context-warning-bar')) {
          document.body.prepend(warningBar);
        }
      });
    }

    const closeBtn = warningBar.querySelector('.secure-context-warning-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        warningBar.style.display = 'none';
      });
    }
  }
}

document.addEventListener('DOMContentLoaded', initNavbar);