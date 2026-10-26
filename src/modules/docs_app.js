/**
 * Sentry Console — Documentation Application Controller
 * Handles real-time docs sidebar live search filtering, active section highlighting,
 * and smooth anchor navigation.
 */

export function initDocsPage() {
  console.log('[Sentry Docs] Initializing Documentation Application');

  setupDocsSearch();
  setupScrollSpy();
}

function setupDocsSearch() {
  const searchInput = document.getElementById('docs-search-input');
  if (!searchInput) return;

  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    const navItems = document.querySelectorAll('.docs-nav-item');
    const navGroups = document.querySelectorAll('.docs-nav-group');

    if (!query) {
      navItems.forEach(item => item.style.display = 'block');
      navGroups.forEach(group => group.style.display = 'block');
      return;
    }

    navGroups.forEach(group => {
      let hasVisibleChild = false;
      const items = group.querySelectorAll('.docs-nav-item');

      items.forEach(item => {
        const text = item.textContent.toLowerCase();
        if (text.includes(query)) {
          item.style.display = 'block';
          hasVisibleChild = true;
        } else {
          item.style.display = 'none';
        }
      });

      group.style.display = hasVisibleChild ? 'block' : 'none';
    });
  });
}

function setupScrollSpy() {
  const sections = document.querySelectorAll('.doc-section');
  const navLinks = document.querySelectorAll('.docs-nav-item a');

  window.addEventListener('scroll', () => {
    let currentId = '';
    const scrollPosition = window.scrollY + 100;

    sections.forEach(sec => {
      const top = sec.offsetTop;
      const height = sec.offsetHeight;
      if (scrollPosition >= top && scrollPosition < top + height) {
        currentId = sec.getAttribute('id');
      }
    });

    if (currentId) {
      navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${currentId}`) {
          link.classList.add('active');
        }
      });
    }
  });
}

document.addEventListener('DOMContentLoaded', initDocsPage);
