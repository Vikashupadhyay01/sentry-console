/**
 * Sentry Console — Ambient Background & Live Network Graph Module
 * Injects a decorative, low-light SVG network graph layer behind page content.
 * Pure CSS/SVG-driven breathing node animations and sparse signal flashes.
 */

export function initAmbientBg() {
  if (document.querySelector('.ambient-bg')) return;

  const bgContainer = document.createElement('div');
  bgContainer.className = 'ambient-bg';
  bgContainer.setAttribute('aria-hidden', 'true');
  bgContainer.innerHTML = buildAmbientSvg();

  if (document.body) {
    document.body.prepend(bgContainer);
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      if (!document.querySelector('.ambient-bg')) {
        document.body.prepend(bgContainer);
      }
    });
  }
}

function buildAmbientSvg() {
  // ~22 nodes scattered across 1000x1000 viewport coordinate space
  const nodes = [
    { x: 80,  y: 100, delay: '0s',   duration: '5.5s' },
    { x: 240, y: 60,  delay: '1.2s', duration: '6.8s' },
    { x: 410, y: 140, delay: '3.4s', duration: '4.9s' },
    { x: 580, y: 80,  delay: '0.7s', duration: '7.1s' },
    { x: 760, y: 120, delay: '2.1s', duration: '5.8s' },
    { x: 920, y: 70,  delay: '4.3s', duration: '6.4s' },

    { x: 120, y: 320, delay: '1.8s', duration: '6.2s' },
    { x: 300, y: 390, delay: '3.9s', duration: '5.2s' },
    { x: 490, y: 290, delay: '0.4s', duration: '7.5s' },
    { x: 670, y: 370, delay: '2.7s', duration: '4.7s' },
    { x: 840, y: 290, delay: '4.8s', duration: '6.6s' },
    { x: 960, y: 440, delay: '1.1s', duration: '5.9s' },

    { x: 70,  y: 650, delay: '3.1s', duration: '6.5s' },
    { x: 260, y: 590, delay: '0.9s', duration: '5.3s' },
    { x: 440, y: 720, delay: '4.1s', duration: '7.0s' },
    { x: 610, y: 610, delay: '2.3s', duration: '4.8s' },
    { x: 790, y: 690, delay: '1.5s', duration: '6.1s' },
    { x: 900, y: 650, delay: '3.6s', duration: '5.7s' },

    { x: 160, y: 870, delay: '2.8s', duration: '6.9s' },
    { x: 470, y: 910, delay: '0.2s', duration: '5.4s' },
    { x: 720, y: 880, delay: '4.5s', duration: '6.3s' },
    { x: 890, y: 850, delay: '1.9s', duration: '7.3s' }
  ];

  // Loose constellation network graph connections
  const edges = [
    [0, 1], [1, 2], [2, 3], [3, 4], [4, 5],
    [0, 6], [1, 7], [2, 8], [3, 9], [4, 10], [5, 11],
    [6, 7], [7, 8], [8, 9], [9, 10], [10, 11],
    [6, 12], [7, 13], [8, 14], [9, 15], [10, 16], [11, 17],
    [12, 13], [13, 14], [14, 15], [15, 16], [16, 17],
    [12, 18], [14, 19], [16, 20], [17, 21],
    [18, 19], [19, 20], [20, 21]
  ];

  // Sparse signal flashes on select edges
  const flashEdgeMap = new Map([
    [7,  { delay: '1s',  duration: '9s' }],   // Edge [2, 8]
    [15, { delay: '5s',  duration: '13s' }],  // Edge [9, 15]
    [24, { delay: '8s',  duration: '11s' }],  // Edge [14, 15]
    [30, { delay: '3s',  duration: '14s' }]   // Edge [17, 21]
  ]);

  let linesSvg = '';
  edges.forEach(([i, j], index) => {
    const n1 = nodes[i];
    const n2 = nodes[j];
    if (flashEdgeMap.has(index)) {
      const { delay, duration } = flashEdgeMap.get(index);
      linesSvg += `<line x1="${n1.x}" y1="${n1.y}" x2="${n2.x}" y2="${n2.y}" class="ambient-line-flash" style="--delay: ${delay}; --duration: ${duration};" />`;
    } else {
      linesSvg += `<line x1="${n1.x}" y1="${n1.y}" x2="${n2.x}" y2="${n2.y}" class="ambient-line" />`;
    }
  });

  let nodesSvg = '';
  nodes.forEach(node => {
    nodesSvg += `<circle cx="${node.x}" cy="${node.y}" r="2" class="ambient-node" style="--delay: ${node.delay}; --duration: ${node.duration};" />`;
  });

  return `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000" preserveAspectRatio="xMidYMid slice" style="pointer-events: none !important;">
      <g class="ambient-lines" style="pointer-events: none !important;">
        ${linesSvg}
      </g>
      <g class="ambient-nodes" style="pointer-events: none !important;">
        ${nodesSvg}
      </g>
    </svg>
  `.trim();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAmbientBg);
} else {
  initAmbientBg();
}
