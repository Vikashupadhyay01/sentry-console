/**
 * Sentry Console — SVG Force-Simulation Network Graph
 * Pure vanilla JS + SVG. No D3 dependency.
 * Nodes = unique IPs, sized by traffic volume.
 * Edges = flows, width proportional to byte count.
 * Suspicious/flagged IPs highlighted in red.
 */

export class NetworkGraph {
  constructor(svgEl) {
    this.svg      = svgEl;
    this.nodes    = [];
    this.edges    = [];
    this.width    = 800;
    this.height   = 550;
    this.dragging = null;
    this.panStart = null;
    this.panOffset= { x: 0, y: 0 };
    this.scale    = 1;
    this.animFrame= null;
    this._setupSvg();
  }

  _setupSvg() {
    if (this.svg._netGraphInstance && this.svg._netGraphInstance !== this) {
      try { this.svg._netGraphInstance.destroy(); } catch (e) {}
    }
    this.svg._netGraphInstance = this;

    this.svg.innerHTML = '';
    this.svg.setAttribute('viewBox', `0 0 ${this.width} ${this.height}`);

    // Defs: glow filters, arrowhead marker
    const defs = this._el('defs');
    defs.innerHTML = `
      <filter id="glow-green" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="3" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="4" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
        <path d="M0,0 L0,6 L6,3 z" fill="rgba(0,255,65,0.4)"/>
      </marker>
      <marker id="arrow-red" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
        <path d="M0,0 L0,6 L6,3 z" fill="rgba(255,68,68,0.6)"/>
      </marker>
    `;
    this.svg.appendChild(defs);

    // Group for pan/zoom transform
    this.g = this._el('g');
    this.g.setAttribute('id', 'graph-g');
    this.svg.appendChild(this.g);

    this._bindEvents();
  }

  _el(tag) {
    return document.createElementNS('http://www.w3.org/2000/svg', tag);
  }

  update(packets = [], findingsOrSuspicious = [], stats = null) {
    let findingsArray = [];
    if (Array.isArray(findingsOrSuspicious)) {
      findingsArray = findingsOrSuspicious;
    } else if (findingsOrSuspicious instanceof Set) {
      findingsArray = Array.from(findingsOrSuspicious).map(ip => ({ src: ip, dst: '' }));
    }
    this.build(packets, findingsArray, stats);
  }

  /**
   * Load pre-aggregated graph data (nodes + edges) and start the simulation.
   * This is the preferred method when coming from storage,
   * since the raw packets array is no longer persisted.
   *
   * @param {{ nodes: Array, edges: Array }} graphData
   */
  loadGraphData({ nodes = [], edges = [] } = {}) {
    console.log('[NetworkGraph] loadGraphData received nodes count:', nodes?.length, 'edges count:', edges?.length);
    if (!nodes || nodes.length === 0) {
      console.warn('[NetworkGraph] loadGraphData called with zero nodes.');
      return;
    }

    const cx = this.width / 2, cy = this.height / 2;
    const r  = Math.min(cx, cy) * 0.75;

    // Deep-copy so simulation mutations don't affect the stored data
    this.nodes = nodes.map((n, i) => ({
      ...n,
      packets: n.packets || n.count || 1,
      bytes: n.bytes || n.count || 1,
      x:  cx + r * Math.cos((2 * Math.PI * i) / nodes.length) + (Math.random() - 0.5) * 40,
      y:  cy + r * Math.sin((2 * Math.PI * i) / nodes.length) + (Math.random() - 0.5) * 40,
      vx: 0,
      vy: 0,
    }));
    this.edges = edges.map(e => ({
      ...e,
      bytes: e.bytes || e.count || 1,
      packets: e.packets || e.count || 1
    }));

    // Build IP → node lookup
    this._nodeByIP = {};
    for (const n of this.nodes) this._nodeByIP[n.ip] = n;

    this._render();
    this._startSimulation();
  }



  // ─── Build graph from packets + findings ─────────────────────────────────────

  build(packets = [], findings = [], stats = null) {
    // Collect node data
    const nodeMap   = {};  // ip -> { ip, packets, bytes, flagged }
    const edgeMap   = {};  // "src->dst" -> { src, dst, packets, bytes, flagged }
    const flaggedIPs = new Set();

    // Mark flagged IPs from findings
    for (const f of findings) {
      if (f.src && !f.src.includes(' ')) flaggedIPs.add(f.src);
      if (f.dst && !f.dst.includes(' ')) flaggedIPs.add(f.dst);
    }

    for (const p of packets) {
      if (!p.ipSrc || !p.ipDst) continue;

      // Nodes
      for (const ip of [p.ipSrc, p.ipDst]) {
        if (!nodeMap[ip]) nodeMap[ip] = { ip, packets: 0, bytes: 0, flagged: flaggedIPs.has(ip) };
      }
      nodeMap[p.ipSrc].packets++;
      nodeMap[p.ipDst].packets++;
      nodeMap[p.ipSrc].bytes += p.inclLen || 0;

      // Edges
      const eKey = `${p.ipSrc}->${p.ipDst}`;
      if (!edgeMap[eKey]) edgeMap[eKey] = {
        src: p.ipSrc, dst: p.ipDst,
        packets: 0, bytes: 0,
        flagged: flaggedIPs.has(p.ipSrc) || flaggedIPs.has(p.ipDst),
      };
      edgeMap[eKey].packets++;
      edgeMap[eKey].bytes += p.inclLen || 0;
    }

    this.nodes = Object.values(nodeMap);
    this.edges = Object.values(edgeMap).filter(e =>
      this.nodes.find(n => n.ip === e.src) && this.nodes.find(n => n.ip === e.dst)
    );

    // Limit to top 60 nodes by packet count for performance
    if (this.nodes.length > 60) {
      this.nodes.sort((a, b) => b.packets - a.packets);
      const kept = new Set(this.nodes.slice(0, 60).map(n => n.ip));
      // Always keep flagged
      for (const ip of flaggedIPs) kept.add(ip);
      this.nodes = this.nodes.filter(n => kept.has(n.ip));
      this.edges = this.edges.filter(e => kept.has(e.src) && kept.has(e.dst));
    }

    // Assign initial positions (circular layout + jitter)
    const cx = this.width / 2, cy = this.height / 2;
    const r  = Math.min(cx, cy) * 0.75;
    this.nodes.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / this.nodes.length;
      n.x  = cx + r * Math.cos(angle) + (Math.random() - 0.5) * 40;
      n.y  = cy + r * Math.sin(angle) + (Math.random() - 0.5) * 40;
      n.vx = 0;
      n.vy = 0;
    });

    // Build lookup
    this._nodeByIP = {};
    for (const n of this.nodes) this._nodeByIP[n.ip] = n;

    this._render();
    this._startSimulation();
  }

  // ─── Force simulation ─────────────────────────────────────────────────────

  _startSimulation() {
    if (this.animFrame) cancelAnimationFrame(this.animFrame);
    let iter = 0;
    const MAX_ITER = 300;

    const step = () => {
      if (iter++ >= MAX_ITER) {
        this._render(); // final render
        return;
      }
      this._simulateStep(iter / MAX_ITER);
      this._render();
      this.animFrame = requestAnimationFrame(step);
    };
    this.animFrame = requestAnimationFrame(step);
  }

  _simulateStep(progress) {
    const alpha = Math.max(0.05, 1 - progress * 1.2); // cooling
    const cx = this.width / 2, cy = this.height / 2;
    const nodes = this.nodes;
    const n = nodes.length;

    // Repulsion (O(n²) — fine for ≤60 nodes)
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const dist2 = dx * dx + dy * dy + 0.01;
        const dist  = Math.sqrt(dist2);
        const force = (2000 / dist2) * alpha;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        nodes[i].vx -= fx;
        nodes[i].vy -= fy;
        nodes[j].vx += fx;
        nodes[j].vy += fy;
      }
    }

    // Attraction (spring) along edges
    for (const e of this.edges) {
      const a = this._nodeByIP[e.src];
      const b = this._nodeByIP[e.dst];
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) + 0.01;
      const ideal = 120;
      const force = ((dist - ideal) / ideal) * 0.4 * alpha;
      const fx = (dx / dist) * force * dist;
      const fy = (dy / dist) * force * dist;
      a.vx += fx * 0.5;
      a.vy += fy * 0.5;
      b.vx -= fx * 0.5;
      b.vy -= fy * 0.5;
    }

    // Gravity toward center
    for (const nd of nodes) {
      nd.vx += (cx - nd.x) * 0.002 * alpha;
      nd.vy += (cy - nd.y) * 0.002 * alpha;
    }

    // Integrate + damping + boundary clamp
    for (const nd of nodes) {
      if (nd._pinned) { nd.vx = nd.vy = 0; continue; }
      nd.vx *= 0.85;
      nd.vy *= 0.85;
      nd.x = Math.max(30, Math.min(this.width  - 30, nd.x + nd.vx));
      nd.y = Math.max(30, Math.min(this.height - 30, nd.y + nd.vy));
    }
  }

  // ─── Render ───────────────────────────────────────────────────────────────

  _render() {
    try {
      this.g.innerHTML = '';
      if (!this.nodes || this.nodes.length === 0) return;

      // Max packet counts for sizing
      const maxPkts  = Math.max(...this.nodes.map(n => n.packets || 1), 1);
      const maxBytes = Math.max(...this.edges.map(e => e.bytes || 1), 1);

      const nodeRadius = (n) => {
        const pkts = n.packets || 1;
        const r = 5 + (Math.log(pkts + 1) / Math.log(maxPkts + 1)) * 18;
        return Math.max(5, Math.min(23, isNaN(r) ? 10 : r));
      };

      // ── Edges ──
      for (const e of this.edges) {
        const a = this._nodeByIP[e.src];
        const b = this._nodeByIP[e.dst];
        if (!a || !b) continue;

        const bytes = e.bytes || 1;
        const strokeW = 0.5 + (Math.log(bytes + 1) / Math.log(maxBytes + 1)) * 3;
        const line = this._el('line');
        line.setAttribute('x1', isNaN(a.x) ? 0 : a.x);
        line.setAttribute('y1', isNaN(a.y) ? 0 : a.y);
        line.setAttribute('x2', isNaN(b.x) ? 0 : b.x);
        line.setAttribute('y2', isNaN(b.y) ? 0 : b.y);
        line.setAttribute('stroke', e.flagged ? 'rgba(255,68,68,0.55)' : 'rgba(0,255,65,0.2)');
        line.setAttribute('stroke-width', (isNaN(strokeW) ? 1 : strokeW).toFixed(1));
        if (e.flagged) {
          line.setAttribute('stroke-dasharray', '5,3');
          line.setAttribute('marker-end', 'url(#arrow-red)');
        } else {
          line.setAttribute('marker-end', 'url(#arrow)');
        }
        this.g.appendChild(line);
      }

      // ── Nodes ──
      for (const nd of this.nodes) {
        const r = nodeRadius(nd);
        const nx = isNaN(nd.x) ? 100 : nd.x;
        const ny = isNaN(nd.y) ? 100 : nd.y;

        // Outer glow ring for flagged
        if (nd.flagged) {
          const ring = this._el('circle');
          ring.setAttribute('cx', nx);
          ring.setAttribute('cy', ny);
          ring.setAttribute('r', r + 5);
          ring.setAttribute('fill', 'none');
          ring.setAttribute('stroke', 'rgba(255,68,68,0.4)');
          ring.setAttribute('stroke-width', '1.5');
          ring.setAttribute('filter', 'url(#glow-red)');
          this.g.appendChild(ring);
        }

        const circle = this._el('circle');
        circle.setAttribute('cx', nx);
        circle.setAttribute('cy', ny);
        circle.setAttribute('r', r);
        circle.setAttribute('fill', nd.flagged ? 'rgba(255,68,68,0.2)' : 'rgba(0,255,65,0.12)');
        circle.setAttribute('stroke', nd.flagged ? '#ff4444' : '#00ff41');
        circle.setAttribute('stroke-width', nd.flagged ? '2' : '1');
        circle.setAttribute('filter', nd.flagged ? 'url(#glow-red)' : 'url(#glow-green)');
        circle.style.cursor = 'grab';
        this._bindNodeEvents(circle, nd);
        this.g.appendChild(circle);

        // IP label (only if radius big enough)
        if (r >= 8) {
          const label = this._el('text');
          label.setAttribute('x', nx);
          label.setAttribute('y', ny + r + 12);
          label.setAttribute('text-anchor', 'middle');
          label.setAttribute('fill', nd.flagged ? '#ff8888' : '#6aff8e');
          label.setAttribute('font-size', '9');
          label.setAttribute('font-family', "'IBM Plex Mono', monospace");
          label.setAttribute('pointer-events', 'none');
          label.textContent = nd.ip;
          this.g.appendChild(label);
        }

        // Tooltip group
        const title = this._el('title');
        title.textContent = `${nd.ip}\nPackets: ${(nd.packets || 0).toLocaleString()}\nBytes: ${(nd.bytes || 0).toLocaleString()}\n${nd.flagged ? '⚠ FLAGGED' : ''}`;
        circle.appendChild(title);
      }
    } catch (renderErr) {
      console.error('[NetworkGraph] _render error:', renderErr);
    }
  }

  // ─── Drag ─────────────────────────────────────────────────────────────────

  _bindNodeEvents(el, nd) {
    el.addEventListener('mousedown', (e) => {
      e.stopPropagation();
      nd._pinned = true;
      this.dragging = { nd, el };
      el.style.cursor = 'grabbing';
    });
  }

  _bindEvents() {
    this._mousemoveHandler = (e) => {
      if (this.dragging) {
        const rect = this.svg.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          const scaleX = this.width  / rect.width;
          const scaleY = this.height / rect.height;
          this.dragging.nd.x = (e.clientX - rect.left) * scaleX - this.panOffset.x;
          this.dragging.nd.y = (e.clientY - rect.top)  * scaleY - this.panOffset.y;
          this._render();
        }
      }
    };

    this._mouseupHandler = () => {
      if (this.dragging) {
        if (this.dragging.el) this.dragging.el.style.cursor = 'grab';
        this.dragging = null;
      }
    };

    this._mouseleaveHandler = () => { this.dragging = null; };

    this.svg.addEventListener('mousemove', this._mousemoveHandler);
    this.svg.addEventListener('mouseup', this._mouseupHandler);
    this.svg.addEventListener('mouseleave', this._mouseleaveHandler);
  }

  destroy() {
    if (this.animFrame) cancelAnimationFrame(this.animFrame);
    if (this._mousemoveHandler) this.svg.removeEventListener('mousemove', this._mousemoveHandler);
    if (this._mouseupHandler) this.svg.removeEventListener('mouseup', this._mouseupHandler);
    if (this._mouseleaveHandler) this.svg.removeEventListener('mouseleave', this._mouseleaveHandler);
    this.svg.innerHTML = '';
  }
}
