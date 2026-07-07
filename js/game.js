/* Hlavní smyčka, vstup, UI, minimapa. */
(function () {
  'use strict';
  const EG = window.EG;
  const A = EG.atlas;
  const S = A.S;

  const MAP_SIZE = 160;

  let map, sim, renderer;
  let tool = 'pan';            // pan | hydro | dam | coal | solar | wind | sub | line | demolish
  let lineFrom = null;         // budova, odkud táhneme vedení
  let hover = [0, 0];
  let mouse = { x: 0, y: 0, down: false, panning: false, lastX: 0, lastY: 0 };
  let speed = 1;
  let lastMsgCount = 0;

  const $ = (s) => document.querySelector(s);

  function kindSprite(kind) {
    return { hydro: S.HYDRO, dam: S.DAM, coal: S.COAL, solar: S.SOLAR, wind: S.WIND, sub: S.SUBST }[kind];
  }

  function init() {
    const seedStr = new URLSearchParams(location.search).get('seed');
    const seed = seedStr ? (parseInt(seedStr, 10) || 1) : ((Math.random() * 1e9) | 0);
    map = EG.generateMap(MAP_SIZE, seed);
    sim = new EG.Sim(map);
    const canvas = $('#game');
    renderer = new EG.Renderer(canvas);
    // jemné tónování podle výšky, ať mapa není plochá jednolitá barva
    const tintFn = (x, y) => 0.88 + Math.min(0.24, Math.max(0, map.elev[map.idx(x, y)] - 0.3) * 0.55);
    EG.onTerrainChanged = () => renderer.uploadTerrain(map, tintFn);
    renderer.uploadTerrain(map, tintFn);

    // kamera do středu první osady
    const c0 = map.cities[0] || { x: MAP_SIZE / 2, y: MAP_SIZE / 2 };
    const [wx, wy] = renderer.tileToWorld(c0.x, c0.y);
    renderer.cam.x = wx; renderer.cam.y = wy;
    renderer.cam.zoom = 0.9;

    $('#seed-label').textContent = 'seed ' + seed;
    $('#btn-newmap').addEventListener('click', () => {
      location.search = '?seed=' + ((Math.random() * 1e9) | 0);
    });

    setupInput(canvas);
    setupToolbar();
    setupMinimap();
    sim.msg('Vítej! Postav elektrárnu, rozvodnu u města a spoj je vedením.');

    // ladicí přístup (používá i smoke test)
    EG.game = { get sim() { return sim; }, get map() { return map; }, get renderer() { return renderer; } };

    requestAnimationFrame(loop);
  }

  /* ---------- vstup ---------- */
  function setupInput(canvas) {
    canvas.addEventListener('mousedown', (e) => {
      mouse.down = true; mouse.lastX = e.clientX; mouse.lastY = e.clientY;
      mouse.panning = (e.button === 1 || e.button === 2 || tool === 'pan');
    });
    window.addEventListener('mouseup', (e) => {
      const wasPan = mouse.panning && (Math.abs(e.clientX - mouse.lastX) + Math.abs(e.clientY - mouse.lastY) > 4);
      mouse.down = false; mouse.panning = false;
      if (e.button === 0 && !wasPan && e.target === canvas) click();
    });
    canvas.addEventListener('contextmenu', (e) => e.preventDefault());
    canvas.addEventListener('mousemove', (e) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left; mouse.y = e.clientY - rect.top;
      if (mouse.down && mouse.panning) {
        renderer.cam.x -= (e.clientX - mouse.lastX) / renderer.cam.zoom;
        renderer.cam.y -= (e.clientY - mouse.lastY) / renderer.cam.zoom;
        mouse.lastX = e.clientX; mouse.lastY = e.clientY;
      } else {
        mouse.lastX = e.clientX; mouse.lastY = e.clientY;
      }
      hover = renderer.screenToTile(mouse.x, mouse.y);
      updateHoverInfo();
    });
    canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const z = renderer.cam.zoom;
      const nz = Math.min(3.2, Math.max(0.18, z * (e.deltaY < 0 ? 1.15 : 0.87)));
      // zoom ke kurzoru
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left - canvas.clientWidth / 2;
      const my = e.clientY - rect.top - canvas.clientHeight / 2;
      renderer.cam.x += mx / z - mx / nz;
      renderer.cam.y += my / z - my / nz;
      renderer.cam.zoom = nz;
    }, { passive: false });

    window.addEventListener('keydown', (e) => {
      const k = e.key.toLowerCase();
      const byHotkey = Object.entries(EG.BUILD).find(([, v]) => v.hotkey === k);
      if (byHotkey) setTool(byHotkey[0] === 'line' ? 'line' : byHotkey[0]);
      else if (k === 'escape' || k === 'q') setTool('pan');
      else if (k === 'x') setTool('demolish');
      else if (k === ' ') { e.preventDefault(); speed = speed === 0 ? 1 : 0; updateSpeedLabel(); }
      else if (k === '+' || k === '=') { speed = Math.min(4, (speed || 1) * 2); updateSpeedLabel(); }
      else if (k === '-') { speed = Math.max(1, speed / 2) * (speed === 0 ? 0 : 1); updateSpeedLabel(); }
    });
  }

  function click() {
    const [gx, gy] = hover;
    if (tool === 'pan') {
      const b = sim.buildingAt(gx, gy);
      if (b) selectInfo(b);
      return;
    }
    if (tool === 'demolish') {
      // klik na vedení? – najdi nejbližší segment do 0.6 dlaždice
      const l = lineNear(gx, gy);
      if (l && !sim.buildingAt(gx, gy)) { sim.removeLine(l); return; }
      sim.demolish(gx, gy);
      return;
    }
    if (tool === 'line') {
      const b = sim.buildingAt(gx, gy);
      if (!b) { sim.msg('Vedení musí začínat i končit na stavbě', 'warn'); return; }
      if (!lineFrom) { lineFrom = b; sim.msg('Vyber cílovou stavbu'); return; }
      sim.connect(lineFrom, b);
      lineFrom = b; // řetězení vedení
      return;
    }
    // stavba budovy
    const b = sim.place(tool, gx, gy);
    if (b && tool !== 'sub') {
      // pohodlí: po postavení elektrárny rovnou nabídnout vedení
    }
  }

  function lineNear(gx, gy) {
    let best = null, bestD = 0.7;
    for (const l of sim.lines) {
      const a = sim.buildings.find((b) => b.id === l.a);
      const b = sim.buildings.find((o) => o.id === l.b);
      if (!a || !b) continue;
      const d = distToSeg(gx, gy, a.x, a.y, b.x, b.y);
      if (d < bestD) { bestD = d; best = l; }
    }
    return best;
  }

  function distToSeg(px, py, x1, y1, x2, y2) {
    const dx = x2 - x1, dy = y2 - y1;
    const len2 = dx * dx + dy * dy;
    let t = len2 ? ((px - x1) * dx + (py - y1) * dy) / len2 : 0;
    t = Math.max(0, Math.min(1, t));
    return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
  }

  /* ---------- toolbar ---------- */
  function setTool(t) {
    tool = t;
    lineFrom = null;
    document.querySelectorAll('.tool').forEach((el) => {
      el.classList.toggle('active', el.dataset.tool === t);
    });
    $('#game').style.cursor = t === 'pan' ? 'grab' : 'crosshair';
  }

  function setupToolbar() {
    const bar = $('#toolbar');
    const tools = [
      { t: 'pan', label: 'Prohlížet', key: 'Q' },
      ...Object.entries(EG.BUILD).map(([k, v]) => ({
        t: k, label: v.name, key: v.hotkey.toUpperCase(), cost: v.cost, desc: v.desc,
      })),
      { t: 'demolish', label: 'Zbourat', key: 'X' },
    ];
    for (const def of tools) {
      const el = document.createElement('button');
      el.className = 'tool';
      el.dataset.tool = def.t;
      el.innerHTML = '<span class="key">' + def.key + '</span>' + def.label +
        (def.cost ? '<span class="cost">' + def.cost + (def.t === 'line' ? '/dl' : '') + '</span>' : '');
      if (def.desc) el.title = def.desc;
      el.addEventListener('click', () => setTool(def.t));
      bar.appendChild(el);
    }
    setTool('pan');
    $('#btn-speed').addEventListener('click', () => {
      speed = speed === 0 ? 1 : speed >= 4 ? 0 : speed * 2;
      updateSpeedLabel();
    });
  }

  function updateSpeedLabel() {
    $('#btn-speed').textContent = speed === 0 ? '⏸ pauza' : '▶ ' + speed + '×';
  }

  function selectInfo(b) {
    const def = EG.BUILD[b.kind];
    sim.msg(def.name + ' – výkon ' + b.out.toFixed(1) + ' MW');
  }

  function updateHoverInfo() {
    const [gx, gy] = hover;
    const el = $('#hover-info');
    if (gx < 0 || gy < 0 || gx >= map.size || gy >= map.size) { el.textContent = ''; return; }
    const t = map.type[map.idx(gx, gy)];
    const names = ['jezero', 'písek', 'louka', 'les', 'kopec', 'hora', 'řeka', 'nádrž'];
    let s = '[' + gx + ',' + gy + '] ' + (names[t] || '?');
    if (t === 6) s += ' · průtok ' + map.flow[map.idx(gx, gy)].toFixed(1);
    const b = sim.buildingAt(gx, gy);
    if (b) s += ' · ' + EG.BUILD[b.kind].name + ' ' + b.out.toFixed(0) + '/' + b.gen.toFixed(0) + ' MW';
    const city = map.cities.find((c) => Math.abs(c.x - gx) <= 2 && Math.abs(c.y - gy) <= 2);
    if (city) s += ' · ' + city.name + ' (' + city.pop + ' tis., napájení ' + Math.round((city.powered || 0) * 100) + ' %)';
    el.textContent = s;
  }

  /* ---------- minimapa ---------- */
  let minimapCtx, minimapBase;
  function setupMinimap() {
    const cv = $('#minimap');
    cv.width = map.size; cv.height = map.size;
    minimapCtx = cv.getContext('2d');
    minimapBase = document.createElement('canvas');
    minimapBase.width = map.size; minimapBase.height = map.size;
    const g = minimapBase.getContext('2d');
    const img = g.createImageData(map.size, map.size);
    const colors = {
      0: [46, 111, 168], 1: [216, 201, 141], 2: [124, 179, 91], 3: [105, 160, 76],
      4: [143, 174, 100], 5: [142, 141, 134], 6: [63, 134, 192], 7: [51, 115, 159],
    };
    for (let i = 0; i < map.size * map.size; i++) {
      const c = colors[map.type[i]] || [0, 0, 0];
      img.data[i * 4] = c[0]; img.data[i * 4 + 1] = c[1]; img.data[i * 4 + 2] = c[2]; img.data[i * 4 + 3] = 255;
    }
    g.putImageData(img, 0, 0);
    cv.addEventListener('click', (e) => {
      const r = cv.getBoundingClientRect();
      const gx = (e.clientX - r.left) / r.width * map.size;
      const gy = (e.clientY - r.top) / r.height * map.size;
      const [wx, wy] = renderer.tileToWorld(gx, gy);
      renderer.cam.x = wx; renderer.cam.y = wy;
    });
  }

  function drawMinimap() {
    const g = minimapCtx;
    g.drawImage(minimapBase, 0, 0);
    for (const c of map.cities) {
      g.fillStyle = (c.powered || 0) > 0.9 ? '#ffe14d' : '#ff5340';
      g.fillRect(c.x - 1.5, c.y - 1.5, 4, 4);
    }
    g.strokeStyle = 'rgba(255,255,255,0.85)'; g.lineWidth = 1;
    for (const l of sim.lines) {
      const a = sim.buildings.find((b) => b.id === l.a);
      const b = sim.buildings.find((o) => o.id === l.b);
      if (!a || !b) continue;
      g.beginPath(); g.moveTo(a.x, a.y); g.lineTo(b.x, b.y); g.stroke();
    }
    for (const b of sim.buildings) {
      g.fillStyle = b.kind === 'sub' ? '#e8c84a' : '#ffffff';
      g.fillRect(b.x - 1, b.y - 1, 2.5, 2.5);
    }
    // rámeček kamery
    const z = renderer.cam.zoom;
    const cw = renderer.canvas.clientWidth / z, ch = renderer.canvas.clientHeight / z;
    const gx = (renderer.cam.x / EG.iso.HW + renderer.cam.y / EG.iso.HH) / 2;
    const gy = (renderer.cam.y / EG.iso.HH - renderer.cam.x / EG.iso.HW) / 2;
    g.strokeStyle = 'rgba(255,255,255,0.6)';
    g.strokeRect(gx - cw / 130, gy - ch / 70, cw / 65, ch / 35);
  }

  /* ---------- HUD ---------- */
  function updateHUD() {
    $('#money').textContent = Math.floor(sim.money).toLocaleString('cs-CZ') + ' ₤';
    const st = sim.stats;
    $('#power').textContent = st.delivered.toFixed(0) + ' / ' + st.demand.toFixed(0) + ' MW';
    $('#power').className = st.demand > 0 && st.delivered / st.demand < 0.7 ? 'bad' : (st.delivered / Math.max(1, st.demand) < 0.98 ? 'warn' : '');
    $('#income').textContent = (st.income >= 0 ? '+' : '') + (st.income * 60).toFixed(1) + '/min';
    $('#score').textContent = Math.floor(sim.score).toLocaleString('cs-CZ');
    const ph = sim.dayPhase || 0;
    const hours = Math.floor(6 + ph * 24) % 24;
    $('#clock').textContent = String(hours).padStart(2, '0') + ':00 ' +
      (sim.sun > 0.05 ? '☀' + Math.round(sim.sun * 100) + '%' : '☾') + ' 💨' + Math.round(sim.wind * 100) + '%';

    if (sim.messages.length !== lastMsgCount) {
      lastMsgCount = sim.messages.length;
      const log = $('#log');
      log.innerHTML = sim.messages.slice(-6).map((m) =>
        '<div class="' + m.kind + '">' + m.text + '</div>').join('');
      log.scrollTop = log.scrollHeight;
    }
  }

  /* ---------- vykreslení scény ---------- */
  function pushScene() {
    renderer.beginDynamic();
    const id2b = new Map();
    for (const b of sim.buildings) id2b.set(b.id, b);

    // vedení
    for (const l of sim.lines) {
      const a = id2b.get(l.a), b = id2b.get(l.b);
      if (!a || !b) continue;
      let r = 0.25, g = 0.25, bl = 0.28;
      if (l.load > 1) { r = 0.95; g = 0.2; bl = 0.15; }
      else if (l.load > 0.75) { r = 0.95; g = 0.6; bl = 0.1; }
      const dir = l.flow > 0.5 ? 1 : (l.flow < -0.5 ? -1 : 0);
      renderer.pushLine(a.x, a.y, b.x, b.y, r, g, bl, 0.95, Math.min(1, l.load), dir);
    }
    // rozestavěné vedení
    if (tool === 'line' && lineFrom) {
      renderer.pushLine(lineFrom.x, lineFrom.y, hover[0], hover[1], 1, 0.9, 0.3, 0.6, 0, 0);
    }

    // města (seřazení podle hloubky řeší pořadí přidání – kreslíme po diagonálách zjednodušeně dle y)
    const spr = [];
    for (const c of map.cities) {
      for (let i = 0; i < c.houses.length; i++) {
        const [hx, hy] = c.houses[i];
        if (hx === c.x && hy === c.y) continue;
        spr.push([hx, hy, (hx * 7 + hy * 13) % 3 === 0 ? S.HOUSE2 : S.HOUSE, c]);
      }
      spr.push([c.x, c.y, S.CENTER, c]);
    }
    for (const b of sim.buildings) spr.push([b.x, b.y, kindSprite(b.kind), null, b]);
    spr.sort((p, q) => (p[0] + p[1]) - (q[0] + q[1]));
    for (const [x, y, sId, city, b] of spr) {
      let dim = 1;
      if (city && (city.powered || 0) < 0.5 && sim.sun < 0.15) dim = 0.55; // blackout v noci
      let tintR = dim, tintG = dim, tintB = dim;
      if (b && b.kind !== 'sub' && b.gen > 0.5 && b.out < 0.1) { tintG = 0.75; tintB = 0.7; } // odpojená elektrárna
      renderer.pushSprite(x, y, sId, tintR, tintG, tintB, 1);
    }

    // dosah rozvodny při stavbě
    if (tool === 'sub') {
      const R = EG.SUB_RANGE;
      for (let dy = -R; dy <= R; dy++) for (let dx = -R; dx <= R; dx++) {
        if (Math.hypot(dx, dy) > R || (dx === 0 && dy === 0)) continue;
        if ((dx + dy) % 2 !== 0) continue; // řidší mřížka, ať to neruší
        renderer.pushSprite(hover[0] + dx, hover[1] + dy, S.CITYRING, 1, 1, 1, 0.35);
      }
    }

    // kurzor
    if (tool !== 'pan') {
      const [gx, gy] = hover;
      let ok = true;
      if (tool === 'demolish') ok = !!sim.buildingAt(gx, gy) || !!lineNear(gx, gy);
      else if (tool === 'line') ok = !!sim.buildingAt(gx, gy);
      else ok = sim.canPlace(tool, gx, gy).ok;
      renderer.pushSprite(gx, gy, ok ? S.SEL : S.BAD);
      if (ok && tool !== 'demolish' && tool !== 'line') {
        renderer.pushSprite(gx, gy, kindSprite(tool), 1, 1, 1, 0.55);
      }
    }

    // nenapájená města – blikající indikátor
    const blink = (Math.sin(performance.now() * 0.006) + 1) / 2;
    for (const c of map.cities) {
      if ((c.powered || 0) < 0.9) {
        renderer.pushSprite(c.x, c.y, S.BAD, 1, 1, 1, 0.25 + 0.5 * blink);
      }
    }
  }

  /* ---------- smyčka ---------- */
  let lastT = 0;
  function loop(t) {
    const dt = Math.min(0.1, (t - lastT) / 1000 || 0.016);
    lastT = t;
    if (speed > 0) sim.tick(dt * speed);
    pushScene();
    renderer.render(t / 1000);
    drawMinimap();
    updateHUD();
    requestAnimationFrame(loop);
  }

  window.addEventListener('DOMContentLoaded', init);
})();
