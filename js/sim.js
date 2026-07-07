/* Herní simulace: elektrárny, vedení, rozvodny, města, toky energie.
   Toky v síti se počítají zjednodušeným DC power-flow modelem:
   uzlová injekce P (výroba − spotřeba), Laplacián sítě, iterační
   Gauss–Seidel řešení fázových úhlů, tok hranou = rozdíl úhlů. */
(function () {
  'use strict';
  const EG = window.EG;
  const T = () => EG.T;

  const BUILD = {
    hydro: {
      name: 'Vodní elektrárna', cost: 220, upkeep: 2,
      desc: 'Jen na řece. Výkon dle průtoku. Přehrada nad ní průtok posílí.',
      hotkey: '1',
    },
    dam: {
      name: 'Přehrada', cost: 520, upkeep: 4,
      desc: 'Jen na řece. Vytvoří nádrž, velký stabilní výkon a posílí průtok níže.',
      hotkey: '2',
    },
    coal: {
      name: 'Uhelná elektrárna', cost: 380, upkeep: 14,
      desc: 'Kdekoli na pevnině. Stabilních 90 MW, ale drahý provoz.',
      hotkey: '3',
    },
    solar: {
      name: 'Solární park', cost: 160, upkeep: 1,
      desc: 'Na trávě. Až 35 MW, jen ve dne.',
      hotkey: '4',
    },
    wind: {
      name: 'Větrná turbína', cost: 130, upkeep: 1,
      desc: 'Na kopcích nejvíc. Až 30 MW, kolísá s větrem.',
      hotkey: '5',
    },
    sub: {
      name: 'Rozvodna', cost: 90, upkeep: 1,
      desc: 'Napájí města do vzdálenosti 6 dlaždic. Bez ní města nesvítí.',
      hotkey: '6',
    },
    line: {
      name: 'Vedení', cost: 6, upkeep: 0.06,
      desc: 'Spojuje stavby. Cena za dlaždici délky. Kapacita 120 MW.',
      hotkey: '7',
    },
  };

  const LINE_CAP = 120;       // MW na jedno vedení
  const SUB_RANGE = 6;        // dosah rozvodny k městu
  const PRICE_PER_MWH = 0.055; // příjem za dodanou MW za sekundu hry

  function Sim(map) {
    this.map = map;
    this.buildings = [];      // {id,kind,x,y,out,node}
    this.lines = [];          // {a,b,id,flow,load}
    this.money = 900;
    this.time = 0;            // herní sekundy
    this.dayLen = 120;        // délka dne
    this.score = 0;
    this.nextId = 1;
    this.blackouts = 0;
    this.messages = [];
    this.stats = { produced: 0, delivered: 0, demand: 0 };
    this._noiseT = Math.random() * 1000;
  }

  Sim.prototype.msg = function (text, kind) {
    this.messages.push({ text, kind: kind || 'info', t: this.time });
    if (this.messages.length > 60) this.messages.shift();
  };

  Sim.prototype.buildingAt = function (x, y) {
    return this.buildings.find((b) => b.x === x && b.y === y) || null;
  };

  Sim.prototype.canPlace = function (kind, x, y) {
    const m = this.map;
    if (x < 0 || y < 0 || x >= m.size || y >= m.size) return { ok: false, why: 'Mimo mapu' };
    const t = m.type[m.idx(x, y)];
    if (this.buildingAt(x, y)) return { ok: false, why: 'Obsazeno' };
    for (const c of m.cities) {
      if (Math.abs(c.x - x) <= 1 && Math.abs(c.y - y) <= 1) return { ok: false, why: 'Centrum města' };
      if (c.houses.some(([hx, hy]) => hx === x && hy === y)) return { ok: false, why: 'Zástavba' };
    }
    const TT = T();
    switch (kind) {
      case 'hydro':
      case 'dam':
        if (t !== TT.RIVER) return { ok: false, why: 'Jen na řece' };
        return { ok: true };
      case 'coal':
        if (t === TT.WATER || t === TT.RIVER || t === TT.MOUNTAIN) return { ok: false, why: 'Jen na pevnině' };
        return { ok: true };
      case 'solar':
        if (t !== TT.GRASS && t !== TT.SAND) return { ok: false, why: 'Jen na rovině' };
        return { ok: true };
      case 'wind':
        if (t === TT.WATER || t === TT.RIVER) return { ok: false, why: 'Ne na vodě' };
        return { ok: true };
      case 'sub':
        if (t === TT.WATER || t === TT.RIVER || t === TT.MOUNTAIN) return { ok: false, why: 'Jen na pevnině' };
        return { ok: true };
    }
    return { ok: false, why: '?' };
  };

  Sim.prototype.place = function (kind, x, y) {
    const chk = this.canPlace(kind, x, y);
    if (!chk.ok) { this.msg(chk.why, 'warn'); return null; }
    const cost = BUILD[kind].cost;
    if (this.money < cost) { this.msg('Nedostatek peněz', 'warn'); return null; }
    this.money -= cost;
    const b = { id: this.nextId++, kind, x, y, out: 0, gen: 0 };
    this.buildings.push(b);
    if (kind === 'dam') this._applyDam(b);
    this.msg(BUILD[kind].name + ' postavena (−' + cost + ')');
    return b;
  };

  /* Přehrada: zaplaví pár dlaždic řeky proti proudu (nádrž)
     a zvýší průtok po proudu. */
  Sim.prototype._applyDam = function (b) {
    const m = this.map;
    const TT = T();
    // po proudu +60 % průtoku
    let x = b.x, y = b.y;
    for (let i = 0; i < m.size; i++) {
      const j = m.idx(x, y);
      const d = m.flowDir[j];
      if (i > 0) m.flow[j] *= 1.6;
      if (d < 0) break;
      x += EG.DIRS[d][0]; y += EG.DIRS[d][1];
      if (x < 0 || y < 0 || x >= m.size || y >= m.size) break;
      if (m.type[m.idx(x, y)] !== TT.RIVER) break;
    }
    // proti proudu vytvoř nádrž (RESERVOIR = 7)
    const visited = new Set([m.idx(b.x, b.y)]);
    let frontier = [[b.x, b.y]];
    let flooded = 0;
    while (frontier.length && flooded < 14) {
      const next = [];
      for (const [fx, fy] of frontier) {
        for (const [dx, dy] of EG.DIRS) {
          const nx = fx + dx, ny = fy + dy;
          if (nx < 0 || ny < 0 || nx >= m.size || ny >= m.size) continue;
          const j = m.idx(nx, ny);
          if (visited.has(j)) continue;
          // je to řeka tekoucí SEM? (její flowDir ukazuje na [fx,fy])
          const d = m.flowDir[j];
          if (m.type[j] === TT.RIVER && d >= 0 &&
              nx + EG.DIRS[d][0] === fx && ny + EG.DIRS[d][1] === fy) {
            visited.add(j);
            m.type[j] = 7; // RESERVOIR
            flooded++;
            next.push([nx, ny]);
          }
        }
      }
      frontier = next;
    }
    b.reservoir = flooded;
    if (EG.onTerrainChanged) EG.onTerrainChanged();
  };

  Sim.prototype.demolish = function (x, y) {
    const b = this.buildingAt(x, y);
    if (!b) {
      // smazat vedení procházející bodem? – mažeme vedení klikem na koncový uzel
      return false;
    }
    if (b.kind === 'dam') { this.msg('Přehradu nelze zbourat (nádrž je napuštěná)', 'warn'); return false; }
    this.buildings = this.buildings.filter((o) => o !== b);
    this.lines = this.lines.filter((l) => l.a !== b.id && l.b !== b.id);
    this.money += Math.floor(BUILD[b.kind].cost * 0.4);
    this.msg(BUILD[b.kind].name + ' zbourána (+' + Math.floor(BUILD[b.kind].cost * 0.4) + ')');
    return true;
  };

  Sim.prototype.connect = function (b1, b2) {
    if (b1 === b2) return null;
    if (this.lines.some((l) => (l.a === b1.id && l.b === b2.id) || (l.a === b2.id && l.b === b1.id))) {
      this.msg('Už propojeno', 'warn'); return null;
    }
    const dist = Math.hypot(b1.x - b2.x, b1.y - b2.y);
    if (dist > 24) { this.msg('Příliš daleko (max 24 dlaždic)', 'warn'); return null; }
    const cost = Math.ceil(dist * BUILD.line.cost);
    if (this.money < cost) { this.msg('Nedostatek peněz', 'warn'); return null; }
    this.money -= cost;
    const l = { id: this.nextId++, a: b1.id, b: b2.id, flow: 0, load: 0, len: dist };
    this.lines.push(l);
    this.msg('Vedení nataženo (−' + cost + ')');
    return l;
  };

  Sim.prototype.removeLine = function (line) {
    this.lines = this.lines.filter((l) => l !== line);
    this.msg('Vedení odstraněno');
  };

  /* okamžitý výkon elektrárny */
  Sim.prototype._genOf = function (b, sun, wind) {
    const m = this.map;
    switch (b.kind) {
      case 'hydro': {
        const f = m.flow[m.idx(b.x, b.y)];
        return Math.min(80, 6 + f * 6);
      }
      case 'dam': {
        const f = m.flow[m.idx(b.x, b.y)];
        return Math.min(150, 30 + f * 7 + (b.reservoir || 0) * 3);
      }
      case 'coal': return 90;
      case 'solar': return 35 * sun;
      case 'wind': {
        const TT = T();
        const t = m.type[m.idx(b.x, b.y)];
        const bonus = (t === TT.HILL || t === TT.MOUNTAIN) ? 1.35 : 1;
        return Math.max(0, 30 * wind * bonus);
      }
      default: return 0;
    }
  };

  /* Poptávka města v MW – roste s populací, přes den vyšší */
  Sim.prototype._cityDemand = function (c, dayPhase) {
    const base = c.pop * 1.15;
    const curve = 0.6 + 0.4 * Math.max(0, Math.sin((dayPhase - 0.2) * Math.PI * 2) * 0.5 + 0.5);
    return base * curve;
  };

  /* hlavní tick simulace – dt v herních sekundách */
  Sim.prototype.tick = function (dt) {
    this.time += dt;
    const dayPhase = (this.time % this.dayLen) / this.dayLen; // 0..1, 0 = ráno
    const sun = Math.max(0, Math.sin(dayPhase * Math.PI * 2 - Math.PI * 0.1));
    const wind = 0.35 + 0.65 * EG.rng.fbm(this.time * 0.01 + this._noiseT, 3.7, 42, 3);
    this.sun = sun; this.wind = wind; this.dayPhase = dayPhase;

    // --- sestavit uzly ---
    const nodes = this.buildings;
    const id2i = new Map();
    nodes.forEach((b, i) => id2i.set(b.id, i));
    const n = nodes.length;
    const inj = new Float64Array(n);   // MW injekce (+výroba / −spotřeba)
    const gen = new Float64Array(n);
    const wantGen = new Float64Array(n);

    for (let i = 0; i < n; i++) {
      wantGen[i] = this._genOf(nodes[i], sun, wind);
      nodes[i].gen = wantGen[i];
    }

    // města -> nejbližší rozvodna v dosahu
    const subs = nodes.map((b, i) => (b.kind === 'sub' ? i : -1)).filter((i) => i >= 0);
    const cityAssign = [];
    let totalDemand = 0;
    for (const c of this.map.cities) {
      const d = this._cityDemand(c, dayPhase);
      totalDemand += d;
      let best = -1, bestD = Infinity;
      for (const si of subs) {
        const b = nodes[si];
        const dist = Math.hypot(b.x - c.x, b.y - c.y);
        if (dist <= SUB_RANGE && dist < bestD) { bestD = dist; best = si; }
      }
      cityAssign.push({ city: c, sub: best, demand: d, served: 0 });
    }

    // --- komponenty souvislosti přes vedení ---
    const adj = Array.from({ length: n }, () => []);
    for (const l of this.lines) {
      const a = id2i.get(l.a), b = id2i.get(l.b);
      if (a === undefined || b === undefined) continue;
      adj[a].push({ to: b, line: l, sign: 1 });
      adj[b].push({ to: a, line: l, sign: -1 });
    }
    const comp = new Int32Array(n).fill(-1);
    let nc = 0;
    for (let i = 0; i < n; i++) {
      if (comp[i] >= 0) continue;
      const stack = [i]; comp[i] = nc;
      while (stack.length) {
        const u = stack.pop();
        for (const e of adj[u]) if (comp[e.to] < 0) { comp[e.to] = nc; stack.push(e.to); }
      }
      nc++;
    }

    // --- na komponentu: nabídka vs. poptávka ---
    const compGen = new Float64Array(nc);
    const compDem = new Float64Array(nc);
    for (let i = 0; i < n; i++) compGen[comp[i]] += wantGen[i];
    for (const ca of cityAssign) {
      if (ca.sub >= 0) compDem[comp[ca.sub]] += ca.demand;
    }

    let produced = 0, delivered = 0;
    const demandAt = new Float64Array(n);
    for (const ca of cityAssign) {
      if (ca.sub < 0) continue;
      const c = comp[ca.sub];
      const ratio = compDem[c] > 0 ? Math.min(1, compGen[c] / compDem[c]) : 0;
      ca.served = ca.demand * ratio;
      demandAt[ca.sub] += ca.served;
      delivered += ca.served;
    }
    for (let i = 0; i < n; i++) {
      const c = comp[i];
      // elektrárny jedou jen tak, kolik je odběr (přebytek se zahodí)
      const useRatio = compGen[c] > 0 ? Math.min(1, compDem[c] / compGen[c]) : 0;
      gen[i] = wantGen[i] * useRatio;
      produced += gen[i];
      inj[i] = gen[i] - demandAt[i];
      nodes[i].out = gen[i];
    }

    // --- DC power flow: L·θ = P, sdružené gradienty (CG) ---
    // Injekce jsou v každé komponentě bilancované, takže je systém řešitelný;
    // CG na Laplacián konverguje řádově rychleji než Gauss–Seidel.
    const theta = this._theta && this._theta.length === n ? this._theta : new Float64Array(n);
    this._theta = theta;
    const lineW = (l) => 1 / Math.max(1, l.len * 0.25); // delší vedení = větší „odpor"
    const applyL = (v, out) => {
      for (let u = 0; u < n; u++) {
        let s = 0;
        for (const e of adj[u]) s += lineW(e.line) * (v[u] - v[e.to]);
        out[u] = s;
      }
    };
    {
      const r = new Float64Array(n), p = new Float64Array(n), Ap = new Float64Array(n);
      applyL(theta, Ap);
      for (let u = 0; u < n; u++) { r[u] = inj[u] - Ap[u]; p[u] = r[u]; }
      let rs = 0;
      for (let u = 0; u < n; u++) rs += r[u] * r[u];
      const maxIt = Math.min(400, 2 * n + 20);
      for (let it = 0; it < maxIt && rs > 1e-8; it++) {
        applyL(p, Ap);
        let pAp = 0;
        for (let u = 0; u < n; u++) pAp += p[u] * Ap[u];
        if (pAp <= 1e-12) break;
        const alpha = rs / pAp;
        let rs2 = 0;
        for (let u = 0; u < n; u++) {
          theta[u] += alpha * p[u];
          r[u] -= alpha * Ap[u];
          rs2 += r[u] * r[u];
        }
        const beta = rs2 / rs;
        rs = rs2;
        for (let u = 0; u < n; u++) p[u] = r[u] + beta * p[u];
      }
    }

    // toky hranami + přetížení
    let overloaded = 0;
    for (const l of this.lines) {
      const a = id2i.get(l.a), b = id2i.get(l.b);
      const w = 1 / Math.max(1, l.len * 0.25);
      l.flow = (theta[a] - theta[b]) * w;
      l.load = Math.abs(l.flow) / LINE_CAP;
      if (l.load > 1) overloaded++;
    }
    if (overloaded > 0 && Math.floor(this.time) % 5 === 0 && this._lastOverloadWarn !== Math.floor(this.time)) {
      this._lastOverloadWarn = Math.floor(this.time);
      this.msg('Vedení přetíženo! Postav paralelní trasu.', 'warn');
    }

    // --- města: spokojenost, růst, výpadky ---
    for (const ca of cityAssign) {
      const c = ca.city;
      const ratio = ca.demand > 0 ? ca.served / ca.demand : 0;
      c.powered = ratio;
      if (ratio > 0.95) {
        c.satisfaction = Math.min(1, c.satisfaction + dt * 0.02);
        c.unhappyTime = 0;
        if (Math.random() < dt * 0.02 && c.pop < 60) {
          c.pop += 1;
        }
      } else {
        c.satisfaction = Math.max(0, c.satisfaction - dt * (0.05 + 0.1 * (1 - ratio)));
        c.unhappyTime += dt;
        if (c.unhappyTime > 20 && Math.random() < dt * 0.03 && c.pop > 4) {
          c.pop -= 1;
          this.blackouts++;
        }
      }
    }

    // --- ekonomika ---
    let upkeep = 0;
    for (const b of this.buildings) upkeep += BUILD[b.kind].upkeep;
    for (const l of this.lines) upkeep += l.len * BUILD.line.upkeep;
    const income = delivered * PRICE_PER_MWH;
    this.money += (income - upkeep * 0.01) * dt;
    this.score += delivered * dt * 0.01;

    this.stats = {
      produced, delivered, demand: totalDemand,
      overloaded,
      unpowered: cityAssign.filter((ca) => (ca.demand > 0 && (ca.served / ca.demand) < 0.5)).length,
      income: income - upkeep * 0.01,
    };
    this.cityAssign = cityAssign;
  };

  EG.Sim = Sim;
  EG.BUILD = BUILD;
  EG.LINE_CAP = LINE_CAP;
  EG.SUB_RANGE = SUB_RANGE;
})();
