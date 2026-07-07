/* Procedurální generátor mapy: terén, řeky s průtokem, města */
(function () {
  'use strict';
  const EG = window.EG;
  const { fbm, hash2, mulberry32 } = EG.rng;

  // typy terénu
  const T = {
    WATER: 0,   // jezero / moře / přehradní nádrž
    SAND: 1,    // břeh
    GRASS: 2,
    FOREST: 3,
    HILL: 4,
    MOUNTAIN: 5,
    RIVER: 6,
  };

  const DIRS = [[1, 0], [-1, 0], [0, 1], [0, -1]];

  function generate(size, seed) {
    const rand = mulberry32(seed);
    const N = size;
    const type = new Uint8Array(N * N);
    const elev = new Float32Array(N * N);
    const flow = new Float32Array(N * N);      // průtok řeky (0 = není řeka)
    const flowDir = new Int8Array(N * N).fill(-1); // index do DIRS, kam řeka teče
    const idx = (x, y) => y * N + x;

    // --- výšková mapa + vlhkost ---
    const cx = N / 2, cy = N / 2;
    for (let y = 0; y < N; y++) {
      for (let x = 0; x < N; x++) {
        let e = fbm(x / 42, y / 42, seed, 5);
        // mírné snížení k okrajům, ať vznikají jezera u krajů
        const dx = (x - cx) / cx, dy = (y - cy) / cy;
        const edge = Math.max(Math.abs(dx), Math.abs(dy));
        e -= Math.max(0, edge - 0.75) * 0.9;
        elev[idx(x, y)] = e;
      }
    }

    for (let y = 0; y < N; y++) {
      for (let x = 0; x < N; x++) {
        const i = idx(x, y);
        const e = elev[i];
        const m = fbm(x / 23 + 500, y / 23 + 500, seed + 7777, 4);
        if (e < 0.335) type[i] = T.WATER;
        else if (e < 0.60) type[i] = m > 0.55 ? T.FOREST : T.GRASS;
        else if (e < 0.70) type[i] = T.HILL;
        else type[i] = T.MOUNTAIN;
      }
    }

    // --- řeky: prameny v horách, stékají po spádu do vody / za okraj ---
    const springs = [];
    for (let tries = 0; tries < 4000 && springs.length < 14; tries++) {
      const x = 4 + Math.floor(rand() * (N - 8));
      const y = 4 + Math.floor(rand() * (N - 8));
      if (elev[idx(x, y)] > 0.62) {
        let ok = true;
        for (const s of springs) {
          if (Math.abs(s[0] - x) + Math.abs(s[1] - y) < 26) { ok = false; break; }
        }
        if (ok) springs.push([x, y]);
      }
    }

    for (const [sx, sy] of springs) {
      let x = sx, y = sy;
      let f = 3 + rand() * 4; // počáteční průtok (MW ekvivalent na jednotku)
      const visited = new Set();
      for (let step = 0; step < N * 3; step++) {
        const i = idx(x, y);
        if (type[i] === T.WATER) break;                 // doteklo do jezera
        if (visited.has(i)) break;
        visited.add(i);
        if (type[i] === T.RIVER) {                      // soutok – posílí existující tok
          let px = x, py = y;
          while (px >= 0 && px < N && py >= 0 && py < N) {
            const j = idx(px, py);
            if (type[j] !== T.RIVER) break;
            flow[j] += f * 0.8;
            const d = flowDir[j];
            if (d < 0) break;
            px += DIRS[d][0]; py += DIRS[d][1];
          }
          break;
        }
        type[i] = T.RIVER;
        flow[i] = f;
        f += 0.12; // přítoky po cestě
        // vyber souseda s nejnižší elevací (s trochou šumu, ať meandruje)
        let best = -1, bestE = Infinity;
        for (let d = 0; d < 4; d++) {
          const nx = x + DIRS[d][0], ny = y + DIRS[d][1];
          if (nx < 0 || ny < 0 || nx >= N || ny >= N) { best = d; bestE = -Infinity; break; }
          const j = idx(nx, ny);
          if (visited.has(j)) continue;
          const e = elev[j] + (hash2(nx, ny, seed + step) - 0.5) * 0.045;
          if (e < bestE) { bestE = e; best = d; }
        }
        if (best < 0) break;
        flowDir[i] = best;
        const nx = x + DIRS[best][0], ny = y + DIRS[best][1];
        if (nx < 0 || ny < 0 || nx >= N || ny >= N) break; // odtéká z mapy
        // eroze – zajistí, že řeka „neteče do kopce"
        elev[idx(nx, ny)] = Math.min(elev[idx(nx, ny)], elev[i] - 0.001);
        x = nx; y = ny;
      }
    }

    // písek kolem vody
    for (let y = 1; y < N - 1; y++) {
      for (let x = 1; x < N - 1; x++) {
        const i = idx(x, y);
        if (type[i] === T.GRASS || type[i] === T.FOREST) {
          for (let d = 0; d < 4; d++) {
            if (type[idx(x + DIRS[d][0], y + DIRS[d][1])] === T.WATER) { type[i] = T.SAND; break; }
          }
        }
      }
    }

    // --- města: na rovině, daleko od sebe, radši blízko řeky ---
    const cities = [];
    const wanted = 11;
    let attempts = 0;
    while (cities.length < wanted && attempts++ < 20000) {
      const x = 8 + Math.floor(rand() * (N - 16));
      const y = 8 + Math.floor(rand() * (N - 16));
      const i = idx(x, y);
      if (type[i] !== T.GRASS && type[i] !== T.FOREST) continue;
      let minD = Infinity;
      for (const c of cities) {
        const d = Math.abs(c.x - x) + Math.abs(c.y - y);
        if (d < minD) minD = d;
      }
      if (minD < 30) continue;
      // bonus šance u řeky
      let nearRiver = false;
      for (let ry = -4; ry <= 4 && !nearRiver; ry++)
        for (let rx = -4; rx <= 4; rx++) {
          const nx = x + rx, ny = y + ry;
          if (nx >= 0 && ny >= 0 && nx < N && ny < N && type[idx(nx, ny)] === T.RIVER) { nearRiver = true; break; }
        }
      if (!nearRiver && rand() < 0.55) continue;
      const pop = 6 + Math.floor(rand() * 22); // tisíce obyvatel
      cities.push({
        x, y, pop, name: CITY_NAMES[cities.length % CITY_NAMES.length],
        satisfaction: 1, unhappyTime: 0, houses: [],
      });
      // zabrat okolní dlaždice pro zástavbu (jen vizuál + zákaz stavění)
      const c = cities[cities.length - 1];
      const r = 2;
      for (let ry = -r; ry <= r; ry++)
        for (let rx = -r; rx <= r; rx++) {
          const nx = x + rx, ny = y + ry;
          if (nx < 0 || ny < 0 || nx >= N || ny >= N) continue;
          const j = idx(nx, ny);
          if ((type[j] === T.GRASS || type[j] === T.FOREST || type[j] === T.SAND) &&
              Math.abs(rx) + Math.abs(ry) <= r && hash2(nx, ny, seed + 99) < 0.75) {
            c.houses.push([nx, ny]);
          }
        }
    }

    return { size: N, type, elev, flow, flowDir, cities, seed, T, idx };
  }

  const CITY_NAMES = [
    'Vltavín', 'Doubrava', 'Kamenice', 'Lipno', 'Bystřice', 'Orlík',
    'Střekov', 'Jeseník', 'Hluboká', 'Rožmberk', 'Světlá', 'Vranov',
    'Nechranice', 'Dalešice',
  ];

  EG.T = T;
  EG.DIRS = DIRS;
  EG.generateMap = generate;
})();
