/* Deterministický RNG + šumové funkce pro generování mapy */
(function () {
  'use strict';
  const EG = (window.EG = window.EG || {});

  // mulberry32 – rychlý seedovaný generátor
  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // hash mřížkového bodu -> [0,1)
  function hash2(x, y, seed) {
    let h = (x * 374761393 + y * 668265263 + seed * 974711) | 0;
    h = Math.imul(h ^ (h >>> 13), 1274126177);
    h ^= h >>> 16;
    return (h >>> 0) / 4294967296;
  }

  function smooth(t) { return t * t * (3 - 2 * t); }

  // hodnotový šum s bilineární interpolací
  function valueNoise(x, y, seed) {
    const xi = Math.floor(x), yi = Math.floor(y);
    const xf = x - xi, yf = y - yi;
    const a = hash2(xi, yi, seed);
    const b = hash2(xi + 1, yi, seed);
    const c = hash2(xi, yi + 1, seed);
    const d = hash2(xi + 1, yi + 1, seed);
    const u = smooth(xf), v = smooth(yf);
    return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
  }

  // fraktální šum (fBm)
  function fbm(x, y, seed, octaves, lac, gain) {
    lac = lac || 2.0; gain = gain || 0.5;
    let amp = 1, freq = 1, sum = 0, norm = 0;
    for (let i = 0; i < octaves; i++) {
      sum += amp * valueNoise(x * freq, y * freq, seed + i * 131);
      norm += amp;
      amp *= gain; freq *= lac;
    }
    return sum / norm;
  }

  EG.rng = { mulberry32, hash2, valueNoise, fbm };
})();
