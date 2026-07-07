/* Procedurální sprite atlas – vše se kreslí do canvasu při startu,
   žádné externí obrázky. Buňka 64×96 px, kosočtverec dlaždice dole
   (střed podstavy = bod [32, 80]), nad ním prostor pro vysoké objekty. */
(function () {
  'use strict';
  const EG = window.EG;

  const CELL_W = 64, CELL_H = 96, COLS = 8, ROWS = 4;
  const HW = 32, HH = 16;          // poloosy kosočtverce
  const AX = 32, AY = 80;          // kotva (střed dlaždice) uvnitř buňky

  const S = {
    WATER: 0, SAND: 1, GRASS: 2, FOREST: 3, HILL: 4, MOUNTAIN: 5, RIVER: 6, RESERVOIR: 7,
    HOUSE: 8, HOUSE2: 9, CENTER: 10, HYDRO: 11, DAM: 12, COAL: 13, SOLAR: 14, WIND: 15,
    SUBST: 16, SEL: 17, BAD: 18, CITYRING: 19,
  };

  function diamond(ctx, cx, cy, hw, hh) {
    ctx.beginPath();
    ctx.moveTo(cx, cy - hh);
    ctx.lineTo(cx + hw, cy);
    ctx.lineTo(cx, cy + hh);
    ctx.lineTo(cx - hw, cy);
    ctx.closePath();
  }

  function tile(ctx, color, edgeLight, edgeDark) {
    diamond(ctx, AX, AY, HW, HH);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = edgeDark;
    ctx.beginPath();
    ctx.moveTo(AX + HW, AY); ctx.lineTo(AX, AY + HH); ctx.lineTo(AX - HW, AY);
    ctx.stroke();
    ctx.strokeStyle = edgeLight;
    ctx.beginPath();
    ctx.moveTo(AX - HW, AY); ctx.lineTo(AX, AY - HH); ctx.lineTo(AX + HW, AY);
    ctx.stroke();
  }

  // vyvýšený blok (kopec, hora)
  function raised(ctx, h, topColor, leftColor, rightColor) {
    ctx.fillStyle = leftColor;
    ctx.beginPath();
    ctx.moveTo(AX - HW, AY); ctx.lineTo(AX, AY + HH);
    ctx.lineTo(AX, AY + HH - h); ctx.lineTo(AX - HW, AY - h);
    ctx.closePath(); ctx.fill();
    ctx.fillStyle = rightColor;
    ctx.beginPath();
    ctx.moveTo(AX + HW, AY); ctx.lineTo(AX, AY + HH);
    ctx.lineTo(AX, AY + HH - h); ctx.lineTo(AX + HW, AY - h);
    ctx.closePath(); ctx.fill();
    diamond(ctx, AX, AY - h, HW, HH);
    ctx.fillStyle = topColor; ctx.fill();
  }

  // kvádr pro budovy: šířka w, hloubka d (v iso), výška h, střed na kotvě
  function box(ctx, w, d, h, top, left, right, dy) {
    dy = dy || 0;
    const cy = AY + dy;
    ctx.fillStyle = left;
    ctx.beginPath();
    ctx.moveTo(AX - w, cy); ctx.lineTo(AX, cy + d);
    ctx.lineTo(AX, cy + d - h); ctx.lineTo(AX - w, cy - h);
    ctx.closePath(); ctx.fill();
    ctx.fillStyle = right;
    ctx.beginPath();
    ctx.moveTo(AX + w, cy); ctx.lineTo(AX, cy + d);
    ctx.lineTo(AX, cy + d - h); ctx.lineTo(AX + w, cy - h);
    ctx.closePath(); ctx.fill();
    ctx.fillStyle = top;
    ctx.beginPath();
    ctx.moveTo(AX, cy - d - h); ctx.lineTo(AX + w, cy - h);
    ctx.lineTo(AX, cy + d - h); ctx.lineTo(AX - w, cy - h);
    ctx.closePath(); ctx.fill();
  }

  function tree(ctx, x, y, s) {
    ctx.fillStyle = '#5a3d20';
    ctx.fillRect(x - 1, y - 3 * s, 2, 3 * s);
    ctx.fillStyle = '#2f6b33';
    for (let i = 0; i < 3; i++) {
      const w = (6 - i * 1.5) * s, ty = y - 3 * s - i * 4 * s;
      ctx.beginPath();
      ctx.moveTo(x, ty - 6 * s); ctx.lineTo(x + w, ty); ctx.lineTo(x - w, ty);
      ctx.closePath(); ctx.fill();
    }
  }

  function build() {
    const cv = document.createElement('canvas');
    cv.width = COLS * CELL_W; cv.height = ROWS * CELL_H;
    const g = cv.getContext('2d');

    function at(i, fn) {
      g.save();
      g.translate((i % COLS) * CELL_W, Math.floor(i / COLS) * CELL_H);
      fn(g);
      g.restore();
    }

    at(S.WATER, (c) => {
      tile(c, '#2e6fa8', '#4b8fc4', '#22557f');
      c.strokeStyle = 'rgba(255,255,255,0.35)'; c.lineWidth = 1;
      c.beginPath(); c.moveTo(AX - 14, AY - 2); c.quadraticCurveTo(AX - 7, AY - 6, AX, AY - 2); c.stroke();
      c.beginPath(); c.moveTo(AX + 2, AY + 4); c.quadraticCurveTo(AX + 9, AY, AX + 16, AY + 4); c.stroke();
    });
    at(S.SAND, (c) => tile(c, '#d8c98d', '#e8dcaa', '#b3a56e'));
    at(S.GRASS, (c) => {
      tile(c, '#7cb35b', '#93c671', '#5f9143');
      c.fillStyle = 'rgba(255,255,255,0.12)';
      c.fillRect(AX - 10, AY - 4, 2, 1); c.fillRect(AX + 6, AY + 2, 2, 1);
    });
    at(S.FOREST, (c) => {
      tile(c, '#69a04c', '#7fb562', '#4e7d38');
      tree(c, AX - 10, AY + 2, 1); tree(c, AX + 9, AY - 1, 0.9); tree(c, AX - 1, AY + 7, 1.1);
    });
    at(S.HILL, (c) => raised(c, 8, '#8fae64', '#6d8c4b', '#5a7540'));
    at(S.MOUNTAIN, (c) => {
      raised(c, 14, '#8e8d86', '#6f6e69', '#5c5b57');
      c.fillStyle = '#7b7a74';
      c.beginPath(); c.moveTo(AX, AY - 44); c.lineTo(AX + 15, AY - 16); c.lineTo(AX - 15, AY - 16); c.closePath(); c.fill();
      c.fillStyle = '#e9edf2';
      c.beginPath(); c.moveTo(AX, AY - 44); c.lineTo(AX + 6, AY - 32); c.lineTo(AX - 6, AY - 32); c.closePath(); c.fill();
    });
    at(S.RIVER, (c) => {
      tile(c, '#3f86c0', '#63a5d6', '#2e6591');
      c.strokeStyle = 'rgba(255,255,255,0.5)'; c.lineWidth = 1.2;
      c.beginPath(); c.moveTo(AX - 18, AY + 1); c.quadraticCurveTo(AX - 6, AY - 5, AX + 4, AY);
      c.quadraticCurveTo(AX + 12, AY + 4, AX + 18, AY); c.stroke();
    });
    at(S.RESERVOIR, (c) => {
      tile(c, '#33739f', '#5493bd', '#265877');
      c.strokeStyle = 'rgba(255,255,255,0.3)'; c.lineWidth = 1;
      c.beginPath(); c.moveTo(AX - 12, AY); c.quadraticCurveTo(AX, AY - 5, AX + 12, AY); c.stroke();
    });

    at(S.HOUSE, (c) => {
      tile(c, '#9aa77f', '#aeb992', '#7d8a66');
      box(c, 9, 5, 9, '#c2503e', '#e8e2d2', '#c9c2b0');
    });
    at(S.HOUSE2, (c) => {
      tile(c, '#9aa77f', '#aeb992', '#7d8a66');
      box(c, 12, 6, 14, '#b0483a', '#e3dccb', '#c2baa7');
      box(c, 6, 3, 20, '#8a4a3e', '#d8d2c2', '#b8b09c', -4);
    });
    at(S.CENTER, (c) => {
      tile(c, '#8f9db2', '#a5b2c4', '#75839a');
      box(c, 13, 7, 26, '#6a7f9c', '#dfe6ef', '#b9c4d4');
      c.fillStyle = '#3f5977';
      for (let r = 0; r < 4; r++) for (let q = 0; q < 2; q++) {
        c.fillRect(AX - 10 + q * 5, AY - 22 + r * 5, 3, 3);
        c.fillRect(AX + 4 + q * 5, AY - 22 + r * 5, 3, 3);
      }
    });

    at(S.HYDRO, (c) => {
      tile(c, '#3f86c0', '#63a5d6', '#2e6591');
      box(c, 12, 6, 14, '#7899ad', '#dfe9ee', '#a9c0cd');
      c.fillStyle = '#33546b';
      c.beginPath(); c.arc(AX - 6, AY - 6, 6, 0, Math.PI * 2); c.fill();
      c.strokeStyle = '#cfe4ef'; c.lineWidth = 2;
      c.beginPath(); c.arc(AX - 6, AY - 6, 6, 0, Math.PI * 2); c.stroke();
      c.beginPath(); c.moveTo(AX - 6, AY - 12); c.lineTo(AX - 6, AY); c.moveTo(AX - 12, AY - 6); c.lineTo(AX, AY - 6); c.stroke();
      c.fillStyle = 'rgba(255,255,255,0.75)';
      c.fillRect(AX + 4, AY + 4, 10, 3);
    });
    at(S.DAM, (c) => {
      tile(c, '#33739f', '#5493bd', '#265877');
      c.fillStyle = '#9aa2ab';
      c.beginPath();
      c.moveTo(AX - HW + 4, AY - 2); c.quadraticCurveTo(AX, AY - 26, AX + HW - 4, AY - 2);
      c.lineTo(AX + HW - 4, AY + 6); c.quadraticCurveTo(AX, AY - 16, AX - HW + 4, AY + 6);
      c.closePath(); c.fill();
      c.fillStyle = '#b8bfc7';
      c.beginPath();
      c.moveTo(AX - HW + 4, AY - 2); c.quadraticCurveTo(AX, AY - 26, AX + HW - 4, AY - 2);
      c.lineTo(AX + HW - 4, AY + 1); c.quadraticCurveTo(AX, AY - 22, AX - HW + 4, AY + 1);
      c.closePath(); c.fill();
      c.fillStyle = 'rgba(255,255,255,0.8)';
      c.fillRect(AX - 4, AY + 2, 3, 9); c.fillRect(AX + 3, AY + 3, 3, 8);
    });
    at(S.COAL, (c) => {
      tile(c, '#8a8a80', '#a0a095', '#6e6e66');
      box(c, 13, 7, 13, '#54524e', '#8c8a84', '#6b6963');
      c.fillStyle = '#5f5d58'; c.fillRect(AX + 4, AY - 40, 7, 28);
      c.fillStyle = '#78766f'; c.fillRect(AX + 4, AY - 40, 3, 28);
      c.fillStyle = '#c2483a'; c.fillRect(AX + 4, AY - 40, 7, 3);
      c.fillStyle = 'rgba(220,220,220,0.8)';
      c.beginPath(); c.arc(AX + 8, AY - 46, 5, 0, Math.PI * 2); c.fill();
      c.beginPath(); c.arc(AX + 13, AY - 53, 7, 0, Math.PI * 2); c.fill();
    });
    at(S.SOLAR, (c) => {
      tile(c, '#9aa77f', '#aeb992', '#7d8a66');
      for (const [ox, oy] of [[-11, -2], [7, -6], [-2, 5]]) {
        c.fillStyle = '#1d3a5f';
        c.beginPath();
        c.moveTo(AX + ox - 9, AY + oy); c.lineTo(AX + ox + 3, AY + oy - 6);
        c.lineTo(AX + ox + 9, AY + oy - 3); c.lineTo(AX + ox - 3, AY + oy + 3);
        c.closePath(); c.fill();
        c.strokeStyle = '#5b87b8'; c.lineWidth = 0.8; c.stroke();
      }
    });
    at(S.WIND, (c) => {
      tile(c, '#9db374', '#b1c489', '#7f945c');
      c.strokeStyle = '#e8ecef'; c.lineWidth = 3;
      c.beginPath(); c.moveTo(AX, AY - 2); c.lineTo(AX, AY - 46); c.stroke();
      c.fillStyle = '#dfe4e8';
      for (let b = 0; b < 3; b++) {
        const a = b * (Math.PI * 2 / 3) + 0.5;
        c.beginPath();
        c.moveTo(AX, AY - 46);
        c.lineTo(AX + Math.cos(a) * 18 - Math.sin(a) * 2, AY - 46 + Math.sin(a) * 18 + Math.cos(a) * 2);
        c.lineTo(AX + Math.cos(a) * 18 + Math.sin(a) * 2, AY - 46 + Math.sin(a) * 18 - Math.cos(a) * 2);
        c.closePath(); c.fill();
      }
      c.fillStyle = '#c74a3c';
      c.beginPath(); c.arc(AX, AY - 46, 2.5, 0, Math.PI * 2); c.fill();
    });
    at(S.SUBST, (c) => {
      tile(c, '#b9b3a4', '#cbc6b8', '#968f80');
      box(c, 8, 4, 7, '#7d838c', '#c8cdd4', '#a3a9b2');
      c.strokeStyle = '#4a4f57'; c.lineWidth = 1.5;
      c.beginPath(); c.moveTo(AX - 5, AY - 7); c.lineTo(AX - 5, AY - 20); c.stroke();
      c.beginPath(); c.moveTo(AX + 5, AY - 7); c.lineTo(AX + 5, AY - 16); c.stroke();
      c.fillStyle = '#e8c84a';
      c.beginPath(); c.arc(AX - 5, AY - 21, 2, 0, Math.PI * 2); c.fill();
      c.beginPath(); c.arc(AX + 5, AY - 17, 2, 0, Math.PI * 2); c.fill();
    });

    at(S.SEL, (c) => {
      diamond(c, AX, AY, HW - 1, HH - 0.5);
      c.fillStyle = 'rgba(255,230,80,0.28)'; c.fill();
      c.strokeStyle = 'rgba(255,230,80,0.95)'; c.lineWidth = 2; c.stroke();
    });
    at(S.BAD, (c) => {
      diamond(c, AX, AY, HW - 1, HH - 0.5);
      c.fillStyle = 'rgba(230,60,50,0.3)'; c.fill();
      c.strokeStyle = 'rgba(230,60,50,0.95)'; c.lineWidth = 2; c.stroke();
    });
    at(S.CITYRING, (c) => {
      diamond(c, AX, AY, HW - 1, HH - 0.5);
      c.strokeStyle = 'rgba(120,200,255,0.9)'; c.lineWidth = 2;
      c.setLineDash([5, 4]); c.stroke();
    });

    return cv;
  }

  EG.atlas = { build, S, CELL_W, CELL_H, COLS, ROWS, AX, AY };
})();
