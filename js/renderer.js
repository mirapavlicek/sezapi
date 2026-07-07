/* WebGL2 izometrický renderer.
   Vše se kreslí na GPU instancovaně:
   - statický buffer terénu (nahraje se jednou, ~desítky tisíc instancí)
   - dynamický buffer budov/overlay (pár set instancí za snímek)
   - elektrická vedení jako instancované segmenty s animovaným tokem */
(function () {
  'use strict';
  const EG = window.EG;
  const A = EG.atlas;

  const HW = 32, HH = 16; // iso poloosy v pixelech

  const SPRITE_VS = `#version 300 es
  layout(location=0) in vec2 aCorner;      // 0..1 roh quadu
  layout(location=1) in vec3 aPos;         // world px x, y, depth
  layout(location=2) in float aSprite;     // index do atlasu
  layout(location=3) in vec4 aTint;
  uniform vec2 uView;                      // velikost viewportu v px
  uniform vec2 uCam;                       // pozice kamery ve world px
  uniform float uZoom;
  uniform vec2 uCell;                      // velikost buňky atlasu v px
  uniform vec2 uAtlasGrid;                 // sloupce, řádky
  out vec2 vUV;
  out vec4 vTint;
  void main() {
    vec2 anchor = vec2(${A.AX}.0, ${A.AY}.0);
    vec2 local = aCorner * uCell - anchor;
    vec2 world = aPos.xy + local;
    vec2 screen = (world - uCam) * uZoom + uView * 0.5;
    vec2 clip = screen / uView * 2.0 - 1.0;
    gl_Position = vec4(clip.x, -clip.y, aPos.z, 1.0);
    float col = mod(aSprite, uAtlasGrid.x);
    float row = floor(aSprite / uAtlasGrid.x);
    vUV = (vec2(col, row) + aCorner) / uAtlasGrid;
    vTint = aTint;
  }`;

  const SPRITE_FS = `#version 300 es
  precision mediump float;
  in vec2 vUV;
  in vec4 vTint;
  uniform sampler2D uTex;
  out vec4 outColor;
  void main() {
    vec4 c = texture(uTex, vUV);
    if (c.a < 0.01) discard;
    outColor = c * vTint;
  }`;

  // segment vedení: quad natažený mezi dva body, s animovanými „paketami" energie
  const LINE_VS = `#version 300 es
  layout(location=0) in vec2 aCorner;      // x: 0..1 podél, y: -1..1 napříč
  layout(location=1) in vec4 aSeg;         // x1,y1,x2,y2 world px
  layout(location=2) in vec4 aColor;
  layout(location=3) in vec2 aInfo;        // load 0..1, flowDir (-1/0/1)
  uniform vec2 uView;
  uniform vec2 uCam;
  uniform float uZoom;
  out vec4 vColor;
  out vec2 vInfo;
  out float vDist;                          // px podél segmentu
  out float vAcross;
  void main() {
    vec2 p1 = aSeg.xy, p2 = aSeg.zw;
    vec2 dir = normalize(p2 - p1);
    vec2 nrm = vec2(-dir.y, dir.x);
    float len = length(p2 - p1);
    float halfW = 2.2 / uZoom + 1.2;
    vec2 world = mix(p1, p2, aCorner.x) + nrm * aCorner.y * halfW;
    vec2 screen = (world - uCam) * uZoom + uView * 0.5;
    vec2 clip = screen / uView * 2.0 - 1.0;
    gl_Position = vec4(clip.x, -clip.y, 0.0, 1.0);
    vColor = aColor;
    vInfo = aInfo;
    vDist = aCorner.x * len;
    vAcross = aCorner.y;
  }`;

  const LINE_FS = `#version 300 es
  precision mediump float;
  in vec4 vColor;
  in vec2 vInfo;
  in float vDist;
  in float vAcross;
  uniform float uTime;
  out vec4 outColor;
  void main() {
    float core = 1.0 - smoothstep(0.35, 1.0, abs(vAcross));
    vec4 c = vColor;
    // animované pakety energie ve směru toku
    if (vInfo.y != 0.0 && vInfo.x > 0.001) {
      float speed = 46.0 + 90.0 * vInfo.x;
      float ph = fract((vDist * vInfo.y - uTime * speed * vInfo.y) / 34.0);
      float pulse = smoothstep(0.22, 0.0, abs(ph - 0.5) - 0.08);
      c.rgb += pulse * vec3(0.9, 0.9, 0.5) * (0.35 + vInfo.x);
    }
    c.a *= (0.55 + 0.45 * core);
    outColor = c;
  }`;

  function compile(gl, type, src) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      throw new Error('Shader: ' + gl.getShaderInfoLog(s));
    }
    return s;
  }

  function program(gl, vs, fs) {
    const p = gl.createProgram();
    gl.attachShader(p, compile(gl, gl.VERTEX_SHADER, vs));
    gl.attachShader(p, compile(gl, gl.FRAGMENT_SHADER, fs));
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
      throw new Error('Program: ' + gl.getProgramInfoLog(p));
    }
    return p;
  }

  function isoX(x, y) { return (x - y) * HW; }
  function isoY(x, y) { return (x + y) * HH; }

  function Renderer(canvas) {
    const gl = canvas.getContext('webgl2', { antialias: true, alpha: false });
    if (!gl) throw new Error('WebGL2 není k dispozici');
    this.gl = gl;
    this.canvas = canvas;
    this.cam = { x: 0, y: 0, zoom: 1 };

    // atlas -> textura
    const atlasCanvas = A.build();
    this.atlasCanvas = atlasCanvas;
    const tex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, atlasCanvas);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.generateMipmap(gl.TEXTURE_2D);
    this.tex = tex;

    this.spriteProg = program(gl, SPRITE_VS, SPRITE_FS);
    this.lineProg = program(gl, LINE_VS, LINE_FS);
    this.uS = {
      view: gl.getUniformLocation(this.spriteProg, 'uView'),
      cam: gl.getUniformLocation(this.spriteProg, 'uCam'),
      zoom: gl.getUniformLocation(this.spriteProg, 'uZoom'),
      cell: gl.getUniformLocation(this.spriteProg, 'uCell'),
      grid: gl.getUniformLocation(this.spriteProg, 'uAtlasGrid'),
      tex: gl.getUniformLocation(this.spriteProg, 'uTex'),
    };
    this.uL = {
      view: gl.getUniformLocation(this.lineProg, 'uView'),
      cam: gl.getUniformLocation(this.lineProg, 'uCam'),
      zoom: gl.getUniformLocation(this.lineProg, 'uZoom'),
      time: gl.getUniformLocation(this.lineProg, 'uTime'),
    };

    // sdílený quad
    const quad = new Float32Array([0, 0, 1, 0, 0, 1, 1, 1]);
    this.quadBuf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, this.quadBuf);
    gl.bufferData(gl.ARRAY_BUFFER, quad, gl.STATIC_DRAW);

    const lineQuad = new Float32Array([0, -1, 1, -1, 0, 1, 1, 1]);
    this.lineQuadBuf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, this.lineQuadBuf);
    gl.bufferData(gl.ARRAY_BUFFER, lineQuad, gl.STATIC_DRAW);

    // VAO statického terénu
    this.terrainVAO = gl.createVertexArray();
    this.terrainBuf = gl.createBuffer();
    this.terrainCount = 0;
    this._setupSpriteVAO(this.terrainVAO, this.terrainBuf);

    // VAO dynamických spritů
    this.dynVAO = gl.createVertexArray();
    this.dynBuf = gl.createBuffer();
    this._setupSpriteVAO(this.dynVAO, this.dynBuf);
    this.dynData = new Float32Array(8 * 4096);
    this.dynCount = 0;

    // VAO vedení
    this.lineVAO = gl.createVertexArray();
    this.lineBuf = gl.createBuffer();
    gl.bindVertexArray(this.lineVAO);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.lineQuadBuf);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.lineBuf);
    const lstride = 10 * 4;
    gl.enableVertexAttribArray(1);
    gl.vertexAttribPointer(1, 4, gl.FLOAT, false, lstride, 0);
    gl.vertexAttribDivisor(1, 1);
    gl.enableVertexAttribArray(2);
    gl.vertexAttribPointer(2, 4, gl.FLOAT, false, lstride, 16);
    gl.vertexAttribDivisor(2, 1);
    gl.enableVertexAttribArray(3);
    gl.vertexAttribPointer(3, 2, gl.FLOAT, false, lstride, 32);
    gl.vertexAttribDivisor(3, 1);
    gl.bindVertexArray(null);
    this.lineData = new Float32Array(10 * 4096);
    this.lineCount = 0;

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    gl.clearColor(0.09, 0.12, 0.16, 1);
  }

  Renderer.prototype._setupSpriteVAO = function (vao, instBuf) {
    const gl = this.gl;
    gl.bindVertexArray(vao);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.quadBuf);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    gl.bindBuffer(gl.ARRAY_BUFFER, instBuf);
    const stride = 8 * 4; // x,y,depth,sprite,r,g,b,a
    gl.enableVertexAttribArray(1);
    gl.vertexAttribPointer(1, 3, gl.FLOAT, false, stride, 0);
    gl.vertexAttribDivisor(1, 1);
    gl.enableVertexAttribArray(2);
    gl.vertexAttribPointer(2, 1, gl.FLOAT, false, stride, 12);
    gl.vertexAttribDivisor(2, 1);
    gl.enableVertexAttribArray(3);
    gl.vertexAttribPointer(3, 4, gl.FLOAT, false, stride, 16);
    gl.vertexAttribDivisor(3, 1);
    gl.bindVertexArray(null);
  };

  /* Nahraje terén jako statické instance, seřazené podle hloubky. */
  Renderer.prototype.uploadTerrain = function (map, tintFn) {
    const gl = this.gl;
    const N = map.size;
    const S = A.S;
    const T = EG.T;
    const data = new Float32Array(8 * N * N);
    let n = 0;
    // pořadí kreslení podle (x+y) => procházet diagonály
    for (let s = 0; s <= 2 * (N - 1); s++) {
      const y0 = Math.max(0, s - (N - 1));
      const y1 = Math.min(N - 1, s);
      for (let y = y0; y <= y1; y++) {
        const x = s - y;
        const t = map.type[map.idx(x, y)];
        let sprite;
        switch (t) {
          case T.WATER: sprite = S.WATER; break;
          case T.SAND: sprite = S.SAND; break;
          case T.GRASS: sprite = S.GRASS; break;
          case T.FOREST: sprite = S.FOREST; break;
          case T.HILL: sprite = S.HILL; break;
          case T.MOUNTAIN: sprite = S.MOUNTAIN; break;
          case T.RIVER: sprite = S.RIVER; break;
          default: sprite = S.RESERVOIR;
        }
        const o = n * 8;
        data[o] = isoX(x, y); data[o + 1] = isoY(x, y); data[o + 2] = 0;
        data[o + 3] = sprite;
        const tint = tintFn ? tintFn(x, y) : 1;
        data[o + 4] = tint; data[o + 5] = tint; data[o + 6] = tint; data[o + 7] = 1;
        n++;
      }
    }
    gl.bindBuffer(gl.ARRAY_BUFFER, this.terrainBuf);
    gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
    this.terrainCount = n;
  };

  Renderer.prototype.beginDynamic = function () { this.dynCount = 0; this.lineCount = 0; };

  Renderer.prototype.pushSprite = function (gx, gy, sprite, r, g, b, a) {
    if (this.dynCount * 8 >= this.dynData.length) {
      const bigger = new Float32Array(this.dynData.length * 2);
      bigger.set(this.dynData); this.dynData = bigger;
    }
    const o = this.dynCount * 8;
    const d = this.dynData;
    d[o] = isoX(gx, gy); d[o + 1] = isoY(gx, gy); d[o + 2] = 0;
    d[o + 3] = sprite;
    d[o + 4] = r === undefined ? 1 : r;
    d[o + 5] = g === undefined ? 1 : g;
    d[o + 6] = b === undefined ? 1 : b;
    d[o + 7] = a === undefined ? 1 : a;
    this.dynCount++;
  };

  Renderer.prototype.pushLine = function (gx1, gy1, gx2, gy2, r, g, b, a, load, flowDir) {
    if (this.lineCount * 10 >= this.lineData.length) {
      const bigger = new Float32Array(this.lineData.length * 2);
      bigger.set(this.lineData); this.lineData = bigger;
    }
    const o = this.lineCount * 10;
    const d = this.lineData;
    d[o] = isoX(gx1, gy1); d[o + 1] = isoY(gx1, gy1);
    d[o + 2] = isoX(gx2, gy2); d[o + 3] = isoY(gx2, gy2);
    d[o + 4] = r; d[o + 5] = g; d[o + 6] = b; d[o + 7] = a;
    d[o + 8] = load; d[o + 9] = flowDir;
    this.lineCount++;
  };

  Renderer.prototype.render = function (time) {
    const gl = this.gl;
    const canvas = this.canvas;
    const dpr = window.devicePixelRatio || 1;
    const w = Math.floor(canvas.clientWidth * dpr);
    const h = Math.floor(canvas.clientHeight * dpr);
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w; canvas.height = h;
    }
    gl.viewport(0, 0, w, h);
    gl.clear(gl.COLOR_BUFFER_BIT);

    const zoom = this.cam.zoom * dpr;

    // terén
    gl.useProgram(this.spriteProg);
    gl.uniform2f(this.uS.view, w, h);
    gl.uniform2f(this.uS.cam, this.cam.x, this.cam.y);
    gl.uniform1f(this.uS.zoom, zoom);
    gl.uniform2f(this.uS.cell, A.CELL_W, A.CELL_H);
    gl.uniform2f(this.uS.grid, A.COLS, A.ROWS);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.tex);
    gl.uniform1i(this.uS.tex, 0);
    gl.bindVertexArray(this.terrainVAO);
    gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, this.terrainCount);

    // vedení (pod budovami)
    if (this.lineCount > 0) {
      gl.useProgram(this.lineProg);
      gl.uniform2f(this.uL.view, w, h);
      gl.uniform2f(this.uL.cam, this.cam.x, this.cam.y);
      gl.uniform1f(this.uL.zoom, zoom);
      gl.uniform1f(this.uL.time, time);
      gl.bindVertexArray(this.lineVAO);
      gl.bindBuffer(gl.ARRAY_BUFFER, this.lineBuf);
      gl.bufferData(gl.ARRAY_BUFFER, this.lineData.subarray(0, this.lineCount * 10), gl.DYNAMIC_DRAW);
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, this.lineCount);
    }

    // dynamické sprity
    if (this.dynCount > 0) {
      gl.useProgram(this.spriteProg);
      gl.bindVertexArray(this.dynVAO);
      gl.bindBuffer(gl.ARRAY_BUFFER, this.dynBuf);
      gl.bufferData(gl.ARRAY_BUFFER, this.dynData.subarray(0, this.dynCount * 8), gl.DYNAMIC_DRAW);
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, this.dynCount);
    }
    gl.bindVertexArray(null);
  };

  // převod obrazovka -> dlaždice
  Renderer.prototype.screenToTile = function (px, py) {
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    const wx = (px - w / 2) / this.cam.zoom + this.cam.x;
    const wy = (py - h / 2) / this.cam.zoom + this.cam.y;
    const gx = (wx / HW + wy / HH) / 2;
    const gy = (wy / HH - wx / HW) / 2;
    return [Math.round(gx), Math.round(gy)];
  };

  Renderer.prototype.tileToWorld = function (gx, gy) {
    return [isoX(gx, gy), isoY(gx, gy)];
  };

  EG.Renderer = Renderer;
  EG.iso = { isoX, isoY, HW, HH };
})();
