// The login background: slow colour masses in the product's own colours,
// seen through fluted (reeded) glass. Two WebGL passes:
//   1. the colour field, rendered small (it is soft, so a quarter of the
//      resolution is enough) into a texture;
//   2. the glass, at full resolution: every rib is a cylindrical lens that
//      shows a squeezed, offset slice of the field, with a light edge, a
//      shaded edge and a little dispersion, plus static grain.
// No network, no dependency. Under prefers-reduced-motion it draws one still
// frame. It stops when the tab is hidden. Without hardware WebGL it leaves
// the CSS fallback (gradient plus rib overlay) in place.
import { useEffect, useRef } from 'react';

const VERT = `
attribute vec2 aPos;
varying vec2 vUv;
void main() { vUv = aPos * 0.5 + 0.5; gl_Position = vec4(aPos, 0.0, 1.0); }
`;

const FIELD = `
precision highp float;
varying vec2 vUv;
uniform float uT;
uniform float uAspect;
uniform float uPortrait;

vec2 hash2(vec2 p) {
  p = vec2(dot(p, vec2(127.1, 311.7)), dot(p, vec2(269.5, 183.3)));
  return -1.0 + 2.0 * fract(sin(p) * 43758.5453123);
}
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(dot(hash2(i), f), dot(hash2(i + vec2(1.0, 0.0)), f - vec2(1.0, 0.0)), u.x),
             mix(dot(hash2(i + vec2(0.0, 1.0)), f - vec2(0.0, 1.0)), dot(hash2(i + vec2(1.0, 1.0)), f - vec2(1.0, 1.0)), u.x), u.y);
}
float fbm(vec2 p) {
  float a = 0.5, s = 0.0;
  for (int i = 0; i < 4; i++) { s += a * noise(p); p = p * 2.03 + vec2(1.7, 9.2); a *= 0.5; }
  return s;
}
float blob(vec2 p, vec2 c, vec2 r) { vec2 d = (p - c) / r; return exp(-dot(d, d)); }

// a mass with a soft halo and a defined, wobbling edge
float mass(vec2 p, vec2 c, vec2 r, float edge) {
  vec2 d = (p - c) / r;
  float l = length(d);
  return 0.35 * exp(-l * l * 1.6) + 0.65 * smoothstep(1.0, 1.0 - edge, l);
}

void main() {
  // p: x in [0, aspect], y in [0, 1], y up.
  vec2 p = vec2(vUv.x * uAspect, vUv.y);
  float t = uT;
  float A = uAspect;
  // on a tall screen the masses gather in the upper half, above the panel
  float yS = mix(1.0, 0.62, uPortrait);
  float y0 = mix(0.0, 0.22, uPortrait);

  // a slow flow, like ink in water
  vec2 w = vec2(fbm(p * 1.25 + vec2(0.0, t * 0.020)), fbm(p * 1.25 + vec2(5.2, -t * 0.017)));
  vec2 q = p + 0.48 * w;
  // long horizontal streaks, as if the light had moved during a long exposure
  float streak = fbm(vec2(q.x * 0.9, q.y * 7.0) + vec2(t * 0.01, 0.0));

  vec3 night   = vec3(0.012, 0.022, 0.058);
  vec3 deep    = vec3(0.035, 0.095, 0.250);
  vec3 blue    = vec3(0.120, 0.330, 0.840);
  vec3 bright  = vec3(0.470, 0.680, 0.980);
  vec3 coral   = vec3(0.980, 0.380, 0.400);
  vec3 magenta = vec3(0.700, 0.150, 0.500);
  vec3 dark    = vec3(0.003, 0.005, 0.012);

  vec3 col = night;
  col = mix(col, deep, smoothstep(-0.35, 0.30, fbm(q * 0.8 + vec2(3.1, t * 0.008))) * 0.95);

  // the blue: a wide river across the upper frame, brightest at its core
  float by = y0 + yS * (0.62 + 0.11 * sin(q.x * 1.3 + t * 0.040) + 0.04 * sin(t * 0.031));
  float bd = (q.y - by) / (0.24 * yS);
  float river = exp(-bd * bd) * smoothstep(-0.3, 0.35, q.x / A);
  float bBlue = clamp(river * (0.85 + 0.6 * streak), 0.0, 1.0);
  bBlue = max(bBlue, mass(q, vec2(A * (0.16 + 0.05 * sin(t * 0.037)), y0 + yS * (0.86 + 0.04 * cos(t * 0.029))), vec2(0.34, 0.20) * vec2(1.0, yS), 0.5) * 0.85);
  col = mix(col, blue, bBlue);
  col = mix(col, bright, smoothstep(0.55, 1.0, bBlue) * 0.6);

  // the alarm: coral going to magenta, low in the frame
  vec2 cc = vec2(A * (0.42 + 0.06 * sin(t * 0.026 + 1.0)), y0 + yS * (0.40 + 0.05 * cos(t * 0.033)));
  float bCoral = mass(q, cc, vec2(0.36, 0.22) * vec2(1.0, yS), 0.45);
  bCoral = clamp(bCoral * (0.8 + 0.5 * streak), 0.0, 1.0);
  float toMag = smoothstep(-0.16, 0.14, (cc.y - q.y) / yS + 0.25 * w.x);
  col = mix(col, mix(coral, magenta, toMag), bCoral);
  // a hotter core inside the alarm
  float core = mass(q, cc + vec2(-0.04, 0.05 * yS), vec2(0.15, 0.10) * vec2(1.0, yS), 0.7);
  col = mix(col, vec3(1.0, 0.52, 0.42), core * 0.55 * (1.0 - toMag));
  col = mix(col, magenta * 0.65, mass(q, cc + vec2(0.34, -0.20 * yS), vec2(0.42, 0.13) * vec2(1.0, yS), 0.6) * 0.6);

  // one dark mass standing in the light, tall, leaning a little
  vec2 cd = vec2(A * (0.56 + 0.04 * sin(t * 0.021 + 2.0)), y0 + yS * (0.56 + 0.04 * sin(t * 0.027)));
  vec2 qd = q; qd.x -= (q.y - cd.y) * 0.25;
  col = mix(col, dark, mass(qd, cd, vec2(0.10, 0.36) * vec2(1.0, yS), 0.6) * 0.94);

  // keep the night: a soft fall-off to the edges
  vec2 v = vUv - 0.5;
  col *= 0.55 + 0.45 * smoothstep(0.95, 0.2, length(v * vec2(1.05, 1.25)));
  gl_FragColor = vec4(col, 1.0);
}
`;

const GLASS = `
precision highp float;
uniform sampler2D uField;
uniform vec2 uRes;
uniform float uRib;
uniform float uDpr;

void main() {
  vec2 px = gl_FragCoord.xy;
  float s = fract(px.x / uRib);
  float idx = floor(px.x / uRib);
  float n = s * 2.0 - 1.0;
  // a cylindrical lens: a strip about 2.6 ribs wide, squeezed into one rib,
  // bending harder at the edges; the slice is offset from the rib under it
  float lens = n * 1.45 + 0.45 * n * n * n;
  float cx = (idx + 0.5) * uRib + lens * uRib + 0.7 * uRib;
  float dy = n * n * uRib * 0.35;
  vec2 uv = vec2(cx, px.y + dy) / uRes;
  float disp = 0.12 * uRib * n / uRes.x;
  vec3 c;
  c.r = texture2D(uField, uv + vec2(disp, 0.0)).r;
  c.g = texture2D(uField, uv).g;
  c.b = texture2D(uField, uv - vec2(disp, 0.0)).b;

  float lum = dot(c, vec3(0.3, 0.59, 0.11));
  float d = s * uRib / uDpr;                 // css px from the light edge
  float e = (1.0 - s) * uRib / uDpr;         // css px from the shaded edge
  c += exp(-d / 0.8) * (0.02 + 0.45 * lum) * vec3(0.92, 0.96, 1.0);
  float gs = (s - 0.28) / 0.16;
  c += exp(-gs * gs) * (0.006 + 0.08 * lum);
  c *= 1.0 - 0.16 * smoothstep(0.45, 1.0, s) - 0.12 * exp(-e / 1.0);

  float g = fract(sin(dot(floor(px / uDpr), vec2(12.9898, 78.233))) * 43758.5453);
  c += (g - 0.5) * 0.05 * (0.55 + lum);
  gl_FragColor = vec4(c, 1.0);
}
`;

// Field time runs at SPEED x wall time: the masses complete a drift in
// about 1.5 to 2.5 minutes; the flow inside them is slower still.
const START_T = 34;
const SPEED = 1.5;

export function FlutedField({ className }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const gl = canvas.getContext('webgl', {
      alpha: false, antialias: false, depth: false, stencil: false,
      premultipliedAlpha: false, preserveDrawingBuffer: false,
      powerPreference: 'low-power', failIfMajorPerformanceCaveat: true,
    });
    if (!gl || gl.isContextLost()) return; // no hardware WebGL: the CSS fallback under the canvas stays

    const compile = (type: number, src: string) => {
      const s = gl.createShader(type)!;
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s) ?? 'shader');
      return s;
    };
    const program = (frag: string) => {
      const p = gl.createProgram()!;
      gl.attachShader(p, compile(gl.VERTEX_SHADER, VERT));
      gl.attachShader(p, compile(gl.FRAGMENT_SHADER, frag));
      gl.bindAttribLocation(p, 0, 'aPos');
      gl.linkProgram(p);
      if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p) ?? 'link');
      return p;
    };

    let pField: WebGLProgram, pGlass: WebGLProgram;
    try { pField = program(FIELD); pGlass = program(GLASS); } catch { return; }

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

    const tex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    const fbo = gl.createFramebuffer();

    const uF = { t: gl.getUniformLocation(pField, 'uT'), a: gl.getUniformLocation(pField, 'uAspect'), p: gl.getUniformLocation(pField, 'uPortrait') };
    const uG = { tex: gl.getUniformLocation(pGlass, 'uField'), res: gl.getUniformLocation(pGlass, 'uRes'), rib: gl.getUniformLocation(pGlass, 'uRib'), dpr: gl.getUniformLocation(pGlass, 'uDpr') };

    let W = 0, H = 0, FW = 0, FH = 0, dpr = 1, rib = 20;
    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      const cw = canvas.clientWidth, ch = canvas.clientHeight;
      W = Math.max(1, Math.round(cw * dpr)); H = Math.max(1, Math.round(ch * dpr));
      canvas.width = W; canvas.height = H;
      FW = Math.max(2, Math.ceil(cw / 4)); FH = Math.max(2, Math.ceil(ch / 4));
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, FW, FH, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
      gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      // ribs about 20 css px on a desktop, narrower on a phone; a whole number of device pixels
      rib = Math.round(Math.min(22, Math.max(12, cw / 70)) * dpr);
    };

    const draw = (t: number) => {
      gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
      gl.viewport(0, 0, FW, FH);
      gl.useProgram(pField);
      gl.uniform1f(uF.t, t);
      gl.uniform1f(uF.a, FW / FH);
      gl.uniform1f(uF.p, FH > FW ? 1 : 0);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      gl.viewport(0, 0, W, H);
      gl.useProgram(pGlass);
      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.uniform1i(uG.tex, 0);
      gl.uniform2f(uG.res, W, H);
      gl.uniform1f(uG.rib, rib);
      gl.uniform1f(uG.dpr, dpr);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    };

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
    // Test hook: ?still=<seconds> draws one fixed frame (screenshots, the film).
    const still = Number(new URLSearchParams(window.location.search).get('still') ?? NaN);
    let raf = 0, last = 0, elapsed = 0, prev = 0;
    const FRAME_MS = 1000 / 30; // the motion is slow; 30 frames a second is plenty

    const tick = (now: number) => {
      raf = requestAnimationFrame(tick);
      if (now - last < FRAME_MS - 2) return;
      elapsed += Math.min(now - (prev || now), 100);
      prev = now; last = now;
      draw(START_T + (SPEED * elapsed) / 1000);
    };
    const start = () => {
      cancelAnimationFrame(raf); raf = 0;
      if (reduce.matches || document.hidden || Number.isFinite(still)) {
        draw(Number.isFinite(still) ? still : START_T + (SPEED * elapsed) / 1000);
        return;
      }
      prev = 0; last = 0;
      raf = requestAnimationFrame(tick);
    };

    const ro = new ResizeObserver(() => { resize(); draw(START_T + (SPEED * elapsed) / 1000); start(); });
    resize();
    draw(Number.isFinite(still) ? still : START_T);
    canvas.dataset.ready = '1';
    ro.observe(canvas);
    start();

    const onVis = () => start();
    document.addEventListener('visibilitychange', onVis);
    reduce.addEventListener('change', onVis);
    const onLost = (e: Event) => { e.preventDefault(); cancelAnimationFrame(raf); delete canvas.dataset.ready; };
    canvas.addEventListener('webglcontextlost', onLost);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      document.removeEventListener('visibilitychange', onVis);
      reduce.removeEventListener('change', onVis);
      canvas.removeEventListener('webglcontextlost', onLost);
      // The context stays alive: React StrictMode mounts twice, and a lost
      // context cannot be got back from the same canvas.
      gl.deleteTexture(tex); gl.deleteFramebuffer(fbo); gl.deleteBuffer(buf);
      gl.deleteProgram(pField); gl.deleteProgram(pGlass);
    };
  }, []);

  return (
    <div className={className} aria-hidden="true">
      <div className="lgn-bg-fallback" />
      <canvas ref={ref} className="lgn-bg-canvas" />
    </div>
  );
}
