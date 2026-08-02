/* ═══════════════════════════════════════════════════════════
   profile.js — محرك بطاقة الملف الذهبي
   مشغل موسيقى WebAudio (الوتر A minor) + عدادات متحركة
   + جزيئات ذهبية + إمالة ثلاثية الأبعاد
   ═══════════════════════════════════════════════════════════ */
'use strict';

/* ─────────── الثوابت الموسيقية ─────────── */
const CHORD_STEPS = 16;   // 16 خطوة لكل وتر (4 ثوانٍ بمعدل 0.25)
const STEP = 0.25;        // ثانية لكل خطوة

// الأوتار: [التردد الأساسي, الأربيجيو, الوسادة]
const CHORDS = {
  Am: [110.00, [261.63, 329.63, 440.00, 329.63], [261.63, 329.63, 440.00]],
  F:  [ 87.31, [220.00, 261.63, 349.23, 261.63], [220.00, 261.63, 349.23]],
  G:  [ 98.00, [246.94, 293.66, 392.00, 293.66], [246.94, 293.66, 392.00]],
  Em: [ 82.41, [196.00, 246.94, 329.63, 246.94], [196.00, 246.94, 329.63]]
};

// تسلسل الأوتار: Am → F → G → Em
const CHORD_SEQ = ['Am', 'F', 'G', 'Em'];

// سلم A minor الخماسي
const SCALE = [220.00, 261.63, 293.66, 329.63, 392.00, 440.00];

// اللحن (مؤشرات على السلم) + إيقاع نصف زمني
const MELODY = [3, 4, 2, 3, 1, 2, 0, 1, 3, 4, 5, 4, 3, 2, 1, 2];
const DUR = [1, 0.5, 0.5, 1, 0.5, 0.5, 1, 1, 1, 0.5, 0.5, 1, 0.5, 0.5, 1, 1];

/* ─────────── الحالة ─────────── */
const music = {
  ctx: null,
  master: null,
  delay: null,
  started: false,
  playing: false,
  timer: null,
  step: 0,
  chordIdx: 0,
  nextTime: 0,
  songName: 'memory_03',
  byline: 'Willix · A minor'
};

/* ─────────── الأدوات ─────────── */
const $ = (sel, ctx) => (ctx || document).querySelector(sel);
const $$ = (sel, ctx) => Array.from((ctx || document).querySelectorAll(sel));

function midiToFreq(m) { return 440 * Math.pow(2, (m - 69) / 12); }

function dbToGain(db) { return Math.pow(10, db / 20); }

/* ─────────── محرك الصوت ─────────── */
function ensureCtx() {
  if (music.ctx) return;
  const AC = window.AudioContext || window.webkitAudioContext;
  if (!AC) return;
  music.ctx = new AC();

  music.master = music.ctx.createGain();
  music.master.gain.value = dbToGain(-14);
  music.master.connect(music.ctx.destination);

  // صدى (Delay) خفيف للعمق
  music.delay = music.ctx.createDelay(1);
  music.delay.delayTime.value = STEP * 3;
  const fb = music.ctx.createGain();
  fb.gain.value = 0.32;
  const wet = music.ctx.createGain();
  wet.gain.value = dbToGain(-12);
  music.delay.connect(fb);
  fb.connect(music.delay);
  music.delay.connect(wet);
  wet.connect(music.master);
}

function note(freq, start, dur, dest, type, volDb) {
  if (!music.ctx) return;
  const osc = music.ctx.createOscillator();
  const g = music.ctx.createGain();
  osc.type = type || 'sine';
  osc.frequency.value = freq;
  g.gain.setValueAtTime(0.0001, start);
  g.gain.exponentialRampToValueAtTime(dbToGain(volDb), start + 0.02);
  g.gain.exponentialRampToValueAtTime(0.0001, start + dur);
  osc.connect(g);
  g.connect(dest);
  osc.start(start);
  osc.stop(start + dur + 0.05);
}

function noiseHit(start, dur, volDb) {
  if (!music.ctx) return;
  const len = Math.max(1, Math.floor(music.ctx.sampleRate * dur));
  const buf = music.ctx.createBuffer(1, len, music.ctx.sampleRate);
  const data = buf.getChannelData(0);
  for (let i = 0; i < len; i++) data[i] = (Math.random() * 2 - 1) * (1 - i / len);
  const src = music.ctx.createBufferSource();
  src.buffer = buf;
  const g = music.ctx.createGain();
  g.gain.value = dbToGain(volDb);
  src.connect(g);
  g.connect(music.master);
  src.start(start);
}

function scheduleStep(step, time) {
  const bar = Math.floor(step / CHORD_STEPS);
  const idx = step % CHORD_STEPS;
  const chordKey = CHORD_SEQ[bar % CHORD_SEQ.length];
  const chord = CHORDS[chordKey];

  // الجهير — نبضة ثابتة
  note(chord[0], time, STEP * 0.9, music.master, 'triangle', -16);

  // الأربيجيو — نغمة كل خطوة
  const arpIdx = idx % chord[1].length;
  note(chord[1][arpIdx], time, STEP * 0.85, music.master, 'sine', -22);

  // الوسادة — نغمات طويلة عند بداية كل وتر
  if (idx === 0) {
    chord[2].forEach(f => note(f, time, STEP * CHORD_STEPS * 0.95, music.master, 'sine', -27));
  }

  // اللحن فوق السلم الخماسي
  const mIdx = MELODY[step % MELODY.length];
  const f = SCALE[mIdx];
  const d = DUR[step % DUR.length] * STEP * 2;
  note(f, time, d * 0.9, music.master, 'sine', -19);
  note(f * 2, time, d * 0.6, music.master, 'sine', -26);

  // طبلة خفيفة كل 4 خطوات + نقرة على الخطوة 2
  if (idx % 4 === 0) noiseHit(time, 0.06, -22);
  if (idx === 2 || idx === 10) note(SCALE[0] * 2, time, 0.05, music.master, 'square', -38);
}

function schedulerTick() {
  if (!music.playing) return;
  while (music.nextTime < music.ctx.currentTime + 0.15) {
    scheduleStep(music.step, music.nextTime);
    music.nextTime += STEP;
    music.step++;
  }
  music.timer = setTimeout(schedulerTick, 90);
}


/* ─────────── تشغيل / إيقاف ─────────── */
function startMusic() {
  ensureCtx();
  if (!music.ctx || music.playing) return;
  if (music.ctx.state === 'suspended') music.ctx.resume();
  music.playing = true;
  music.step = 0;
  music.chordIdx = 0;
  music.nextTime = music.ctx.currentTime + 0.08;
  schedulerTick();
  setPlayUI(true);
}

function stopMusic() {
  music.playing = false;
  if (music.timer) { clearTimeout(music.timer); music.timer = null; }
  setPlayUI(false);
}

function toggleMusic() {
  if (!music.playing) startMusic();
  else stopMusic();
}

/* ─────────── واجهة التشغيل ─────────── */
function setPlayUI(on) {
  const btn = $('.play-btn');
  if (!btn) return;
  btn.textContent = on ? '■ إيقاف' : '▶ تشغيل';
  btn.classList.toggle('playing', on);
  // مزامنة حالة الأب .music (لمطابقة زر التزامن الخارجي إن وُجد)
  const wrap = btn.closest('.music');
  if (wrap) wrap.classList.toggle('playing', on);
}

/* ─────────── عنوان المقطع ─────────── */
function setSongName(name, byline) {
  music.songName = name || music.songName;
  music.byline = byline || music.byline;
  const t = $('.track-name .note');
  const b = $('.byline');
  if (t) t.textContent = music.songName;
  if (b) b.textContent = music.byline;
}

/* ─────────── لوحة الرسم (الموشور) ─────────── */
function drawFx(playing, t, w, h) {
  // t ضمن [0,1]
  const ctx = $('canvas#viz').getContext('2d');
  const W = 116, H = 56;
  ctx.clearRect(0, 0, W, H);
  if (!playing) {
    ctx.fillStyle = 'rgba(212, 175, 55, .25)';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('• • •', W / 2, H / 2 + 3);
    return;
  }
  const now = performance.now() / 1000;
  const bands = 24;
  const bw = W / bands;
  for (let i = 0; i < bands; i++) {
    const v = (0.25 + 0.75 * Math.abs(Math.sin(now * 3 + i * 0.6))) * Math.sin(t * Math.PI + i * 0.4);
    const hgt = Math.max(2, H * 0.5 * v);
    const x = i * bw + bw * 0.18;
    const y = H - hgt;
    const g = ctx.createLinearGradient(0, y, 0, H);
    g.addColorStop(0, 'rgba(212, 175, 55, .9)');
    g.addColorStop(1, 'rgba(212, 175, 55, .05)');
    ctx.fillStyle = g;
    ctx.fillRect(x, y, bw * 0.64, hgt);
  }
  const lineY = H * (0.5 + 0.32 * Math.sin(now * 4));
  ctx.strokeStyle = 'rgba(212, 175, 55, .35)';
  ctx.beginPath();
  ctx.moveTo(0, lineY);
  for (let x = 0; x <= W; x += 4) {
    ctx.lineTo(x, lineY + Math.sin(x * 0.3 + now * 5) * 3);
  }
  ctx.stroke();
}

/* ─────────── ربط الأحداث ─────────── */
function bindEvents() {
  const btn = $('.play-btn');
  if (btn) {
    btn.addEventListener('click', () => {
      // بدء سياق الصوت مع أول تفاعل مستخدم (سياسة التشغيل التلقائي)
      ensureCtx();
      toggleMusic();
    });
  }

  // مفتاح المسافة: تشغيل / إيقاف
  document.addEventListener('keydown', e => {
    if (e.code === 'Space' && !e.repeat) {
      const tag = (e.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'button') return;
      e.preventDefault();
      ensureCtx();
      toggleMusic();
    }
  });

  // أول نقرة في أي مكان: فتح سياق الصوت (مطلوب حسب سياسة المتصفح)
  const unlock = () => {
    ensureCtx();
    if (music.ctx && music.ctx.state === 'suspended') music.ctx.resume();
  };
  document.addEventListener('click', unlock, { once: true });
  document.addEventListener('pointerdown', unlock, { once: true });
}


/* ─────────── العدادات المتحركة ─────────── */
function animateCounters() {
  const els = $$('[data-count]');
  if (!els.length) return;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  els.forEach(el => {
    const target = parseFloat(el.dataset.count);
    const suffix = el.dataset.suffix || '';
    if (isNaN(target)) return;
    if (reduce) { el.textContent = Math.round(target) + suffix; return; }
    const dur = 1400 + Math.random() * 600;
    const t0 = performance.now();
    const ease = x => 1 - Math.pow(1 - x, 3);
    function frame(now) {
      const p = Math.min(1, (now - t0) / dur);
      const v = Math.round(target * ease(p));
      el.textContent = v + suffix;
      if (p < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  });
}

/* ─────────── الجزيئات الذهبية ─────────── */
function initParticles() {
  const cv = $('#fx');
  if (!cv) return;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) return;

  const ctx = cv.getContext('2d');
  let W, H, dpr;
  const P = [];
  const COUNT = 34;

  function resize() {
    const parent = cv.parentElement;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = parent.clientWidth;
    H = parent.clientHeight;
    cv.width = W * dpr;
    cv.height = H * dpr;
    cv.style.width = W + 'px';
    cv.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function spawn(p) {
    p.x = Math.random() * W;
    p.y = Math.random() * H;
    p.r = 0.6 + Math.random() * 1.6;
    p.s = 0.12 + Math.random() * 0.35;
    p.a = 0.12 + Math.random() * 0.5;
    p.drift = (Math.random() - 0.5) * 0.12;
  }

  function frame() {
    ctx.clearRect(0, 0, W, H);
    for (const p of P) {
      p.y -= p.s;
      p.x += p.drift + Math.sin((p.y + p.x) * 0.02) * 0.1;
      p.a *= 0.999;
      if (p.y < -8) { p.y = H + 8; p.x = Math.random() * W; }
      if (p.a < 0.05) p.a = 0.5;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(212, 175, 55, ${p.a.toFixed(3)})`;
      ctx.shadowColor = 'rgba(212, 175, 55, .8)';
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
    rafId = requestAnimationFrame(frame);
  }

  let rafId = null;
  resize();
  for (let i = 0; i < COUNT; i++) spawn({});
  frame();

  let resizeT;
  window.addEventListener('resize', () => {
    clearTimeout(resizeT);
    resizeT = setTimeout(resize, 150);
  });

  // إيقاف عند مغادرة التبويب عبر حدث tabchange
  document.addEventListener('tabchange', e => {
    if (e.detail && e.detail.name === 'dashboard') {
      if (!rafId) rafId = requestAnimationFrame(frame);
    } else {
      if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    }
  });
}

/* ─────────── الإمالة ثلاثية الأبعاد ─────────── */
function initTilt() {
  const card = $('#profileCard');
  if (!card) return;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) return;

  let raf = null, tx = 0, ty = 0, cx = 0, cy = 0;

  function render() {
    cx += (tx - cx) * 0.08;
    cy += (ty - cy) * 0.08;
    card.style.transform = `perspective(1000px) rotateX(${cy.toFixed(2)}deg) rotateY(${cx.toFixed(2)}deg)`;
    raf = requestAnimationFrame(render);
  }

  card.addEventListener('pointermove', e => {
    const r = card.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width;
    const py = (e.clientY - r.top) / r.height;
    tx = (px - 0.5) * 10;
    ty = (0.5 - py) * 8;
  });

  card.addEventListener('pointerleave', () => { tx = 0; ty = 0; });

  document.addEventListener('tabchange', e => {
    const active = e.detail && e.detail.name === 'dashboard';
    if (raf) { cancelAnimationFrame(raf); raf = null; }
    if (active) raf = requestAnimationFrame(render);
    else card.style.transform = '';
  });

  raf = requestAnimationFrame(render);
}

/* ─────────── حلقة الموشور المرئي ─────────── */
function initViz() {
  const cv = $('#viz');
  if (!cv || !cv.getContext) return;
  let raf = null;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) return;

  function loop(t) {
    const phase = (music.playing ? (t / 1000) % 4 : 0);
    drawFx(music.playing, phase, 116, 56);
    raf = requestAnimationFrame(loop);
  }

  document.addEventListener('tabchange', e => {
    const active = e.detail && e.detail.name === 'dashboard';
    if (raf) { cancelAnimationFrame(raf); raf = null; }
    if (active) raf = requestAnimationFrame(loop);
  });

  raf = requestAnimationFrame(loop);
}

/* ─────────── الإقلاع ─────────── */
document.addEventListener('DOMContentLoaded', () => {
  setSongName(music.songName, music.byline);
  animateCounters();
  initParticles();
  initTilt();
  initViz();
  bindEvents();
});



