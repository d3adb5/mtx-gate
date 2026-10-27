// mtx-gate watch page: sign in, keep this IP open, watch a channel over WHEP with sound, notice when it ends.
// The login lives only in this page's memory: never in storage, cookies or URLs.
'use strict';

const GATE = '/gate/v1';
const RENEW_MS = 60000;
const POLL_MS = 3000;
const STALL_MS = 12000;
const PATH_RE = /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/;

const $ = (id) => document.getElementById(id);
let auth = null;
let channels = [];
let renewTimer = null;
let session = null;

function basic(user, pass) {
  const bytes = new TextEncoder().encode(user + ':' + pass);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return 'Basic ' + btoa(bin);
}

function request(method, url, opts = {}) {
  const headers = { Authorization: auth };
  if (opts.type) headers['Content-Type'] = opts.type;
  return fetch(url, {
    method, headers, body: opts.body, keepalive: !!opts.keepalive,
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
}

// A refusal from the gate itself (IP not open, bad login) rather than from MediaMTX.
const fromGate = (r) => r.headers.get('X-Mtx-Gate') === '1';

function show(view) {
  for (const id of ['login', 'picker', 'player']) $(id).hidden = id !== view;
}

function status(text) { $('status').textContent = text; }

function overlay(text, tap) {
  $('overlay').hidden = !text && !tap;
  $('overlayText').textContent = text || '';
  $('tap').hidden = !tap;
}

async function open() {
  const r = await request('POST', GATE + '/open');
  if (r.status === 401) throw new Error('login');
  if (r.status === 429) throw new Error('busy');
  if (!r.ok) throw new Error('gate');
}

function startRenewals() {
  clearInterval(renewTimer);
  renewTimer = setInterval(async () => {
    try {
      await open();
    } catch (e) {
      if (e.message === 'login') signOut('Signed out: the login was refused.');
      // Network blips: the lease outlives one missed renewal.
    }
  }, RENEW_MS);
}

async function signIn(ev) {
  ev.preventDefault();
  const user = $('user').value.trim();
  const pass = $('pass').value;
  $('loginMsg').textContent = '';
  if (!user || !pass) return;
  auth = basic(user, pass);
  $('pass').value = '';
  try {
    await open();
    const r = await request('GET', GATE + '/channels');
    if (!r.ok) throw new Error(r.status === 401 ? 'login' : 'gate');
    const list = (await r.json()).channels;
    channels = Array.isArray(list) ? list.filter((c) => typeof c === 'string' && PATH_RE.test(c)) : [];
  } catch (e) {
    auth = null;
    $('loginMsg').textContent = e.message === 'login' ? 'Login refused.'
      : e.message === 'busy' ? 'Too many attempts. Wait a minute.' : 'The server could not be reached.';
    return;
  }
  startRenewals();
  renderChannels();
  route(true);
}

function signOut(message) {
  stopSession();
  clearInterval(renewTimer);
  auth = null;
  channels = [];
  $('channels').replaceChildren();
  history.replaceState(null, '', location.pathname);
  $('loginMsg').textContent = message || '';
  show('login');
  $('user').focus();
}

function renderChannels() {
  const items = channels.map((c) => {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = c;
    b.addEventListener('click', () => {
      unlockAudio();
      history.pushState(null, '', '#' + encodeURIComponent(c));
      watch(c);
    });
    li.append(b);
    return li;
  });
  $('channels').replaceChildren(...items);
}

function route() {
  let want = '';
  try { want = decodeURIComponent(location.hash.slice(1)); } catch { want = ''; }
  if (auth && channels.includes(want)) {
    watch(want);
  } else {
    stopSession();
    show(auth ? 'picker' : 'login');
  }
}

// Called inside a click: lets later play() calls keep their sound (Safari needs the element touched in a gesture).
function unlockAudio() {
  const v = $('video');
  v.muted = false;
  const p = v.play();
  if (p) p.catch(() => {});
}

async function play() {
  const v = $('video');
  v.muted = false;
  try {
    await v.play();
    overlay('', false);
  } catch {
    // Autoplay with sound refused: ask for one tap instead of ever starting muted.
    overlay('', true);
  }
}

function watch(path) {
  stopSession();
  show('player');
  $('title').textContent = path;
  status('Connecting…');
  overlay('', false);
  session = { path, stopped: false, pc: null, resource: null, timer: null };
  connect(session);
}

function stopSession() {
  const s = session;
  session = null;
  if (!s) return;
  s.stopped = true;
  teardown(s);
  const v = $('video');
  v.pause();
  v.srcObject = null;
}

function teardown(s) {
  clearTimeout(s.timer);
  s.timer = null;
  if (s.pc) s.pc.close();
  s.pc = null;
  if (s.resource && auth) request('DELETE', s.resource, { keepalive: true }).catch(() => {});
  s.resource = null;
}

function later(s, fn, ms) {
  clearTimeout(s.timer);
  s.timer = setTimeout(() => { if (!s.stopped) fn(); }, ms);
}

function gathered(pc, ms) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve();
    const done = () => { if (pc.iceGatheringState === 'complete') resolve(); };
    pc.addEventListener('icegatheringstatechange', done);
    setTimeout(resolve, ms);
  });
}

async function connect(s) {
  const pc = new RTCPeerConnection({ bundlePolicy: 'max-bundle' });
  s.pc = pc;
  pc.addTransceiver('video', { direction: 'recvonly' });
  pc.addTransceiver('audio', { direction: 'recvonly' });
  const stream = new MediaStream();
  pc.ontrack = (e) => {
    stream.addTrack(e.track);
    const v = $('video');
    if (v.srcObject !== stream) v.srcObject = stream;
    play();
  };
  pc.onconnectionstatechange = () => {
    if (s.stopped || s.pc !== pc) return;
    if (pc.connectionState === 'connected') status('Live');
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') checkEnded(s, true);
  };
  try {
    await pc.setLocalDescription(await pc.createOffer());
    await gathered(pc, 3000);
    if (s.stopped) return;
    const r = await request('POST', '/' + s.path + '/whep', { type: 'application/sdp', body: pc.localDescription.sdp });
    if (s.stopped) return;
    if (r.status === 201) {
      const loc = new URL(r.headers.get('Location') || '', location.href);
      if (loc.origin === location.origin) s.resource = loc.href;
      await pc.setRemoteDescription({ type: 'answer', sdp: await r.text() });
      monitor(s);
      return;
    }
    teardown(s);
    if (r.status === 404 && fromGate(r)) {
      status('Reopening…');
      await open().catch(() => {});
      later(s, () => connect(s), 2000);
    } else if (r.status === 404) {
      waitForLive(s, 'Not streaming right now. It will start here when it goes live.');
    } else if (r.status === 401) {
      status('');
      overlay('This login may not watch this channel.', false);
    } else {
      status('Server busy, retrying…');
      later(s, () => connect(s), r.status === 429 ? 15000 : 5000);
    }
  } catch {
    if (s.stopped) return;
    teardown(s);
    status('Connection failed, retrying…');
    later(s, () => connect(s), 5000);
  }
}

async function isLive(path) {
  const r = await request('GET', GATE + '/live/' + path);
  if (r.status === 401) throw new Error('login');
  if (!r.ok) return null;
  return (await r.json()).live === true;
}

// While playing: ask the server whether the channel is still published, and watch the bytes arriving.
function monitor(s) {
  let lastBytes = -1;
  let lastChange = Date.now();
  const tick = async () => {
    if (s.stopped || !s.pc) return;
    let bytes = 0;
    try {
      (await s.pc.getStats()).forEach((r) => { if (r.type === 'inbound-rtp') bytes += r.bytesReceived || 0; });
    } catch { /* closed meanwhile */ }
    if (bytes !== lastBytes) { lastBytes = bytes; lastChange = Date.now(); }
    let live = null;
    try { live = await isLive(s.path); } catch { signOut('Signed out: the login was refused.'); return; }
    if (s.stopped) return;
    if (live === false) return ended(s);
    if (Date.now() - lastChange > STALL_MS) {
      teardown(s);
      status('Stalled, reconnecting…');
      return later(s, () => connect(s), 500);
    }
    later(s, tick, POLL_MS);
  };
  later(s, tick, POLL_MS);
}

async function checkEnded(s) {
  let live = null;
  try { live = await isLive(s.path); } catch { return signOut('Signed out: the login was refused.'); }
  if (s.stopped) return;
  if (live === false) return ended(s);
  teardown(s);
  status('Reconnecting…');
  later(s, () => connect(s), 1000);
}

function ended(s) {
  teardown(s);
  $('video').srcObject = null;
  waitForLive(s, 'The stream ended. It will start again here if it comes back.');
}

// Waits for the channel to come back, then resumes by itself (with sound: the page was already clicked).
function waitForLive(s, text) {
  status('Waiting for the stream');
  overlay(text, false);
  const poll = async () => {
    let live = null;
    try { live = await isLive(s.path); } catch { return signOut('Signed out: the login was refused.'); }
    if (s.stopped) return;
    if (live) {
      overlay('', false);
      status('Connecting…');
      connect(s);
    } else {
      later(s, poll, POLL_MS);
    }
  };
  later(s, poll, POLL_MS);
}

document.addEventListener('DOMContentLoaded', () => {
  $('login').addEventListener('submit', signIn);
  $('signoutPicker').addEventListener('click', () => signOut(''));
  $('signoutPlayer').addEventListener('click', () => signOut(''));
  $('back').addEventListener('click', () => { history.pushState(null, '', location.pathname); route(); });
  $('tap').addEventListener('click', () => play());
  window.addEventListener('popstate', () => route());
  window.addEventListener('pagehide', () => stopSession());
  show('login');
  $('user').focus();
});
