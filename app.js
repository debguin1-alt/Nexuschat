'use strict';

// Firebase config is injected at deploy time by GitHub Actions
// from repository secrets — never hardcoded here.
// For local development, copy config.example.js → config.js
// and fill in your values.
const FIREBASE_CONFIG = window.__NX_CONFIG__;

const CONFIG = {
  SESSION_KEY:        'nexus_session_v1',
  ROOM_KEY:           'nexus_room_v1',
  PREFS_KEY:          'nexus_prefs_v1',
  TYPING_WRITE_MS:    2000,
  TYPING_EXPIRE_MS:   5000,
  TYPING_IDLE_MS:     3000,
  HEARTBEAT_MS:       20000,
  MAX_FILE_BYTES:     25 * 1024 * 1024,


  CHUNK_BYTES:        900 * 1024,
  IDB_NAME:           'nexus-v1',
  IDB_VER:            2,
  EDIT_WINDOW_MS:     2 * 60 * 1000,
};

let state = {
  me:         null,
  roomCode:   null,
  prefs: {
    sound:            true,
    animations:       true,
    approvalRequired: false,
  },
};

let db             = null;
let _unsubMsgs     = null;
let _unsubMembers  = null;
let _unsubTyping   = null;
let _heartbeat     = null;
let _typingTimer   = null;
let _lastTypeWrite = 0;
let _isTyping      = false;
let _sidebarOpen   = false;
let _renderedIds   = new Set();
let _lastCachedTs  = 0;
let _idb           = null;
let _onlineCount   = 0;
let _sigPrivKey    = null;
let _pubKeyB64     = null;
const _pubKeyCache = new Map();
let _unsubApproval   = null;
let _isAdmin         = false;
let _presenceSettled = false;


let _unreadCount     = 0;

function openIDB() {
  if (_idb) return Promise.resolve(_idb);
  return new Promise((res, rej) => {
    const req = indexedDB.open(CONFIG.IDB_NAME, CONFIG.IDB_VER);
    req.onupgradeneeded = e => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains('msgs')) {
        const s = d.createObjectStore('msgs', { keyPath: 'id' });
        s.createIndex('room_ts', ['room', 'ts']);
      }
      if (!d.objectStoreNames.contains('meta'))
        d.createObjectStore('meta', { keyPath: 'k' });
      if (!d.objectStoreNames.contains('blobs'))
        d.createObjectStore('blobs', { keyPath: 'id' });

      if (!d.objectStoreNames.contains('sigkey'))
        d.createObjectStore('sigkey', { keyPath: 'id' });
      if (!d.objectStoreNames.contains('pubkeys'))
        d.createObjectStore('pubkeys', { keyPath: 'uid' });
    };
    req.onsuccess = e => { _idb = e.target.result; res(_idb); };
    req.onerror   = e => rej(e.target.error);
  });
}

async function idbTx(stores, mode, fn) {
  const db = await openIDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(stores, mode);
    tx.onerror = e => rej(e.target.error);
    fn(tx, res, rej);
  });
}

async function idbPut(store, val) {
  return idbTx(store, 'readwrite', (tx, res) => {
    const req = tx.objectStore(store).put(val);
    req.onsuccess = () => res(req.result);
  });
}

async function idbGetAll(store) {
  return idbTx(store, 'readonly', (tx, res) => {
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => res(req.result || []);
  });
}

async function idbGetMeta(k) {
  return idbTx('meta', 'readonly', (tx, res) => {
    const req = tx.objectStore('meta').get(k);
    req.onsuccess = () => res(req.result?.v ?? null);
  });
}
async function idbSetMeta(k, v) { return idbPut('meta', { k, v }); }

async function idbGetBlob(id) {
  return idbTx('blobs', 'readonly', (tx, res) => {
    const req = tx.objectStore('blobs').get(id);
    req.onsuccess = () => res(req.result?.url ?? null);
  });
}
async function idbSetBlob(id, url) { return idbPut('blobs', { id, url }); }

async function cacheMsg(docId, room, data) {
  try {
    await idbPut('msgs', { id: docId, room, data, ts: data.ts || 0 });
    const prev = (await idbGetMeta(`ts:${room}`)) || 0;
    if ((data.ts || 0) > prev) await idbSetMeta(`ts:${room}`, data.ts || 0);
  } catch {}
}

async function loadCached(room) {
  try {
    const all = await idbGetAll('msgs');
    return all.filter(r => r.room === room).sort((a, b) => (a.ts || 0) - (b.ts || 0));
  } catch { return []; }
}

async function clearCacheForRoom(room) {
  try {
    const db  = await openIDB();
    const all = await idbGetAll('msgs');
    const tx  = db.transaction(['msgs', 'meta'], 'readwrite');
    all.filter(r => r.room === room).forEach(r => tx.objectStore('msgs').delete(r.id));
    tx.objectStore('meta').delete(`ts:${room}`);
  } catch {}
}

let _roomEpoch   = 0;
const _epochKeys = new Map();
let _unsubRoom   = null;

async function _getEpochKey(code, epoch) {
  const cacheKey = `${code}:${epoch}`;
  if (_epochKeys.has(cacheKey)) return _epochKeys.get(cacheKey);
  const saltInput = new TextEncoder().encode(`NEXUS_EPOCH|${code}|${epoch}`);
  const saltHash  = await crypto.subtle.digest('SHA-256', saltInput);
  const salt      = new Uint8Array(saltHash).slice(0, 16);
  const raw       = new TextEncoder().encode(code);
  const base      = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  const key       = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  _epochKeys.set(cacheKey, key);
  return key;
}

const _AES_SALT = new Uint8Array([
  0x4e,0x58,0x55,0x53,0x5f,0x53,0x41,0x4c,
  0x54,0x5f,0x76,0x31,0x5f,0x32,0x30,0x32,
]);

const _keyCache = new Map();
async function _deriveKey(code) {
  if (_keyCache.has(code)) return _keyCache.get(code);
  const raw  = new TextEncoder().encode(code);
  const base = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: _AES_SALT, iterations: 100000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  _keyCache.set(code, key);
  return key;
}

function _b64uEnc(buf) {
  let s = ''; const u = new Uint8Array(buf);
  for (let i = 0; i < u.length; i += 8192) s += String.fromCharCode(...u.subarray(i, i + 8192));
  return btoa(s).replace(/\+/g,'-').split('/').join('_').replace(/=/g,'');
}
function _b64uDec(s) {
  return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
}

const _CHARSET =
  ' abcdefghijklmnopqrstuvwxyz' +
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
  '0123456789' +
  '.,!?\'":-_;@#()\n/\\+*=<>[]{}|%&^~`';

const _roomMaps = new Map();

function _getRoomMap(roomCode) {
  if (_roomMaps.has(roomCode)) return _roomMaps.get(roomCode);

  const arr = Array.from(_CHARSET);

  let h = 0x12345678;
  for (let i = 0; i < roomCode.length; i++) {
    h = Math.imul(h ^ roomCode.charCodeAt(i), 0x9e3779b9);
    h = (h << 13) | (h >>> 19);
  }
  h = h >>> 0;

  for (let i = arr.length - 1; i > 0; i--) {
    h = Math.imul(h ^ (h >>> 15), 0x85ebca6b) >>> 0;
    h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35) >>> 0;
    h = (h ^ (h >>> 16)) >>> 0;
    [arr[i], arr[h % (i + 1)]] = [arr[h % (i + 1)], arr[i]];
  }

  const offset = h % 51;

  const encode = new Map(), decode = new Map();
  arr.forEach((c, i) => {
    encode.set(c, offset + i);
    decode.set(offset + i, c);
  });

  _roomMaps.set(roomCode, { encode, decode, offset });
  return { encode, decode, offset };
}

function _textEncode(text, roomCode) {
  const { encode } = _getRoomMap(roomCode);
  return Array.from(text)
    .map(c => encode.has(c) ? encode.get(c) : `U${c.codePointAt(0)}`)
    .join('.');
}

function _textDecode(encoded, roomCode) {
  if (!encoded) return encoded;
  const { decode } = _getRoomMap(roomCode);
  return encoded.split('.')
    .map(tok => {
      if (tok.startsWith('U')) return String.fromCodePoint(parseInt(tok.slice(1), 10));
      const n = parseInt(tok, 10);
      return decode.has(n) ? decode.get(n) : tok;
    })
    .join('');
}

const _COMPRESS_MARKER   = 0x43;
const _NOCOMPRESS_MARKER = 0x4e;

let _compressionSupported = null;
async function _testCompression() {
  if (_compressionSupported !== null) return _compressionSupported;
  try {
    if (typeof CompressionStream === 'undefined' || typeof DecompressionStream === 'undefined') {
      _compressionSupported = false; return false;
    }
    const cs = new CompressionStream('deflate-raw');
    const w  = cs.writable.getWriter();
    w.write(new TextEncoder().encode('test'));
    w.close();
    const reader = cs.readable.getReader();
    const { value } = await reader.read();
    _compressionSupported = value instanceof Uint8Array && value.length > 0;
  } catch {
    _compressionSupported = false;
  }
  return _compressionSupported;
}

async function _collectStream(readable) {
  const chunks = [], reader = readable.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

async function _compress(str) {
  const raw = new TextEncoder().encode(str);
  if (!(await _testCompression())) {
    const out = new Uint8Array(1 + raw.length);
    out[0] = _NOCOMPRESS_MARKER;
    out.set(raw, 1);
    return out;
  }
  try {
    const cs = new CompressionStream('deflate-raw');
    const w  = cs.writable.getWriter();
    w.write(raw); w.close();
    const compressed = await _collectStream(cs.readable);
    const out = new Uint8Array(1 + compressed.length);
    out[0] = _COMPRESS_MARKER;
    out.set(compressed, 1);
    return out;
  } catch {
    const out = new Uint8Array(1 + raw.length);
    out[0] = _NOCOMPRESS_MARKER;
    out.set(raw, 1);
    return out;
  }
}

async function _decompress(buf) {
  if (!(buf instanceof Uint8Array) || buf.length < 2) {
    return new TextDecoder().decode(buf);
  }
  const marker  = buf[0];
  const payload = buf.slice(1);
  if (marker === _NOCOMPRESS_MARKER) {
    return new TextDecoder().decode(payload);
  }
  if (marker === _COMPRESS_MARKER) {
    if (typeof DecompressionStream === 'undefined') {
      return '[message requires update to read]';
    }
    try {
      const ds = new DecompressionStream('deflate-raw');
      const w  = ds.writable.getWriter();
      w.write(payload); w.close();
      const decompressed = await _collectStream(ds.readable);
      return new TextDecoder().decode(decompressed);
    } catch {
      return '[decryption error]';
    }
  }
  return new TextDecoder().decode(buf);
}

async function enc(text, code) {
  try {
    const encoded    = _textEncode(text, code);
    const compressed = await _compress(encoded);
    const epoch      = _roomEpoch;
    const key        = await _getEpochKey(code, epoch);
    const iv         = crypto.getRandomValues(new Uint8Array(12));
    const ct         = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, compressed);
    const out        = new Uint8Array(12 + ct.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(ct), 12);
    return `e${epoch}:${_b64uEnc(out)}`;
  } catch { return ''; }
}

async function dec(payload, code) {
  if (!payload) return '';
  try {
    if (payload.startsWith('e') && /^e\d+:/.test(payload)) {
      const colon = payload.indexOf(':');
      const epoch = parseInt(payload.slice(1, colon), 10);
      const raw   = _b64uDec(payload.slice(colon + 1));
      const key   = await _getEpochKey(code, epoch);
      const pt    = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12));
      const str   = await _decompress(new Uint8Array(pt));
      return _textDecode(str, code);
    }
    if (payload.startsWith('g:')) {
      const raw = _b64uDec(payload.slice(2));
      const key = await _deriveKey(code);
      const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12));
      return new TextDecoder().decode(pt);
    }
    const b64 = payload.replace(/-/g,'+').replace(/_/g,'/');
    const b = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const k = new TextEncoder().encode(code), o = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) o[i] = b[i] ^ k[i % k.length];
    return new TextDecoder().decode(o);
  } catch { return '[encrypted]'; }
}

async function encBytes(file, code) {
  try {
    const epoch = _roomEpoch;
    const key   = await _getEpochKey(code, epoch);
    const iv    = crypto.getRandomValues(new Uint8Array(12));
    const ct    = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      await file.arrayBuffer()
    );
    const epochBuf = new Uint8Array(4);
    new DataView(epochBuf.buffer).setUint32(0, epoch, false);
    const out = new Uint8Array(4 + 12 + ct.byteLength);
    out.set(epochBuf, 0);
    out.set(iv, 4);
    out.set(new Uint8Array(ct), 16);
    let s = ''; const C = 8192;
    for (let i = 0; i < out.length; i += C) s += String.fromCharCode(...out.subarray(i, i + C));
    return 'b:' + btoa(s);
  } catch(e) { throw e; }
}

async function decBytes(b64full, mime, code) {
  try {
    if (b64full.startsWith('b:')) {
      const raw   = Uint8Array.from(atob(b64full.slice(2)), c => c.charCodeAt(0));
      const epoch = new DataView(raw.buffer, 0, 4).getUint32(0, false);
      const iv    = raw.slice(4, 16);
      const ct    = raw.slice(16);
      const key   = await _getEpochKey(code, epoch);
      const pt    = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      return new Blob([pt], { type: mime });
    }
    if (b64full.startsWith('g:')) {
      const raw = Uint8Array.from(atob(b64full.slice(2)), c => c.charCodeAt(0));
      const key = await _deriveKey(code);
      const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12));
      return new Blob([pt], { type: mime });
    }
    const raw = Uint8Array.from(atob(b64full), c => c.charCodeAt(0));
    const k   = new TextEncoder().encode(code), o = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) o[i] = raw[i] ^ k[i % k.length];
    return new Blob([o], { type: mime });
  } catch(e) { throw e; }
}

const _EC_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
const _EC_SIGN = { name: 'ECDSA', hash: 'SHA-256' };

async function initSigningKey() {
  try {
    const idb = await openIDB();
    const row = await new Promise((res, rej) => {
      const tx = idb.transaction('sigkey', 'readonly');
      const req = tx.objectStore('sigkey').get('my');
      req.onsuccess = () => res(req.result ?? null);
      req.onerror   = () => rej(req.error);
    });
    if (row?.priv && row?.pubB64) {
      _sigPrivKey = await crypto.subtle.importKey('pkcs8', _b64uDec(row.priv), _EC_ALGO, false, ['sign']);
      _pubKeyB64  = row.pubB64;
      return;
    }
    const kp      = await crypto.subtle.generateKey(_EC_ALGO, true, ['sign', 'verify']);
    const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
    const pubRaw  = await crypto.subtle.exportKey('spki',  kp.publicKey);
    const privB64 = _b64uEnc(privRaw);
    const pubB64  = _b64uEnc(pubRaw);
    _sigPrivKey   = await crypto.subtle.importKey('pkcs8', privRaw, _EC_ALGO, false, ['sign']);
    _pubKeyB64    = pubB64;
    await new Promise((res, rej) => {
      const tx  = idb.transaction('sigkey', 'readwrite');
      const req = tx.objectStore('sigkey').put({ id: 'my', priv: privB64, pubB64 });
      req.onsuccess = res; req.onerror = rej;
    });
  } catch (e) {

    _sigPrivKey = null; _pubKeyB64 = null;
  }
}

async function signMsg(senderId, ts, encText) {
  if (!_sigPrivKey) return null;
  try {
    const buf = new TextEncoder().encode(`${senderId}|${ts}|${encText}`);
    const sig = await crypto.subtle.sign(_EC_SIGN, _sigPrivKey, buf);
    return _b64uEnc(sig);
  } catch (e) {  return null; }
}

async function verifyMsg(sig, senderId, ts, encText, pubKeyB64) {
  if (!sig || !pubKeyB64) return 'unsigned';
  try {
    const key = await _importPubKey(pubKeyB64);
    const buf = new TextEncoder().encode(`${senderId}|${ts}|${encText}`);
    const ok  = await crypto.subtle.verify(_EC_SIGN, key, _b64uDec(sig), buf);
    return ok ? 'verified' : 'failed';
  } catch { return 'failed'; }
}

const _importedPubKeys = new Map();
async function _importPubKey(b64) {
  if (_importedPubKeys.has(b64)) return _importedPubKeys.get(b64);
  const key = await crypto.subtle.importKey('spki', _b64uDec(b64), _EC_ALGO, false, ['verify']);
  _importedPubKeys.set(b64, key);
  return key;
}

async function getPubKey(uid) {
  if (uid === state.me?.id) return _pubKeyB64;
  if (_pubKeyCache.has(uid)) return _pubKeyCache.get(uid);
  try {
    const idb = await openIDB();
    const row = await new Promise((res) => {
      const tx  = idb.transaction('pubkeys', 'readonly');
      const req = tx.objectStore('pubkeys').get(uid);
      req.onsuccess = () => res(req.result ?? null);
      req.onerror   = () => res(null);
    });
    if (row?.pubB64) { _pubKeyCache.set(uid, row.pubB64); return row.pubB64; }
  } catch {}
  if (!state.roomCode) return null;
  try {
    const snap   = await db.collection('rooms').doc(state.roomCode).collection('members').doc(uid).get();
    const pubB64 = snap.data()?.pubKey ?? null;
    if (pubB64) { _pubKeyCache.set(uid, pubB64); _cachePubKeyIDB(uid, pubB64); }
    return pubB64;
  } catch { return null; }
}

async function _cachePubKeyIDB(uid, pubB64) {
  try {
    const idb = await openIDB();
    await new Promise((res, rej) => {
      const tx  = idb.transaction('pubkeys', 'readwrite');
      const req = tx.objectStore('pubkeys').put({ uid, pubB64 });
      req.onsuccess = res; req.onerror = rej;
    });
  } catch {}
}

async function verifyAndBadge(data, docId) {
  if (!data.sig) return;
  const wrap = document.querySelector(`.msg-wrapper[data-doc-id="${CSS.escape(docId)}"]`);
  if (!wrap) return;
  const pubB64 = await getPubKey(data.senderId);
  const result = await verifyMsg(data.sig, data.senderId, data.ts, data.enc, pubB64);
  if (result === 'failed') {
    wrap.style.display = 'none';
    wrap.setAttribute('data-sig-blocked', '1');
  }
}

const $  = id  => document.getElementById(id);
const qs = sel => document.querySelector(sel);

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ══════════════════════════════════════════════════
   DEFENCE 1 — ENTROPY METER
   Scores room codes on character variety + length.
   Shown only on the CREATE tab, not on join.
   Score 0-4: Very Weak / Weak / Fair / Strong / Very Strong

   Side-effect: users with scores < 2 are blocked from
   creating rooms. They can still JOIN existing weak rooms
   (we don't control what codes others created before).
══════════════════════════════════════════════════ */
function calcEntropy(code) {
  if (!code) return 0;
  let pool = 0;
  if (/[a-z]/.test(code)) pool += 26;
  if (/[A-Z]/.test(code)) pool += 26;
  if (/[0-9]/.test(code)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(code)) pool += 32;

  // Penalise repeated characters e.g. "aaaaaaaaaa"
  const unique = new Set(code).size;
  const diversity = unique / code.length;  // 1 = all unique, 0.1 = very repetitive

  // Bits of entropy approximation
  const bits = code.length * Math.log2(pool || 1) * diversity;

  // Score 0–4
  if (bits < 28) return 0;   // Very Weak  — most PINs, short words
  if (bits < 40) return 1;   // Weak       — phone numbers, "password1"
  if (bits < 55) return 2;   // Fair       — "MySecret99"
  if (bits < 70) return 3;   // Strong     — "Horse#Correct7"
  return 4;                   // Very Strong
}

const _ENTROPY_META = [
  { label: 'VERY WEAK',   color: '#ff4444', width: '15%'  },
  { label: 'WEAK',        color: '#ff8800', width: '30%'  },
  { label: 'FAIR',        color: '#fcc419', width: '55%'  },
  { label: 'STRONG',      color: '#51cf66', width: '78%'  },
  { label: 'VERY STRONG', color: '#2dd4bf', width: '100%' },
];

function updateEntropyMeter(code) {
  const wrap  = $('entropy-wrap');
  const fill  = $('entropy-fill');
  const label = $('entropy-label');
  if (!wrap || !fill || !label) return;

  if (!code) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'flex';

  const score = calcEntropy(code);
  const meta  = _ENTROPY_META[score];
  fill.style.width      = meta.width;
  fill.style.background = meta.color;
  label.textContent     = meta.label;
  label.style.color     = meta.color;
}

/* ══════════════════════════════════════════════════
   DEFENCE 2 — RATE LIMITER (client-side)
   Prevents automated scripts from hammering room
   creation/join in a tight loop from your app.
   Does NOT stop direct REST API abuse — that needs
   Firebase App Check. This guards the UI only.

   Side-effect: a user who fat-fingers the join button
   3 times quickly will see "Too many attempts" and
   must wait 30 seconds. Rare in practice.
══════════════════════════════════════════════════ */
const _createRl = { count: 0, resetAt: 0 };
const _enterRl  = { count: 0, resetAt: 0, wrongCount: 0, lockedUntil: 0 };

/* How many wrong codes allowed before lockout */
const WRONG_CODE_LIMIT = 5;

/* Live countdown timer handle */
let _countdownTimer = null;

function checkRateLimit(type) {
  const rl  = type === 'enter' ? _enterRl : _createRl;
  const now = Date.now();
  const window_ms = type === 'enter' ? 60000 : 30000;
  const max       = 5;
  if (now > rl.resetAt) { rl.count = 0; rl.resetAt = now + window_ms; }
  rl.count++;
  if (rl.count > max) {
    const wait = Math.ceil((rl.resetAt - now) / 1000);
    showError(`Too many attempts — please wait ${wait}s`);
    return false;
  }
  return true;
}

function _startCountdown(ms) {
  if (_countdownTimer) { clearInterval(_countdownTimer); _countdownTimer = null; }
  const endTime = Date.now() + ms;

  function _tick() {
    const remaining = Math.ceil((endTime - Date.now()) / 1000);
    if (remaining <= 0) {
      clearInterval(_countdownTimer);
      _countdownTimer = null;
      const errEl = $('join-error') || $('invite-error');
      const cdEl  = $('nx-countdown');
      if (errEl) errEl.textContent = '';
      if (cdEl)  cdEl.remove();
      const btn = qs('#tab-enter .btn-join') || $('invite-join-btn');
      if (btn) { btn.disabled = false; if (btn.querySelector('span')) btn.querySelector('span').textContent = btn.id === 'invite-join-btn' ? 'JOIN ROOM' : 'ENTER ROOM'; }
      return;
    }
    const mins    = Math.floor(remaining / 60);
    const secs    = remaining % 60;
    const timeStr = mins > 0 ? `${mins}m ${String(secs).padStart(2,'0')}s` : `${secs}s`;

    let cdEl = $('nx-countdown');
    if (!cdEl) {
      cdEl = document.createElement('div');
      cdEl.id = 'nx-countdown';
      cdEl.style.cssText = [
        'display:flex','align-items:center','justify-content:center','gap:10px',
        'margin-top:10px','padding:12px 16px',
        'background:rgba(255,80,80,0.08)','border:1px solid rgba(255,80,80,0.25)',
        'border-radius:var(--r)','font-family:var(--font-mono)','font-size:0.78rem',
        'color:var(--danger)','letter-spacing:1px',
        'animation:nx-morph-in 0.3s ease both'
      ].join(';');
      const errEl = $('join-error') || $('invite-error');
      if (errEl) errEl.insertAdjacentElement('afterend', cdEl);
    }
    cdEl.innerHTML =
      '<svg viewBox="0 0 20 20" fill="none" width="14" height="14" style="flex-shrink:0">' +
        '<circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5"/>' +
        '<path d="M10 6v4l2.5 2.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
      '</svg>' +
      'Too many wrong attempts — try again in <strong style="margin-left:4px">' + timeStr + '</strong>';

    const btn = qs('#tab-enter .btn-join') || $('invite-join-btn');
    if (btn) btn.disabled = true;
  }

  _tick();
  _countdownTimer = setInterval(_tick, 500);
}

function _recordWrongCode() {
  const now = Date.now();
  _enterRl.wrongCount++;

  /* Still under the limit — show attempts remaining */
  if (_enterRl.wrongCount < WRONG_CODE_LIMIT) {
    const left = WRONG_CODE_LIMIT - _enterRl.wrongCount;
    showError(`Wrong code — ${left} attempt${left !== 1 ? 's' : ''} remaining`);
    return;
  }

  /* Hit the limit — exponential backoff + live countdown */
  const backoffIndex = _enterRl.wrongCount - WRONG_CODE_LIMIT;
  const waitMs = Math.min(30000 * Math.pow(2, backoffIndex), 8 * 60 * 1000);
  _enterRl.lockedUntil = now + waitMs;
  _enterRl.resetAt     = now + waitMs;
  _enterRl.count       = 999;

  const errEl = $('join-error') || $('invite-error');
  if (errEl) errEl.textContent = '';
  _startCountdown(waitMs);
}

function _checkEnterLock() {
  const now = Date.now();
  if (_enterRl.lockedUntil > now) {
    const remaining = _enterRl.lockedUntil - now;
    if (!_countdownTimer) _startCountdown(remaining);
    return false;
  }
  return true;
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts), n = new Date();
  return d.toDateString() === n.toDateString()
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}
function fmtBytes(b) {
  return b < 1024 ? b + ' B' : b < 1048576 ? (b/1024).toFixed(1) + ' KB' : (b/1048576).toFixed(1) + ' MB';
}
function ts_now() { return firebase.firestore.FieldValue.serverTimestamp(); }

/* ──────────────────────────────────────────
   AVATAR
────────────────────────────────────────── */
const AV_COLORS = ['#2dd4bf','#06b6d4','#3b82f6','#8b5cf6','#ec4899','#f43f5e','#f97316','#eab308','#22c55e','#14b8a6','#6366f1','#a855f7'];
const REACTION_EMOJIS = ['👍','❤️','😂','😮','😢','🔥','👀','🎉'];
function avatarColor(s) { let h=0; for(const c of s) h=(h*31+c.charCodeAt(0))&0xffffffff; return AV_COLORS[Math.abs(h)%AV_COLORS.length]; }
function initials(n)     { return n.trim().split(/\s+/).map(w=>w[0]?.toUpperCase()||'').join('').slice(0,2)||'??'; }

/* ──────────────────────────────────────────
   CALLSIGN / UID
────────────────────────────────────────── */
const _A=['DARK','FAST','COLD','BOLD','VOID','NEON','GREY','IRON','WILD','FLUX'];
const _N=['FOX','OWL','RAY','ACE','SKY','KAI','ZEN','MAX','REX','DOT'];
function genCallsign() { return `${_A[Math.random()*_A.length|0]} ${_N[Math.random()*_N.length|0]}${(Math.random()*90+10)|0}`; }
function getUID() {
  let id = localStorage.getItem('nx_uid');
  if (!id) { id = 'u'+Date.now().toString(36)+Math.random().toString(36).slice(2,7); localStorage.setItem('nx_uid',id); }
  return id;
}

/* ──────────────────────────────────────────
   PERSIST
────────────────────────────────────────── */
function saveSession() { localStorage.setItem(CONFIG.SESSION_KEY, JSON.stringify(state.me)); }
function loadSession() { try { return JSON.parse(localStorage.getItem(CONFIG.SESSION_KEY)); } catch { return null; } }
function saveRoom(c)   { localStorage.setItem(CONFIG.ROOM_KEY, c); }
function loadRoom()    { return localStorage.getItem(CONFIG.ROOM_KEY); }

/* ══════════════════════════════════════════════════
   INIT
══════════════════════════════════════════════════ */
window.addEventListener('DOMContentLoaded', () => {
  getUID();

  // Prefs
  try {
    const p = JSON.parse(localStorage.getItem(CONFIG.PREFS_KEY) || '{}');
    Object.assign(state.prefs, p);
  } catch {}

  // Open IDB (non-blocking)
  openIDB().catch(() => {});
  // Firebase init — wrapped so a failure doesn't kill the splash timer
  try {
    firebase.initializeApp(FIREBASE_CONFIG);
    db = firebase.firestore();
  } catch (e) {
    // Already initialized (e.g. hot-reload) — grab the existing instance
    try {
      db = firebase.app().firestore();

    } catch (e2) {

      // Splash will still hide and show join screen; Firestore calls will fail gracefully
    }
  }

  // Ripple
  document.addEventListener('touchstart', handleRipple, { passive: true });
  document.addEventListener('mousedown',  handleRipple);

  document.addEventListener('copy',        e => { if (!e.target.closest('input,textarea')) e.preventDefault(); });
  document.addEventListener('cut',         e => { if (!e.target.closest('input,textarea')) e.preventDefault(); });
  document.addEventListener('contextmenu', e => { if (!e.target.closest('input,textarea,.msg-bubble')) e.preventDefault(); });
  document.addEventListener('selectstart', e => { if (!e.target.closest('input,textarea')) e.preventDefault(); });

  // Sidebar setup
  setupSidebar();
  setupActionBtn();
  setupClipboardPaste();

  // Restore saved name
  const saved = localStorage.getItem('nx_name');
  if (saved) { const el = $('input-name'); if (el) el.value = saved; }

  // Splash → session restore.
  // Always fires after 1800ms regardless of Firebase state.
  setTimeout(() => {
    hideSplash();
    const inviteCode = _detectInviteParam();
    if (inviteCode) {
      showInviteScreen();
      return;
    }
    const me = loadSession(), room = loadRoom();
    if (me?.id && room) { state.me = me; state.roomCode = room; checkApprovalAndBoot(); }
    else showScreen('join-screen');
  }, 1800);
});

function hideSplash() { $('splash')?.classList.remove('active'); }
function showScreen(id) {
  const next = $(id);
  if (!next) return;
  // Morph-exit the currently active screen
  document.querySelectorAll('.screen.active').forEach(s => {
    if (s.id === id) return;
    s.classList.add('morph-exit');
    s.classList.remove('active');
    setTimeout(() => s.classList.remove('morph-exit'), 350);
  });
  // Small delay so exit animation registers before enter
  requestAnimationFrame(() => {
    next.classList.add('active');
    // Re-trigger nx-anim children so stagger replays each time
    next.querySelectorAll('.nx-anim').forEach(el => {
      el.style.animation = 'none';
      el.style.opacity   = '';
      requestAnimationFrame(() => { el.style.animation = ''; });
    });
  });
}

/* ══════════════════════════════════════════════════
   SIDEBAR — completely rewritten
   Mobile (≤640): fixed position, starts off-screen,
     slides in to translateX(0). Overlay fades in/out
     using visibility+opacity (NOT display — that breaks transitions).
   Desktop (>640): always in flex layout, no overlay.
══════════════════════════════════════════════════ */
function setupSidebar() {
  // Inject overlay element
  if (!$('sidebar-overlay')) {
    const ov = document.createElement('div');
    ov.id = 'sidebar-overlay';
    document.body.appendChild(ov);
  }
  const ov = $('sidebar-overlay');
  ov.addEventListener('click',      closeSidebar);
  ov.addEventListener('touchend',   e => { e.preventDefault(); closeSidebar(); }, { passive: false });

  // Inject hamburger into chat-header
  const header = $('chat-header');
  if (header && !$('hamburger-btn')) {
    const ham = document.createElement('button');
    ham.id = 'hamburger-btn';
    ham.className = 'icon-btn hamburger-btn';
    ham.setAttribute('aria-label', 'Open menu');
    ham.innerHTML = `<svg viewBox="0 0 20 20" fill="none" width="18" height="18">
      <path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
    </svg>`;
    ham.addEventListener('click', e => { e.stopPropagation(); _sidebarOpen ? closeSidebar() : openSidebar(); });
    header.insertBefore(ham, header.firstChild);
  }

  // Swipe gestures
  let _tx = 0, _ty = 0, _skipSwipe = false;
  document.addEventListener('touchstart', e => {
    _tx = e.touches[0].clientX;
    _ty = e.touches[0].clientY;
    _skipSwipe = !!e.target.closest('button,input,textarea,a,label,.member-item');
  }, { passive: true });
  document.addEventListener('touchend', e => {
    if (_skipSwipe) return;
    const dx = e.changedTouches[0].clientX - _tx;
    const dy = e.changedTouches[0].clientY - _ty;
    if (Math.abs(dy) > Math.abs(dx) * 1.3 || Math.abs(dx) < 44) return;
    if (dx > 0 && _tx < 24 && !_sidebarOpen)  openSidebar();
    if (dx < 0 && _sidebarOpen)               closeSidebar();
  }, { passive: true });
}

function openSidebar() {
  if (window.innerWidth > 640) return;
  _sidebarOpen = true;
  $('sidebar')?.classList.add('open');
  document.body.classList.add('sidebar-active');
  const main = $('main-area');
  if (main) { main.style.pointerEvents = 'none'; main.setAttribute('inert', ''); }
  $('sidebar-overlay')?.classList.add('active');
}

function closeSidebar() {
  _sidebarOpen = false;
  $('sidebar')?.classList.remove('open');
  document.body.classList.remove('sidebar-active');
  const main = $('main-area');
  if (main) { main.style.pointerEvents = ''; main.removeAttribute('inert'); }
  $('sidebar-overlay')?.classList.remove('active');
}

/* ══════════════════════════════════════════════════
   JOIN SCREEN
══════════════════════════════════════════════════ */
function switchJoinTab(tab) {
  document.querySelectorAll('.join-tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.join-tab-panel').forEach(p => p.classList.remove('active'));
  qs(`.join-tab-btn[data-tab="${tab}"]`)?.classList.add('active');
  $(`tab-${tab}`)?.classList.add('active');
}

function resolveName() {
  const typed = ($('input-name')?.value || '').trim();
  if (typed) { localStorage.setItem('nx_name', typed); return typed; }
  let anon = localStorage.getItem('nx_anon');
  if (!anon) { anon = genCallsign(); localStorage.setItem('nx_anon', anon); }
  return anon;
}

/* ══════════════════════════════════════════════════
   CREATE ROOM
══════════════════════════════════════════════════ */
async function handleCreate() {
  if (!checkRateLimit('create')) return;
  const code = ($('input-create-code')?.value || '').trim();
  if (!code) { showError('Please enter a room code — it becomes your encryption key'); return; }

  // Minimum length defence — 6 chars minimum
  if (code.length < 6) {
    showError('Code must be at least 6 characters');
    return;
  }

  // Entropy gate — block codes that are too weak even if long
  const score = calcEntropy(code);
  if (score < 2) {
    showError('Code is too weak — add numbers, symbols, or mixed case');
    return;
  }

  const btn = qs('#tab-create .btn-join');
  setLoading(btn, true, 'CREATING...');
  try {
    await db.collection('rooms').doc(code).set({
      createdAt: ts_now(), creatorId: getUID(), epoch: 0,
    }, { merge: true });
    _roomEpoch = 0;
    state.me = buildMe(resolveName()); state.roomCode = code;
    saveSession(); saveRoom(code);
    await registerPresence('admin', true);
    await sendSys(`${state.me.name} created this room`);
    bootApp();
    showRoomConfigPopup();
  } catch (e) { showError('Could not create room. Check your internet.'); }
  finally { setLoading(btn, false); }
}

/* ══════════════════════════════════════════════════
   ENTER ROOM
══════════════════════════════════════════════════ */
async function handleEnter() {
  if (!_checkEnterLock()) return;
  if (!checkRateLimit('enter')) return;
  const code = ($('input-room-code')?.value || '').trim();
  if (!code) { showError('Enter the room code'); return; }

  const btn = qs('#tab-enter .btn-join');
  setLoading(btn, true, 'CONNECTING...');
  try {
    const roomSnap = await db.collection('rooms').doc(code).get();
    if (!roomSnap.exists) {
      _recordWrongCode();
      return;
    }
    _enterRl.wrongCount = 0;
    _enterRl.lockedUntil = 0;
    _roomEpoch = roomSnap.data()?.epoch || 0;

    const uid         = getUID();
    const memberSnap  = await db.collection('rooms').doc(code).collection('members').doc(uid).get();
    const prevData    = memberSnap.exists ? memberSnap.data() : null;
    const wasApproved = prevData?.approved === true;

    state.me = buildMe(resolveName()); state.roomCode = code;
    saveSession(); saveRoom(code);

    if (wasApproved) {
      // Returning approved member — skip the queue
      const role = prevData.role || 'member';
      await registerPresence(role, true);
      await sendSys(`${state.me.name} rejoined the room`);
      bootApp();
    } else {
      // D7: check if the room has approval required (stored on room doc)
      const roomData          = roomSnap.data();
      const approvalRequired  = roomData?.approvalRequired === true;

      if (approvalRequired) {
        // Gate — register as pending and show waiting screen
        await registerPresence('member', false);
        showWaitingScreen();
      } else {
        // Open room — approve immediately and boot
        await registerPresence('member', true);
        await sendSys(`${state.me.name} joined the room`);
        bootApp();
      }
    }
  } catch (e) { showError('Connection error. Check your internet.'); }
  finally { setLoading(btn, false); }
}

function buildMe(name) {
  return { id: getUID(), name, color: avatarColor(name), joinedAt: Date.now() };
}

async function registerPresence(role = 'member', approved = false) {
  // Ensure signing key exists before publishing public key to Firestore
  await initSigningKey();
  await db.collection('rooms').doc(state.roomCode)
    .collection('members').doc(state.me.id)
    .set({
      name:     state.me.name,
      color:    state.me.color,
      online:   true,
      joinedAt: ts_now(),
      pubKey:   _pubKeyB64 ?? null,   // D3: ECDSA public key for message verification
      role,                            // D7: 'admin' | 'member'
      approved,                        // D7: false until an admin approves
    });
  state.me.role     = role;
  state.me.approved = approved;
}

/* ══════════════════════════════════════════════════
   BOOT
══════════════════════════════════════════════════ */
function bootApp() {
  _renderedIds.clear();
  _lastCachedTs    = 0;
  _onlineCount     = 0;
  _presenceSettled = false;  // reset — first snapshot must not trigger wipe
  _isAdmin         = state.me?.role === 'admin';

  // Update UI
  ['chat-name','room-code-pill','welcome-room-name'].forEach(id => {
    const el = $(id); if (el) el.textContent = state.roomCode;
  });
  const nsb = $('my-name-sidebar');   if (nsb) nsb.textContent = state.me.name;
  const av  = $('my-avatar-sidebar');
  if (av) { av.textContent = initials(state.me.name); av.style.background = state.me.color; }

  // D7: show admin badge in sidebar profile
  updateAdminBadge();

  showScreen('app');

  // Set solo hint code
  const sc = $('solo-code'); if (sc) sc.textContent = state.roomCode;

  // Load IDB cache instantly, then fetch history from Firestore
  loadCachedMessages();

  // Start ALL listeners immediately — no gating on user count
  startPresenceListener();
  startChatListeners();
  startRoomListener();
  startHeartbeat();
  initScrollFab();
  toast('Joined room', state.roomCode, '✓');
}

/* ══════════════════════════════════════════════════
   D7 — ADMIN GATING SYSTEM
   ─────────────────────────────────────────────────
   Flow for new member:
     1. registerPresence(role='member', approved=false)
     2. showWaitingScreen() — no messages, no chat
     3. startApprovalListener() — watches own member doc
     4. Admin sees pending badge → taps Approve
     5. Member doc → approved:true → listener fires
     6. bootApp() runs — full chat access granted

   Flow for admin:
     • renderMembers() shows PENDING section
     • Approve → approveUser() sets approved:true
     • Decline → declineUser() sets declined:true
     • Promote → promoteToAdmin() sets role:'admin'
     • Promoted member's presence listener updates _isAdmin live
══════════════════════════════════════════════════ */

/* ── Session restore approval check ─────────────── */
async function checkApprovalAndBoot() {
  try {
    const roomSnap = await db.collection('rooms').doc(state.roomCode).get();
    if (roomSnap.exists) _roomEpoch = roomSnap.data()?.epoch || 0;

    const snap = await db.collection('rooms').doc(state.roomCode)
      .collection('members').doc(state.me.id).get();

    if (!snap.exists) {
      // Room wiped or member doc gone — go back to join
      showScreen('join-screen'); return;
    }
    const data = snap.data();
    state.me.role     = data.role     || 'member';
    state.me.approved = data.approved || false;

    if (data.approved) {
      // Re-mark online before starting listeners so presence listener
      // doesn't see count=0 and trigger wipeRoom on the first snapshot.
      await db.collection('rooms').doc(state.roomCode)
        .collection('members').doc(state.me.id)
        .update({ online: true }).catch(() => {});
      bootApp();
    } else if (data.declined) {
      // Was declined while offline
      localStorage.removeItem(CONFIG.SESSION_KEY);
      localStorage.removeItem(CONFIG.ROOM_KEY);
      state.me = null; state.roomCode = null;
      showScreen('join-screen');
      setTimeout(() => showError('Your previous join request was declined'), 400);
    } else {
      // Still pending — re-register as online and resume waiting
      await registerPresence('member', false);
      showWaitingScreen();
    }
  } catch(e) {

    // Mark online best-effort; if offline this fails silently
    if (state.roomCode && state.me?.id) {
      db.collection('rooms').doc(state.roomCode)
        .collection('members').doc(state.me.id)
        .update({ online: true }).catch(() => {});
    }
    bootApp();
  }
}

/* ── Waiting screen ──────────────────────────────── */
function showWaitingScreen() {
  const wa = $('waiting-avatar'), wn = $('waiting-name'), wr = $('waiting-room-code');
  if (wa) { wa.textContent = initials(state.me.name); wa.style.background = state.me.color; }
  if (wn) wn.textContent = state.me.name;
  if (wr) wr.textContent = state.roomCode;
  showScreen('waiting-screen');
  startHeartbeat();
  startApprovalListener();
}

/* ── Approval listener — runs only while pending ─── */
function startApprovalListener() {
  if (_unsubApproval) { try { _unsubApproval(); } catch {} }

  _unsubApproval = db.collection('rooms').doc(state.roomCode)
    .collection('members').doc(state.me.id)
    .onSnapshot(snap => {
      if (!snap.exists) { handleDeclined('Room closed or request removed.'); return; }
      const data = snap.data();
      if (data.declined) { handleDeclined('Your request to join was declined.'); return; }
      if (data.approved) {
        // ✓ Approved — clean up and boot into the chat
        if (_unsubApproval) { try { _unsubApproval(); } catch {} _unsubApproval = null; }
        state.me.role     = data.role     || 'member';
        state.me.approved = true;
        saveSession();
        sendSys(`${state.me.name} joined the room`).catch(() => {});
        bootApp();
      }
    }, () => {});
}

function handleDeclined(msg = 'Request declined.') {
  if (_unsubApproval) { try { _unsubApproval(); } catch {} _unsubApproval = null; }
  clearInterval(_heartbeat);
  localStorage.removeItem(CONFIG.SESSION_KEY);
  localStorage.removeItem(CONFIG.ROOM_KEY);
  state.me = null; state.roomCode = null;
  showScreen('join-screen');
  setTimeout(() => showError(msg), 300);
}

async function cancelJoinRequest() {
  if (_unsubApproval) { try { _unsubApproval(); } catch {} _unsubApproval = null; }
  clearInterval(_heartbeat);
  if (state.roomCode && state.me?.id) {
    await db.collection('rooms').doc(state.roomCode)
      .collection('members').doc(state.me.id)
      .update({ online: false }).catch(() => {});
  }
  localStorage.removeItem(CONFIG.SESSION_KEY);
  localStorage.removeItem(CONFIG.ROOM_KEY);
  state.me = null; state.roomCode = null;
  showScreen('join-screen');
}

/* ── Admin actions ───────────────────────────────── */
async function approveUser(uid, name) {
  if (!_isAdmin || !state.roomCode) return;
  try {
    await db.collection('rooms').doc(state.roomCode)
      .collection('members').doc(uid)
      .update({ approved: true });
    // Don't send system message here — the newly approved user sends it on their side (bootApp)
    toast(`${name} approved`, 'They can now see the chat.', '✓');
  } catch(e) { toast('Approval failed', e.message, '✗'); }
}

async function declineUser(uid, name) {
  if (!_isAdmin || !state.roomCode) return;
  const ok = await showConfirm(`Decline ${name}?`, 'They will be removed from the room.', 'DECLINE');
  if (!ok) return;
  try {
    await db.collection('rooms').doc(state.roomCode)
      .collection('members').doc(uid)
      .update({ online: false, declined: true });
    toast(`${name} was declined`, '', '✗');
  } catch(e) { toast('Decline failed', e.message, '✗'); }
}

async function promoteToAdmin(uid, name) {
  if (!_isAdmin || !state.roomCode) return;
  const ok = await showConfirm(
    `Promote ${name} to Admin?`,
    'They will be able to approve and decline new members.',
    'PROMOTE'
  );
  if (!ok) return;
  try {
    await db.collection('rooms').doc(state.roomCode)
      .collection('members').doc(uid)
      .update({ role: 'admin' });
    await sendSys(`${name} was promoted to admin ◆`);
    toast(`${name} is now Admin`, '', '◆');
  } catch(e) { toast('Promotion failed', e.message, '✗'); }
}

/* ── Admin UI helpers ───────────────────────────── */
function updateAdminBadge() {
  const badge = $('my-admin-badge');
  if (!badge) return;
  badge.style.display = _isAdmin ? 'flex' : 'none';
}

function showRoomConfigPopup() {
  const ov = document.createElement('div');
  ov.id = 'room-config-popup';
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.8);backdrop-filter:blur(8px);z-index:9999;display:flex;align-items:center;justify-content:center;padding:24px;animation:nx-morph-in .38s cubic-bezier(0.22,1,0.36,1) both';
  ov.innerHTML = `
    <div class="room-config-box">
      <div class="room-config-header">
        <svg viewBox="0 0 20 20" fill="none" width="18" height="18">
          <rect x="3" y="9" width="14" height="9" rx="2" stroke="var(--teal)" stroke-width="1.5"/>
          <path d="M7 9V6a3 3 0 016 0v3" stroke="var(--teal)" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
        <div>
          <div class="room-config-title">Room Created</div>
          <div class="room-config-code">${esc(state.roomCode)}</div>
        </div>
      </div>
      <p class="room-config-desc">Configure who can join this room.</p>
      <div class="room-config-option" id="rco-open">
        <div class="rco-radio selected" id="rco-open-dot"></div>
        <div class="rco-label">
          <div class="rco-title">Open Room</div>
          <div class="rco-sub">Anyone with the code can join instantly.</div>
        </div>
      </div>
      <div class="room-config-option" id="rco-gated">
        <div class="rco-radio" id="rco-gated-dot"></div>
        <div class="rco-label">
          <div class="rco-title">Approval Gate</div>
          <div class="rco-sub">You must approve each person before they can see the chat.</div>
        </div>
      </div>
      <button class="room-config-btn ripple-btn" id="room-config-confirm">
        OPEN ROOM
      </button>
    </div>`;

  let gated = false;
  const openOpt  = ov.querySelector('#rco-open');
  const gateOpt  = ov.querySelector('#rco-gated');
  const openDot  = ov.querySelector('#rco-open-dot');
  const gateDot  = ov.querySelector('#rco-gated-dot');
  const confirmBtn = ov.querySelector('#room-config-confirm');

  const select = (isGated) => {
    gated = isGated;
    openDot.classList.toggle('selected', !isGated);
    gateDot.classList.toggle('selected',  isGated);
    confirmBtn.textContent = isGated ? 'ENABLE APPROVAL GATE' : 'OPEN ROOM';
  };

  openOpt.addEventListener('click', () => select(false));
  gateOpt.addEventListener('click', () => select(true));

  confirmBtn.addEventListener('click', async () => {
    if (gated) {
      await db.collection('rooms').doc(state.roomCode)
        .update({ approvalRequired: true }).catch(() => {});
      toast('Approval gate enabled', 'New members must be approved.', '🔒');
    }
    ov.remove();
  });

  document.body.appendChild(ov);
}

function startRoomListener() {
  if (_unsubRoom) { try { _unsubRoom(); } catch {} _unsubRoom = null; }
  _unsubRoom = db.collection('rooms').doc(state.roomCode)
    .onSnapshot(snap => {
      if (!snap.exists) return;
      const newEpoch = snap.data()?.epoch || 0;
      if (newEpoch > _roomEpoch) {
        _roomEpoch = newEpoch;
        toast('Encryption key rotated', `Epoch ${newEpoch} — new messages use a fresh key`, '🔑');
      }
    }, () => {});
}

async function rotateKey() {
  if (!_isAdmin || !state.roomCode) return;
  const ok = await showConfirm(
    'Rotate Encryption Key?',
    'Future messages will use a freshly derived key. Old messages remain readable with their original key. All members will be notified.',
    'ROTATE'
  );
  if (!ok) return;
  const newEpoch = _roomEpoch + 1;
  try {
    await db.collection('rooms').doc(state.roomCode).update({ epoch: newEpoch });
    _roomEpoch = newEpoch;
    await sendSys(`🔑 The encryption key was rotated — epoch ${newEpoch} is now active`);
    toast('Key rotated', `Epoch ${newEpoch} now active`, '🔑');
  } catch(e) { toast('Rotation failed', e.message, '✗'); }
}

/* ══════════════════════════════════════════════════
   PHASE 1 — IDB CACHE (instant, zero network)
   PHASE 2 — ONE-TIME FIRESTORE HISTORY FETCH
     Uses .get() (not onSnapshot) so it counts as a
     single batch read, not an open listener.
     Runs regardless of online count — history is always
     visible to anyone who joins, even if alone.
     After this, _lastCachedTs is set so the live
     listener (started at count ≥ 2) only fetches NEW.
══════════════════════════════════════════════════ */
async function loadCachedMessages() {
  const code = state.roomCode;

  // ── Phase 1: render from IDB instantly ──────────
  try {
    const cached = await loadCached(code);
    if (cached.length) {
      $('room-welcome')?.style && ($('room-welcome').style.display = 'none');
      cached.forEach(row => {
        _renderedIds.add(row.id);
        renderMsg(row.data, row.id);
      });
      _lastCachedTs = cached.reduce((m, r) => Math.max(m, r.ts || 0), 0);
      scrollBottom();
    }
  } catch (e) {  }

  // ── Phase 2: one-time Firestore history fetch ───
  // Fetches only messages newer than what IDB already has.
  // For a brand-new user _lastCachedTs=0, so this gets everything.
  // For a returning user it only closes the gap since they were last here.
  fetchHistoryOnce(code);
}

async function fetchHistoryOnce(code) {
  try {
    let q = db.collection('rooms').doc(code)
              .collection('messages')
              .orderBy('createdAt', 'asc');
    if (_lastCachedTs > 0) {
      q = q.where('createdAt', '>', firebase.firestore.Timestamp.fromMillis(_lastCachedTs));
    }

    // .get() = one snapshot read, NOT a persistent listener
    const snap = await q.get();
    if (snap.empty) return;

    let hasNew = false;
    snap.forEach(doc => {
      if (_renderedIds.has(doc.id)) return;
      const data = doc.data();
      _renderedIds.add(doc.id);
      $('room-welcome')?.style && ($('room-welcome').style.display = 'none');
      renderMsg(data, doc.id);
      hasNew = true;
      // Cache each doc so we don't re-read next time
      cacheMsg(doc.id, code, data).catch(() => {});
      // Advance the high-water mark
      const docTs = data.ts || 0;
      if (docTs > _lastCachedTs) _lastCachedTs = docTs;
    });

    if (hasNew) scrollBottom();
  } catch (e) {
    // Non-fatal — live listener will catch up when count ≥ 2

  }
}

/* ══════════════════════════════════════════════════
   PRESENCE LISTENER — always active, lightweight.
   Only reads/writes: members subcollection.
   Triggers chat listener when count goes above 1.
══════════════════════════════════════════════════ */
function startPresenceListener() {
  const code = state.roomCode;
  if (_unsubMembers) _unsubMembers();

  _unsubMembers = db.collection('rooms').doc(code)
    .collection('members').where('online', '==', true)
    .onSnapshot(async snap => {
      _onlineCount = snap.size;

      // D7: notify admin of new pending users joining
      if (_isAdmin) {
        snap.docChanges().forEach(ch => {
          if (ch.type === 'added') {
            const d = ch.doc.data();
            if (!d.approved && ch.doc.id !== state.me?.id) {
              playSound('receive');
              toast(`${d.name || 'Someone'} wants to join`, 'Open the sidebar to approve them', '👤');
            }
          }
        });
      }

      updateOnlineUI();   // updateOnlineUI also called inside renderMembers with correct approved count
      renderMembers(snap);

      // Wipe empty room when last member leaves.
      // _presenceSettled guards against the very first snapshot firing before
      // the current user's online:true has propagated — without it, session
      // restore sees count=0 and wipes a perfectly healthy room.
      if (_presenceSettled && _onlineCount === 0 && state.me) {
        await wipeRoom(code);
        await clearCacheForRoom(code);
      }
      _presenceSettled = true;
    }, () => {});
}

function updateOnlineUI() {
  const oc = $('online-count');
  const ms = $('member-status-text');
  if (_onlineCount <= 1) {
    if (oc) oc.textContent = '';
    if (ms) ms.textContent = 'Only you are online';
  } else {
    if (oc) oc.textContent = _onlineCount;
    if (ms) ms.textContent = `${_onlineCount} members online`;
  }
}

/* ══════════════════════════════════════════════════
   CHAT LISTENERS — only active when ≥2 users online.
   By the time this runs, fetchHistoryOnce() has already
   loaded all history and set _lastCachedTs correctly.
   So this listener ONLY delivers messages sent AFTER
   the user joined — never re-reads history.
══════════════════════════════════════════════════ */
function startChatListeners() {
  const code = state.roomCode;

  // Messages — only NEW since history fetch set _lastCachedTs
  if (_unsubMsgs) _unsubMsgs();
  let q = db.collection('rooms').doc(code).collection('messages').orderBy('createdAt', 'asc');
  // Always filter by _lastCachedTs — fetchHistoryOnce ensures this is accurate.
  // Fall back to "last 5 minutes" if somehow still 0 to avoid a full re-read.
  const since = _lastCachedTs > 0 ? _lastCachedTs : (Date.now() - 5 * 60 * 1000);
  q = q.where('createdAt', '>', firebase.firestore.Timestamp.fromMillis(since));

  _unsubMsgs = q.onSnapshot(snap => {
    let hasNew = false;
    snap.docChanges().forEach(ch => {
      if (ch.type === 'modified') { patchMsg(ch.doc.id, ch.doc.data()); return; }
      if (ch.type !== 'added') return;
      const id = ch.doc.id, data = ch.doc.data();
      if (_renderedIds.has(id)) return;
      _renderedIds.add(id);
      $('room-welcome')?.style && ($('room-welcome').style.display = 'none');
      renderMsg(data, id);
      hasNew = true;
      const docTs = data.ts || 0;
      if (docTs > _lastCachedTs) _lastCachedTs = docTs;
      cacheMsg(id, code, data).catch(() => {});
      if (data.type === 'text' && data.senderId !== state.me?.id) {
        playSound('receive');
        if (document.hidden) {
          _unreadCount++;
          document.title = `(${_unreadCount}) NEXUS`;
        }
        showScrollFab();
      }
    });
    if (hasNew) scrollBottom();
  }, () => {});
  // Typing
  if (_unsubTyping) _unsubTyping();
  _unsubTyping = db.collection('rooms').doc(code).collection('typing')
    .onSnapshot(snap => {
      const now = Date.now(), typers = [];
      snap.forEach(doc => {
        if (doc.id === state.me?.id) return;
        const d = doc.data();
        if (now - (d.ts || 0) < CONFIG.TYPING_EXPIRE_MS) typers.push(d.name || 'Someone');
      });
      showTypingUI(typers);
    }, () => {});

  updateOnlineUI();
}

function stopChatListeners() {
  if (_unsubMsgs)    { try { _unsubMsgs();    } catch {} _unsubMsgs    = null; }
  if (_unsubTyping)  { try { _unsubTyping();  } catch {} _unsubTyping  = null; }
  clearMyTyping();
  showTypingUI([]);
}

/* ══════════════════════════════════════════════════
   FIRESTORE LISTENERS (legacy wrapper — now split above)
══════════════════════════════════════════════════ */
function startListeners() {
  startPresenceListener();
  startChatListeners();
}

function stopListeners() {
  stopChatListeners();
  if (_unsubMembers) { try { _unsubMembers(); } catch {} _unsubMembers = null; }
  if (_unsubRoom)    { try { _unsubRoom();    } catch {} _unsubRoom    = null; }
}

/* ──────────────────────────────────────────
   Typing UI
────────────────────────────────────────── */
function showTypingUI(typers) {
  const el = $('typing-indicator'), txt = $('typing-text');
  if (!el) return;
  if (!typers.length) {
    el.classList.remove('visible');
    setTimeout(() => { if (!el.classList.contains('visible')) el.style.display = 'none'; }, 300);
    return;
  }
  txt && (txt.textContent =
    typers.length === 1   ? `${typers[0]} is typing…` :
    typers.length === 2   ? `${typers[0]} and ${typers[1]} are typing…` :
                            `${typers.length} people are typing…`);
  el.style.display = 'flex';
  requestAnimationFrame(() => el.classList.add('visible'));
}

/* ──────────────────────────────────────────
   Members list
────────────────────────────────────────── */
function renderMembers(snap) {
  _memberNames = [];
  const list = $('members-list'); if (!list) return;
  list.innerHTML = '';

  const approved = [], pending = [];

  snap.forEach(doc => {
    const m = doc.data();
    if (m.pubKey) _pubKeyCache.set(doc.id, m.pubKey);

    // D7: Live-update own role if promoted while in the room
    if (doc.id === state.me?.id && m.role === 'admin' && !_isAdmin) {
      _isAdmin = true; state.me.role = 'admin'; saveSession();
      updateAdminBadge();
      toast('You are now an admin ◆', 'You can approve new members.', '◆');
    }

    if (m.approved) approved.push({ uid: doc.id, ...m });
    else            pending.push({ uid: doc.id, ...m });
  });

  // ── Approved members ───────────────────────────
  const approvedCount = approved.filter(m => m.uid !== state.me?.id || true).length;
  const oc = $('online-count'), ms = $('member-status-text');
  if (oc) oc.textContent = approvedCount <= 1 ? '' : approvedCount;
  if (ms) ms.textContent = approvedCount <= 1 ? 'Only you are online' : `${approvedCount} members online`;

  approved.forEach(m => {
    const isMe = m.uid === state.me?.id;
    if (!isMe) _memberNames.push(m.name);

    const div = document.createElement('div');
    div.className = 'member-item';
    div.innerHTML = `
      <div class="avatar-wrap">
        <div class="avatar" style="background:${esc(m.color||avatarColor(m.name))}">${esc(initials(m.name))}</div>
        <div class="status-dot online"></div>
      </div>
      <div class="member-info">
        <div class="member-name">
          ${m.role === 'admin' ? '<span class="admin-crown" title="Admin">◆</span> ' : ''}${esc(m.name)}${isMe ? '<span class="me-tag"> (you)</span>' : ''}
        </div>
        <div class="member-activity">● Online</div>
      </div>
      ${_isAdmin && !isMe && m.role !== 'admin' ? `
        <button class="member-promote-btn" title="Promote to Admin"
                data-uid="${esc(m.uid)}" data-name="${esc(m.name)}">
          <svg viewBox="0 0 20 20" fill="none" width="11" height="11">
            <path d="M10 3l1.8 5.5H17l-4.7 3.4 1.8 5.5L10 14l-4.1 3.4 1.8-5.5L3 8.5h5.2z"
                  stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
          </svg>
        </button>` : ''}`;

    div.querySelector('.member-promote-btn')?.addEventListener('click', e => {
      const b = e.currentTarget;
      promoteToAdmin(b.dataset.uid, b.dataset.name);
    });
    list.appendChild(div);
  });

  // ── Pending section (admins only) ──────────────
  if (_isAdmin && pending.length > 0) {
    const sep = document.createElement('div');
    sep.className = 'section-label pending-section-label';
    sep.innerHTML = `PENDING <span class="count-badge pending-badge">${pending.length}</span>`;
    list.appendChild(sep);

    pending.forEach(m => {
      const div = document.createElement('div');
      div.className = 'member-item pending-item';
      div.innerHTML = `
        <div class="avatar-wrap">
          <div class="avatar" style="background:${esc(m.color||avatarColor(m.name))}">${esc(initials(m.name))}</div>
          <div class="status-dot" style="background:var(--texting);box-shadow:0 0 5px var(--texting)"></div>
        </div>
        <div class="member-info">
          <div class="member-name">${esc(m.name)}</div>
          <div class="member-activity" style="color:var(--texting)">● Waiting</div>
        </div>
        <div class="pending-actions">
          <button class="pending-approve-btn" title="Approve"
                  data-uid="${esc(m.uid)}" data-name="${esc(m.name)}">
            <svg viewBox="0 0 20 20" fill="none" width="13" height="13">
              <path d="M4 10l4 4 8-8" stroke="currentColor" stroke-width="2"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </button>
          <button class="pending-decline-btn" title="Decline"
                  data-uid="${esc(m.uid)}" data-name="${esc(m.name)}">
            <svg viewBox="0 0 20 20" fill="none" width="13" height="13">
              <path d="M15 5L5 15M5 5l10 10" stroke="currentColor" stroke-width="2"
                    stroke-linecap="round"/>
            </svg>
          </button>
        </div>`;

      div.querySelector('.pending-approve-btn')?.addEventListener('click', e => {
        const b = e.currentTarget;
        approveUser(b.dataset.uid, b.dataset.name).catch(()=>{});
      });
      div.querySelector('.pending-decline-btn')?.addEventListener('click', e => {
        const b = e.currentTarget;
        declineUser(b.dataset.uid, b.dataset.name).catch(()=>{});
      });
      list.appendChild(div);
    });

    // Badge on hamburger so mobile admins notice pending users
    $('hamburger-btn')?.classList.add('has-pending');
  } else {
    $('hamburger-btn')?.classList.remove('has-pending');
  }
}

/* ══════════════════════════════════════════════════
   ROOM WIPE — when last member leaves
   Deletes all subcollections AND the room doc itself.
   NOTE: Firestore rules must allow `delete` on the
   room doc — change to `allow delete: if true` in the
   /rooms/{roomCode} rule for this to work.
══════════════════════════════════════════════════ */
async function wipeRoom(code) {

  try {
    const batchDelete = async col => {
      const s = await db.collection('rooms').doc(code).collection(col).get();
      if (s.empty) return;
      const b = db.batch(); s.forEach(d => b.delete(d.ref)); await b.commit();
    };
    await batchDelete('messages');
    await batchDelete('typing');
    await batchDelete('members');
    // Delete the room doc itself — requires `allow delete: if true` in Firestore rules
    await db.collection('rooms').doc(code).delete().catch(e => {
    });
  } catch (e) {  }
}

/* ──────────────────────────────────────────
   Heartbeat + visibility
────────────────────────────────────────── */
function startHeartbeat() {
  clearInterval(_heartbeat);
  _heartbeat = setInterval(() => {
    if (!state.roomCode || !state.me) return;
    db.collection('rooms').doc(state.roomCode).collection('members').doc(state.me.id)
      .update({ online: true }).catch(() => {});
  }, CONFIG.HEARTBEAT_MS);
}

document.addEventListener('visibilitychange', () => {
  if (!state.me || !state.roomCode) return;
  const online = !document.hidden;
  db.collection('rooms').doc(state.roomCode).collection('members').doc(state.me.id)
    .update({ online }).catch(() => {});
  if (online) {
    _unreadCount = 0;
    document.title = 'NEXUS';
    stopChatListeners(); startChatListeners();
  }  // re-sync on tab focus
});

window.addEventListener('beforeunload', () => {
  if (!state.me || !state.roomCode) return;
  clearMyTyping();
  db.collection('rooms').doc(state.roomCode).collection('members').doc(state.me.id)
    .update({ online: false }).catch(() => {});
});

/* ══════════════════════════════════════════════════
   SEND TEXT
══════════════════════════════════════════════════ */
const _sendRl = { count: 0, resetAt: 0 };
function checkSendRateLimit() {
  const now = Date.now();
  if (now > _sendRl.resetAt) { _sendRl.count = 0; _sendRl.resetAt = now + 10000; }
  _sendRl.count++;
  if (_sendRl.count > 20) { toast('Slow down', 'Too many messages sent too quickly.', '⚠'); return false; }
  return true;
}

async function sendMessage() {
  if (_editingDocId) { submitEdit().catch(() => {}); return; }
  if (!checkSendRateLimit()) return;

  const input = $('msg-input');
  const text  = (input?.value || '').trim();
  if (!text || !state.roomCode) return;
  input.value = ''; input.style.height = 'auto';
  updateActionBtn();
  clearMyTyping();

  const ts_client = Date.now();
  const encText   = await enc(text, state.roomCode);
  const msgSig    = await signMsg(state.me.id, ts_client, encText);

  const msgData = {
    type:        'text',
    enc:         encText,
    sig:         msgSig,             // D3: ECDSA signature
    senderId:    state.me.id,
    senderName:  state.me.name,
    senderColor: state.me.color,
    createdAt:   ts_now(),
    ts:          ts_client,
  };

  // Attach encrypted reply quote if replying
  if (_replyTo) {
    msgData.replyTo = {
      senderName: _replyTo.senderName,
      enc:        _replyTo.text ? await enc(_replyTo.text, state.roomCode) : '',
      docId:      _replyTo.docId || '',
      mediaType:  _replyTo.mediaType || null,
      fileName:   _replyTo.fileName  || null,
    };
    clearReply();
  }

  db.collection('rooms').doc(state.roomCode).collection('messages').add(msgData)
    .catch(e => { toast('Send failed', e.message, '✗'); });
  playSound('send');
}

async function sendSys(text) {
  if (!state.roomCode) return;
  const _sts  = Date.now();
  const _senc = await enc(text, state.roomCode);
  const _ssig = await signMsg(state.me.id || 'sys', _sts, _senc);
  await db.collection('rooms').doc(state.roomCode).collection('messages').add({
    type: 'system', enc: _senc, sig: _ssig,
    senderId: state.me?.id || 'sys',
    createdAt: ts_now(), ts: _sts,
  }).catch(() => {});
}

function handleKey(e) {
  // Escape closes mention dropdown or search
  if (e.key === 'Escape') {
    if (_mentionActive) { e.preventDefault(); hideMentionDropdown(); return; }
    if (_searchActive)  { toggleSearch(); return; }
  }
  // Tab selects first mention
  if (e.key === 'Tab' && _mentionActive) {
    e.preventDefault();
    const first = $('mention-dropdown')?.querySelector('.mention-item');
    if (first) first.dispatchEvent(new Event('mousedown'));
    return;
  }
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

/* ══════════════════════════════════════════════════
   TYPING — THROTTLED WRITES
   Max 1 Firestore write per TYPING_WRITE_MS per user.
══════════════════════════════════════════════════ */
function handleTyping(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
  handleMentionInput(el);
  updateActionBtn();
  if (!state.roomCode || !state.me) return;

  const now = Date.now();
  if (!_isTyping || now - _lastTypeWrite >= CONFIG.TYPING_WRITE_MS) {
    _isTyping = true;
    _lastTypeWrite = now;
    db.collection('rooms').doc(state.roomCode).collection('typing').doc(state.me.id)
      .set({ name: state.me.name, ts: now }).catch(() => {});
  }
  clearTimeout(_typingTimer);
  _typingTimer = setTimeout(clearMyTyping, CONFIG.TYPING_IDLE_MS);
}

function clearMyTyping() {
  clearTimeout(_typingTimer);
  if (!_isTyping) return;
  _isTyping = false;
  if (state.roomCode && state.me) {
    db.collection('rooms').doc(state.roomCode).collection('typing').doc(state.me.id)
      .delete().catch(() => {});
  }
}

/* ══════════════════════════════════════════════════
   FILE ATTACH — stored in Firestore as encrypted base64
   (No Firebase Storage needed — 100% free tier)

   Images: up to 10 MB raw.
     If > 5 MB → compress to ≤5 MB at HIGH quality (0.92+).
     Dimensions are NEVER reduced — only JPEG quality adjusted.
     Quality never drops below 0.82 — no visible degradation.
   Videos/files: up to 5 MB hard cap (no browser compression).
══════════════════════════════════════════════════ */
function triggerAttach() { $('file-input')?.click(); }

/* ══════════════════════════════════════════════════




/* ── High-quality image compression ────────────────────
   Reduces JPEG quality minimally to stay under targetBytes.
   NEVER changes dimensions — only adjusts quality.
   Quality floor: 0.82 (virtually indistinguishable from original).
   If still over target at floor quality, sends as-is (user's
   original is already close to the limit).
────────────────────────────────────────────────────── */

async function handleFileAttach(e) {
  const file = e.target.files?.[0];
  if (!file || !state.roomCode) return;
  e.target.value = '';
  updateActionBtn();

  const MAX = 25 * 1024 * 1024;
  if (file.size > MAX) { toast('File too large', 'Max 25 MB', '✗'); return; }

  const isImg = file.type.startsWith('image/');
  const isVid = file.type.startsWith('video/');
  const msgType = isImg ? 'image' : isVid ? 'video' : 'file';

  toast('Encrypting & uploading…', file.name, '◈');

  try {
    const encrypted = await encBytes(file, state.roomCode);
    const totalSize = encrypted.length;

    if (totalSize <= CONFIG.CHUNK_BYTES) {
      const _fts1  = Date.now();
      const _fsig1 = await signMsg(state.me.id, _fts1, encrypted.slice(0, 64));
      await db.collection('rooms').doc(state.roomCode).collection('messages').add({
        type: msgType, encData: encrypted, mime: file.type,
        fileName: file.name, fileSize: file.size, chunks: 1, chunkOf: 1,
        senderId: state.me.id, senderName: state.me.name, senderColor: state.me.color,
        sig: _fsig1, ts: _fts1, createdAt: ts_now(),
      });
    } else {
      const parts  = [];
      for (let i = 0; i < totalSize; i += CONFIG.CHUNK_BYTES) parts.push(encrypted.slice(i, i + CONFIG.CHUNK_BYTES));
      const groupId = 'grp_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
      const now     = Date.now();
      await Promise.all(parts.map((part, idx) =>
        db.collection('rooms').doc(state.roomCode).collection('messages').add({
          type: idx === 0 ? msgType : 'chunk', encData: part,
          mime: file.type, fileName: file.name, fileSize: file.size,
          groupId, chunkIdx: idx, chunkOf: parts.length,
          senderId: state.me.id, senderName: state.me.name, senderColor: state.me.color,
          createdAt: ts_now(), ts: now + idx,
        })
      ));
    }
    playSound('send');
    toast('Sent!', file.name, '✓');
  } catch (err) {
    toast('Upload failed', err.message || 'Please check your connection.', '✗');
  }
}

/* ══════════════════════════════════════════════════
   REPLY STATE
══════════════════════════════════════════════════ */
let _replyTo = null;  // { senderName, text, docId }

function setReply(senderName, text, docId, mediaType, fileName) {
  _replyTo = { senderName, text, docId, mediaType, fileName };
  const bar   = $('reply-bar');
  const rname = $('reply-sender');
  const rtext = $('reply-preview');
  if (!bar) return;
  rname.textContent = senderName;

  if (mediaType === 'image') {
    rtext.innerHTML = `<span class="rq-media-inline"><svg viewBox="0 0 20 20" fill="none" width="12" height="12"><path d="M2 7a2 2 0 012-2h.5l1-2h5l1 2H17a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V7z" stroke="currentColor" stroke-width="1.4"/><circle cx="10" cy="11" r="2.5" stroke="currentColor" stroke-width="1.4"/></svg> Photo</span>`;
  } else if (mediaType === 'video') {
    rtext.innerHTML = `<span class="rq-media-inline"><svg viewBox="0 0 20 20" fill="none" width="12" height="12"><rect x="2" y="5" width="12" height="10" rx="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M14 9l4-2v6l-4-2V9z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg> Video</span>`;
  } else if (mediaType === 'file') {
    const isPdf = (fileName || '').toLowerCase().endsWith('.pdf');
    const label = isPdf ? 'PDF' : 'File';
    const fname = fileName ? ': ' + (fileName.length > 22 ? fileName.slice(0, 22) + '…' : fileName) : '';
    rtext.innerHTML = `<span class="rq-media-inline"><svg viewBox="0 0 20 20" fill="none" width="12" height="12"><path d="M4 4a2 2 0 012-2h5l5 5v9a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" stroke="currentColor" stroke-width="1.4"/><path d="M11 2v5h5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg> ${esc(label)}${esc(fname)}</span>`;
  } else {
    rtext.textContent = text.length > 80 ? text.slice(0, 80) + '…' : text;
  }

  bar.style.display = 'flex';
  requestAnimationFrame(() => bar.classList.add('visible'));
  $('msg-input')?.focus();
}

function clearReply() {
  // If editing, cancel the edit
  if (_editingDocId) { cancelEdit(); return; }
  _replyTo = null;
  const bar = $('reply-bar');
  if (!bar) return;
  bar.classList.remove('visible');
  setTimeout(() => { bar.style.display = 'none'; }, 250);
}

/* ══════════════════════════════════════════════════
   RENDER MESSAGE — with docId stored, swipe-reply,
   long-press / tap-select delete for own messages
══════════════════════════════════════════════════ */
let _chunkGroups = {};
let _memberNames  = [];      // tracked for @mention autocomplete
let _editingDocId = null;    // docId of message currently being edited
let _editingWrap  = null;
let _editingTs    = 0;       // original message timestamp (for 2-min window)
let _editTimer    = null;    // setInterval for the countdown display
let _mentionActive = false;
let _mentionStart  = -1;
let _searchActive  = false;

async function renderMsg(data, docId) {
  const area = $('messages-area'); if (!area) return;

  if (data.type === 'chunk' || (data.groupId && data.chunkOf > 1)) {
    assembleChunk(data, docId); return;
  }

  const isMine = data.senderId === state.me?.id;

  if (data.type === 'system') {
    const div = document.createElement('div');
    div.className = 'msg-system';
    // Always decrypt — never render the raw enc field as plaintext.
    // This blocks injected system messages via direct Firestore REST writes
    // (Attack 4): an injected message without the room code will fail
    // AES-GCM auth tag verification and render as '[encrypted]'.
    const text = await dec(data.enc, state.roomCode);
    div.innerHTML = `<span>${esc(text)}</span>`;
    area.appendChild(div); return;
  }

  const wrap = document.createElement('div');
  wrap.className    = `msg-wrapper ${isMine ? 'sent' : 'received'}`;
  wrap.dataset.docId    = docId || '';
  wrap.dataset.senderId = data.senderId || '';
  wrap.dataset.ts       = data.ts || '';
  wrap.dataset.type     = data.type || 'text';
  wrap.dataset.fileName = data.fileName || '';

  // Decoded text (used for reply preview)
  const plainText = data.type === 'text' ? await dec(data.enc, state.roomCode) : null;

  let bubble = '';
  let replyQuote = '';

  // Render quoted reply if this message has one
  if (data.replyTo) {
    let rqContent = '';
    const mt = data.replyTo.mediaType;
    if (mt === 'image') {
      rqContent = `<div class="rq-media"><svg viewBox="0 0 20 20" fill="none" width="12" height="12"><path d="M2 7a2 2 0 012-2h.5l1-2h5l1 2H17a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V7z" stroke="currentColor" stroke-width="1.4"/><circle cx="10" cy="11" r="2.5" stroke="currentColor" stroke-width="1.4"/></svg> Photo</div>`;
    } else if (mt === 'video') {
      rqContent = `<div class="rq-media"><svg viewBox="0 0 20 20" fill="none" width="12" height="12"><rect x="2" y="5" width="12" height="10" rx="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M14 9l4-2v6l-4-2V9z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg> Video</div>`;
    } else if (mt === 'file') {
      const isPdf = (data.replyTo.fileName || '').toLowerCase().endsWith('.pdf');
      const label = isPdf ? 'PDF' : 'File';
      const fname = data.replyTo.fileName ? ': ' + esc(data.replyTo.fileName.length > 20 ? data.replyTo.fileName.slice(0, 20) + '…' : data.replyTo.fileName) : '';
      rqContent = `<div class="rq-media"><svg viewBox="0 0 20 20" fill="none" width="12" height="12"><path d="M4 4a2 2 0 012-2h5l5 5v9a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" stroke="currentColor" stroke-width="1.4"/><path d="M11 2v5h5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg> ${label}${fname}</div>`;
    } else {
      const qText = data.replyTo.enc ? await dec(data.replyTo.enc, state.roomCode) : '';
      rqContent = `<div class="rq-text">${esc(qText.length > 60 ? qText.slice(0, 60) + '…' : qText)}</div>`;
    }
    replyQuote = `
      <div class="reply-quote" data-goto="${esc(data.replyTo.docId || '')}">
        <div class="rq-sender">${esc(data.replyTo.senderName || '')}</div>
        ${rqContent}
      </div>`;
  }

  if (data.type === 'text') {
    bubble = renderTextContent(plainText) + (data.edited ? '<span class="msg-edited"> ✎</span>' : '');
  } else if (data.type === 'image' || data.type === 'video' || data.type === 'file') {
    if (data.encData) {
      const uid = 'med_' + (data.ts||Date.now()) + '_' + Math.random().toString(36).slice(2,5);
      bubble = buildMediaPlaceholder(uid, data);
      setTimeout(() => decryptAndShow(data.encData, data.mime||'application/octet-stream', data.type, data.fileName, uid), 60);
    } else {
      bubble = `<div class="msg-media-err">Media unavailable</div>`;
    }
  }

  const senderLine = !isMine
    ? `<div class="msg-sender" style="color:${esc(data.senderColor||'#4ecdc4')}">${esc(data.senderName||'')}</div>`
    : '';

  // Reply icon (shows on hover/touch)
  const replyBtn = `<button class="msg-reply-btn" aria-label="Reply" tabindex="-1">
    <svg viewBox="0 0 20 20" fill="none" width="14" height="14">
      <path d="M8 5L4 9l4 4M4 9h8a4 4 0 010 8h-2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </button>`;

  // Emoji react button
  const reactBtn = `<button class="msg-reply-btn msg-react-btn" aria-label="React" tabindex="-1">
    <svg viewBox="0 0 20 20" fill="none" width="14" height="14">
      <circle cx="10" cy="10" r="7.5" stroke="currentColor" stroke-width="1.5"/>
      <path d="M7 12c.5 1.5 5.5 1.5 6 0" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
      <circle cx="7.8" cy="8.5" r="1" fill="currentColor"/>
      <circle cx="12.2" cy="8.5" r="1" fill="currentColor"/>
    </svg>
  </button>`;

  wrap.innerHTML = `
    <div class="msg-swipe-wrapper">
      <div class="msg-reply-indicator">
        <svg viewBox="0 0 20 20" fill="none" width="18" height="18">
          <path d="M8 5L4 9l4 4M4 9h8a4 4 0 010 8h-2" stroke="var(--teal)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="msg-bubble-wrap">
        ${!isMine ? `<div class="msg-small-avatar" style="background:${esc(data.senderColor||'#4ecdc4')}">${esc(initials(data.senderName||'?'))}</div>` : ''}
        <div class="msg-inner">
          ${senderLine}
          ${replyQuote}
          <div class="msg-bubble">${bubble}</div>
          <div class="msg-meta">
            <span class="msg-time-sm">${fmtTime(data.ts)}</span>
            ${isMine ? '<span class="msg-status">✓</span>' : ''}
          </div>
          <div class="msg-reactions" data-rid="${esc(docId || '')}"></div>
        </div>
        <div class="msg-actions">
          ${replyBtn}
          ${reactBtn}
        </div>
      </div>
    </div>`;

  // Wire reply button — supports text and media messages
  wrap.querySelector('.msg-reply-btn:not(.msg-react-btn)')?.addEventListener('click', e => {
    e.stopPropagation();
    if (plainText !== null) {
      setReply(data.senderName || 'Someone', plainText, wrap.dataset.docId);
    } else if (data.type === 'image' || data.type === 'video' || data.type === 'file') {
      setReply(data.senderName || 'Someone', '', wrap.dataset.docId, data.type, data.fileName);
    }
  });

  // Wire react button
  wrap.querySelector('.msg-react-btn')?.addEventListener('click', e => {
    e.stopPropagation();
    showInlineActions(wrap, wrap.dataset.docId, plainText, data.ts, isMine);
  });

  // Wire reply-quote click → scroll to original message
  wrap.querySelector('.reply-quote[data-goto]')?.addEventListener('click', e => {
    e.stopPropagation();
    scrollToMsg(e.currentTarget.dataset.goto);
  });

  // Long-press → inline action strip (emoji bar + reply + edit + delete)
  // Works on own AND other messages. Delete only shown for own messages.
  {
    const targets = [
      wrap.querySelector('.msg-bubble'),
      wrap.querySelector('.msg-media'),
      wrap.querySelector('.msg-file'),
      wrap.querySelector('.video-thumb'),
    ].filter(Boolean);

    targets.forEach(el => {
      let pressTimer = null;
      el.addEventListener('touchstart', () => {
        pressTimer = setTimeout(() => {
          pressTimer = null;
          if (navigator.vibrate) navigator.vibrate(18);
          showInlineActions(wrap, docId, plainText, data.ts, isMine);
        }, 480);
      }, { passive: true });
      el.addEventListener('touchend',  () => { if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; } }, { passive: true });
      el.addEventListener('touchmove', () => { if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; } }, { passive: true });
      el.addEventListener('contextmenu', e => {
        e.preventDefault();
        showInlineActions(wrap, docId, plainText, data.ts, isMine);
      });
    });
  }

  // Render any existing reactions (e.g. loaded from cache)
  if (data.reactions && Object.keys(data.reactions).length > 0) {
    const reactRow = wrap.querySelector('.msg-reactions');
    if (reactRow) renderReactionsInto(reactRow, data.reactions, docId);
  }

  // Swipe-left-to-reply gesture on the bubble
  addSwipeReply(wrap, data, plainText);

  area.appendChild(wrap);

  // D3: verify signature after DOM paint (async, non-blocking)
  if (data.sig && data.type === 'text') {
    requestAnimationFrame(() => verifyAndBadge(data, docId));
  }
}

function buildMediaPlaceholder(uid, data) {
  if (data.type === 'file') return `<div class="msg-media loading" id="${uid}"><div class="media-decrypt-spinner"></div><div class="media-decrypt-label">${esc(data.fileName||'File')} · Decrypting…</div></div>`;
  return `<div class="msg-media loading" id="${uid}"><div class="media-decrypt-spinner"></div><div class="media-decrypt-label">Decrypting ${data.type}…</div></div>`;
}

function assembleChunk(data, docId) {
  const gid = data.groupId; if (!gid) return;
  if (!_chunkGroups[gid]) _chunkGroups[gid] = { parts: {}, total: data.chunkOf, meta: data, docId };
  _chunkGroups[gid].parts[data.chunkIdx] = data.encData;
  if (data.chunkIdx === 0) { _chunkGroups[gid].meta = data; _chunkGroups[gid].docId = docId; }
  const g = _chunkGroups[gid];
  if (Object.keys(g.parts).length === g.total) {
    const assembled = Array.from({ length: g.total }, (_, i) => g.parts[i]).join('');
    delete _chunkGroups[gid];
    renderMsg({ ...g.meta, encData: assembled, type: g.meta.type === 'chunk' ? 'file' : g.meta.type }, g.docId);
  }
}

/* ══════════════════════════════════════════════════
   SWIPE LEFT → REPLY gesture on each message bubble
══════════════════════════════════════════════════ */
function addSwipeReply(wrap, data, plainText) {
  if (data.type !== 'text') return;  // only swipe-reply on text messages

  const bubbleWrap = wrap.querySelector('.msg-swipe-wrapper');
  const indicator  = wrap.querySelector('.msg-reply-indicator');
  if (!bubbleWrap) return;

  let startX = 0, startY = 0, dx = 0, triggered = false, tracking = false;
  const THRESHOLD = 60;

  bubbleWrap.addEventListener('touchstart', e => {
    if (e.target.closest('button')) return;
    startX   = e.touches[0].clientX;
    startY   = e.touches[0].clientY;
    dx       = 0;
    triggered = false;
    tracking  = true;
  }, { passive: true });

  bubbleWrap.addEventListener('touchmove', e => {
    if (!tracking) return;
    dx = e.touches[0].clientX - startX;
    const dy = e.touches[0].clientY - startY;

    // Only swipe LEFT (negative dx) and only if horizontal
    if (Math.abs(dy) > Math.abs(dx) * 0.8 || dx > 0) {
      tracking = false;
      bubbleWrap.style.transform = '';
      if (indicator) indicator.style.opacity = '0';
      return;
    }

    const pull = Math.min(Math.abs(dx), THRESHOLD + 20);
    bubbleWrap.style.transform = `translateX(${-pull}px)`;
    bubbleWrap.style.transition = 'none';
    if (indicator) indicator.style.opacity = String(Math.min(1, pull / THRESHOLD));

    if (pull >= THRESHOLD && !triggered) {
      triggered = true;
      if (navigator.vibrate) navigator.vibrate(20);
    }
  }, { passive: true });

  bubbleWrap.addEventListener('touchend', () => {
    if (!tracking) return;
    tracking = false;
    bubbleWrap.style.transition = 'transform 0.25s cubic-bezier(0.4,0,0.2,1)';
    bubbleWrap.style.transform  = '';
    if (indicator) {
      indicator.style.transition = 'opacity 0.2s';
      indicator.style.opacity    = '0';
    }
    if (triggered && plainText !== null) {
      setReply(data.senderName || 'Someone', plainText, wrap.dataset.docId);
    }
    setTimeout(() => { bubbleWrap.style.transition = ''; }, 260);
  }, { passive: true });
}

/* ══════════════════════════════════════════════════
   DELETE OWN MESSAGE
══════════════════════════════════════════════════ */
async function confirmDeleteMsg(docId, wrapEl) {
  if (!docId || !state.roomCode) return;
  const ok = await showConfirm('Delete message?', 'This removes it for everyone.', 'DELETE');
  if (!ok) return;
  try {
    await db.collection('rooms').doc(state.roomCode).collection('messages').doc(docId).delete();
    // Also remove from IDB cache
    const db2 = await openIDB();
    await new Promise(res => {
      const tx = db2.transaction('msgs', 'readwrite');
      tx.objectStore('msgs').delete(docId);
      tx.oncomplete = res;
    });
    // Animate out and remove from DOM
    wrapEl.style.transition = 'opacity 0.2s, transform 0.2s';
    wrapEl.style.opacity    = '0';
    wrapEl.style.transform  = 'scaleY(0.8)';
    setTimeout(() => wrapEl.remove(), 220);
    _renderedIds.delete(docId);
  } catch (e) {

    toast('Delete failed', e.message, '✗');
  }
}

/* ══════════════════════════════════════════════════
   SCROLL TO REFERENCED MESSAGE
══════════════════════════════════════════════════ */
function scrollToMsg(docId) {
  if (!docId) return;
  const el = document.querySelector(`.msg-wrapper[data-doc-id="${CSS.escape(docId)}"]`);
  if (!el) { toast('Message not in view', 'Scroll up to find it.', '↑'); return; }
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.add('msg-highlight');
  setTimeout(() => el.classList.remove('msg-highlight'), 2000);
}

/* ══════════════════════════════════════════════════
   PATCH MESSAGE (reactions + edits from Firestore 'modified')
══════════════════════════════════════════════════ */
async function patchMsg(id, data) {
  const wrapEl = document.querySelector(`.msg-wrapper[data-doc-id="${CSS.escape(id)}"]`);
  if (!wrapEl) return;
  const reactRow = wrapEl.querySelector('.msg-reactions');
  if (reactRow) renderReactionsInto(reactRow, data.reactions || {}, id);
  if (data.edited && data.type === 'text') {
    const bubble = wrapEl.querySelector('.msg-bubble');
    if (bubble) bubble.innerHTML = renderTextContent(await dec(data.enc, state.roomCode)) + '<span class="msg-edited"> ✎</span>';
    if (data.sig) requestAnimationFrame(() => verifyAndBadge(data, id));
  }}

/* ══════════════════════════════════════════════════
   TEXT CONTENT RENDERER — highlights @mentions
══════════════════════════════════════════════════ */
function renderTextContent(text) {
  return esc(text)
    .replace(/\n/g, '<br>')
    .replace(/@([A-Z][A-Z0-9]+(?: [A-Z][A-Z0-9]+)*)/g, '<span class="mention">@$1</span>');
}

/* ══════════════════════════════════════════════════
   EMOJI REACTIONS
══════════════════════════════════════════════════ */
async function toggleReaction(docId, emoji) {
  if (!docId || !state.roomCode || !state.me) return;
  try {
    const ref  = db.collection('rooms').doc(state.roomCode).collection('messages').doc(docId);
    const snap = await ref.get();
    if (!snap.exists) return;
    const reactions = JSON.parse(JSON.stringify(snap.data().reactions || {}));
    const users = reactions[emoji] || {};
    if (users[state.me.id]) delete users[state.me.id];
    else users[state.me.id] = state.me.name;
    if (Object.keys(users).length === 0) delete reactions[emoji];
    else reactions[emoji] = users;
    await ref.update({ reactions });
  } catch(e) {  }
}

function renderReactionsInto(container, reactions, docId) {
  container.innerHTML = '';
  const entries = Object.entries(reactions || {}).filter(([, u]) => Object.keys(u).length > 0);
  if (!entries.length) return;
  entries.forEach(([emoji, users]) => {
    const count = Object.keys(users).length;
    const hasMe = !!users[state.me?.id];
    const btn = document.createElement('button');
    btn.className = 'reaction-chip' + (hasMe ? ' mine' : '');
    btn.textContent = emoji;
    const rcnt = document.createElement("span"); rcnt.className = "reaction-count"; rcnt.textContent = count; btn.appendChild(rcnt);
    btn.title = Object.values(users).join(', ');
    btn.addEventListener('click', e => { e.stopPropagation(); toggleReaction(docId, emoji); });
    container.appendChild(btn);
  });
}

function showReactionPicker(wrap, docId) {
  document.querySelector('.reaction-picker')?.remove();
  const picker = document.createElement('div');
  picker.className = 'reaction-picker';
  REACTION_EMOJIS.forEach(emoji => {
    const btn = document.createElement('button');
    btn.className = 'reaction-opt';
    btn.textContent = emoji;
    btn.addEventListener('click', e => { e.stopPropagation(); toggleReaction(docId, emoji); picker.remove(); });
    picker.appendChild(btn);
  });
  picker.style.cssText = wrap.classList.contains('sent') ? 'right:0;left:auto' : 'left:0';
  wrap.style.position = 'relative';
  wrap.appendChild(picker);
  requestAnimationFrame(() => picker.classList.add('visible'));
  const close = e => { if (!picker.contains(e.target) && !e.target.closest('.msg-react-btn')) { picker.remove(); document.removeEventListener('click', close); } };
  setTimeout(() => document.addEventListener('click', close), 50);
}

/* ══════════════════════════════════════════════════
   MESSAGE CONTEXT MENU (own messages: Edit / Delete)
   Edit only appears within CONFIG.EDIT_WINDOW_MS of sending.
══════════════════════════════════════════════════ */
function showInlineActions(wrap, docId, plainText, msgTs, isMine) {
  document.querySelectorAll('.msg-action-strip').forEach(s => s.remove());
  if (navigator.vibrate) navigator.vibrate(18);

  const strip = document.createElement('div');
  strip.className = 'msg-action-strip';

  // Quick emoji reactions row
  const emojiRow = document.createElement('div');
  emojiRow.className = 'strip-emojis';
  REACTION_EMOJIS.forEach(emoji => {
    const btn = document.createElement('button');
    btn.className = 'strip-emoji';
    btn.textContent = emoji;
    btn.addEventListener('click', e => {
      e.stopPropagation();
      toggleReaction(docId, emoji);
      strip.remove();
    });
    emojiRow.appendChild(btn);
  });
  strip.appendChild(emojiRow);

  // Divider
  const div = document.createElement('div');
  div.className = 'strip-divider';
  strip.appendChild(div);

  // Action buttons row
  const actRow = document.createElement('div');
  actRow.className = 'strip-actions';

  const replyBtn = document.createElement('button');
  replyBtn.className = 'strip-action';
  replyBtn.innerHTML = `<svg viewBox="0 0 20 20" fill="none" width="15" height="15"><path d="M8 5L4 9l4 4M4 9h8a4 4 0 010 8h-2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Reply</span>`;
  replyBtn.addEventListener('click', e => {
    e.stopPropagation();
    strip.remove();
    const senderName = wrap.querySelector('.msg-sender')?.textContent?.trim() || 'Someone';
    if (plainText !== null) setReply(senderName, plainText, docId);
    else {
      const mediaType = wrap.dataset.type || null;
      const fileName  = wrap.dataset.fileName || null;
      setReply(senderName, '', docId, mediaType, fileName);
    }
  });
  actRow.appendChild(replyBtn);

  if (isMine) {
    const canEdit = plainText !== null && (Date.now() - (msgTs || 0)) < CONFIG.EDIT_WINDOW_MS;
    if (canEdit) {
      const secsLeft = Math.floor((CONFIG.EDIT_WINDOW_MS - (Date.now() - (msgTs || 0))) / 1000);
      const editBtn = document.createElement('button');
      editBtn.className = 'strip-action';
      editBtn.innerHTML = `<svg viewBox="0 0 20 20" fill="none" width="15" height="15"><path d="M13.5 3.5l3 3L7 16H4v-3L13.5 3.5z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg><span>Edit <small>${fmtEditSecs(secsLeft)}</small></span>`;
      editBtn.addEventListener('click', e => {
        e.stopPropagation();
        strip.remove();
        startEdit(docId, plainText, wrap, msgTs);
      });
      actRow.appendChild(editBtn);
    }
  }

  strip.appendChild(actRow);

  if (isMine) {
    const delRow = document.createElement('div');
    delRow.className = 'strip-delete-row';
    const delBtn = document.createElement('button');
    delBtn.className = 'strip-action danger';
    delBtn.innerHTML = `<svg viewBox="0 0 20 20" fill="none" width="16" height="16"><path d="M4 6h12M8 6V4h4v2M7 6v9a1 1 0 001 1h4a1 1 0 001-1V6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Delete Message</span>`;
    delBtn.addEventListener('click', e => {
      e.stopPropagation();
      strip.remove();
      confirmDeleteMsg(docId, wrap);
    });
    delRow.appendChild(delBtn);
    strip.appendChild(delRow);
  }

  // Position: right side for sent, left side for received
  strip.dataset.side = isMine ? 'sent' : 'received';
  wrap.style.position = 'relative';
  wrap.appendChild(strip);
  requestAnimationFrame(() => strip.classList.add('visible'));

  const close = e => {
    if (!strip.contains(e.target)) {
      strip.remove();
      document.removeEventListener('click', close);
      document.removeEventListener('touchstart', close);
    }
  };
  setTimeout(() => {
    document.addEventListener('click', close);
    document.addEventListener('touchstart', close);
  }, 60);
}

function showReactionPicker(wrap, docId) {
  const ts    = parseInt(wrap.dataset.ts || '0') || 0;
  const mine  = wrap.classList.contains('sent');
  const bubble = wrap.querySelector('.msg-bubble');
  const plain  = bubble ? (bubble.innerText || null) : null;
  showInlineActions(wrap, docId, plain, ts, mine);
}

function fmtEditSecs(s) {
  if (s <= 0) return '0s';
  return s >= 60 ? `${Math.floor(s/60)}m ${s%60}s` : `${s}s`;
}

/* ══════════════════════════════════════════════════
   MESSAGE EDITING — 2-minute window enforced client-side
   AND server-side (submitEdit checks age before writing).
══════════════════════════════════════════════════ */
function startEdit(docId, currentText, wrapEl, msgTs) {
  // Clear any existing edit first
  if (_editingDocId) cancelEdit();

  _editingDocId = docId;
  _editingWrap  = wrapEl;
  _editingTs    = msgTs || 0;

  const input = $('msg-input');
  if (input) {
    input.value = currentText;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 120) + 'px';
    input.focus();
  }

  // Show the reply-bar repurposed as edit bar
  const bar = $('reply-bar'), rname = $('reply-sender'), rtext = $('reply-preview');
  if (bar) {
    rname.innerHTML = `✎ Editing <span id="edit-countdown" class="edit-countdown"></span>`;
    rtext.textContent = currentText.length > 70 ? currentText.slice(0, 70) + '…' : currentText;
    bar.style.display = 'flex';
    requestAnimationFrame(() => bar.classList.add('visible'));
  }

  wrapEl?.querySelector('.msg-bubble')?.classList.add('editing-highlight');

  // Start the countdown ticker
  clearInterval(_editTimer);
  _editTimer = setInterval(() => {
    const remaining = CONFIG.EDIT_WINDOW_MS - (Date.now() - _editingTs);
    const el = $('edit-countdown');
    if (remaining <= 0) {
      clearInterval(_editTimer); _editTimer = null;
      if (el) el.textContent = '';
      toast('Edit window closed', 'The 2-minute edit window has passed.', '⏱');
      cancelEdit();
      return;
    }
    const secs = Math.ceil(remaining / 1000);
    if (el) {
      el.textContent = fmtEditSecs(secs);
      // Turn red below 20 seconds
      el.classList.toggle('urgent', secs <= 20);
    }
  }, 500);
}

function cancelEdit() {
  clearInterval(_editTimer); _editTimer = null;
  _editingWrap?.querySelector('.msg-bubble')?.classList.remove('editing-highlight');
  _editingDocId = null; _editingWrap = null; _editingTs = 0; _replyTo = null;
  const bar = $('reply-bar'); if (!bar) return;
  bar.classList.remove('visible'); setTimeout(() => { bar.style.display = 'none'; }, 250);
  const input = $('msg-input'); if (input) { input.value = ''; input.style.height = 'auto'; }
  updateActionBtn();
}

async function submitEdit() {
  const docId = _editingDocId, input = $('msg-input');
  const text = (input?.value || '').trim();
  if (!text || !docId || !state.roomCode) { cancelEdit(); return; }

  // Double-check window server-side guard (client clock could be wrong)
  const age = Date.now() - _editingTs;
  if (_editingTs > 0 && age > CONFIG.EDIT_WINDOW_MS + 5000) {
    toast('Edit window closed', 'The 2-minute edit window has passed.', '⏱');
    cancelEdit(); return;
  }

  cancelEdit();
  if (input) { input.value = ''; input.style.height = 'auto'; }
  try {
    const _ets   = Date.now();
    const _eenc  = await enc(text, state.roomCode);
    const _esig  = await signMsg(state.me.id, _ets, _eenc);
    await db.collection('rooms').doc(state.roomCode).collection('messages').doc(docId).update({
      enc: _eenc, edited: true, editedAt: ts_now(), sig: _esig, ts: _ets,
    });
  } catch(e) { toast('Edit failed', e.message, '✗'); }
}

/* ══════════════════════════════════════════════════
   @ MENTION AUTOCOMPLETE
══════════════════════════════════════════════════ */
function handleMentionInput(input) {
  const val = input.value, pos = input.selectionStart;
  let atIdx = -1;
  for (let i = pos - 1; i >= 0; i--) {
    if (val[i] === '@') { atIdx = i; break; }
    if (val[i] === ' ' || val[i] === '\n') break;
  }
  if (atIdx === -1) { hideMentionDropdown(); return; }
  const query = val.slice(atIdx + 1, pos).toUpperCase();
  const matches = _memberNames.filter(n => n.toUpperCase().startsWith(query));
  if (!matches.length) { hideMentionDropdown(); return; }
  _mentionActive = true; _mentionStart = atIdx;
  showMentionDropdown(matches, input);
}

function showMentionDropdown(names, input) {
  let dd = $('mention-dropdown');
  if (!dd) {
    dd = document.createElement('div'); dd.id = 'mention-dropdown'; dd.className = 'mention-dropdown';
    $('input-area')?.insertAdjacentElement('beforebegin', dd);
  }
  dd.innerHTML = '';
  names.slice(0, 5).forEach(name => {
    const btn = document.createElement('button'); btn.className = 'mention-item';
    btn.innerHTML = `<div class="mention-av" style="background:${avatarColor(name)}">${esc(initials(name))}</div><span>${esc(name)}</span>`;
    btn.addEventListener('mousedown', e => { e.preventDefault(); insertMention(name, input); });
    dd.appendChild(btn);
  });
  dd.style.display = 'flex';
}

function hideMentionDropdown() {
  _mentionActive = false; _mentionStart = -1;
  const dd = $('mention-dropdown'); if (dd) dd.style.display = 'none';
}

function insertMention(name, input) {
  const val = input.value, pos = input.selectionStart;
  const before = val.slice(0, _mentionStart) + '@' + name + ' ';
  input.value = before + val.slice(pos);
  const np = before.length; input.setSelectionRange(np, np);
  hideMentionDropdown(); input.focus();
}

/* ══════════════════════════════════════════════════
   MESSAGE SEARCH
══════════════════════════════════════════════════ */
function toggleSearch() {
  _searchActive = !_searchActive;
  const bar = $('search-bar'); if (!bar) return;
  if (_searchActive) {
    bar.style.display = 'flex'; requestAnimationFrame(() => bar.classList.add('visible'));
    bar.querySelector('input')?.focus(); $('search-btn')?.classList.add('active');
  } else {
    bar.classList.remove('visible'); setTimeout(() => { bar.style.display = 'none'; }, 250);
    clearSearch(); $('search-btn')?.classList.remove('active');
  }
}

function doSearch(query) {
  const q = (query || '').toLowerCase().trim();
  let matchCount = 0;
  document.querySelectorAll('.msg-wrapper').forEach(w => {
    if (!q) { w.style.display = ''; return; }
    const txt = (w.querySelector('.msg-bubble')?.textContent || '').toLowerCase();
    const match = txt.includes(q);
    w.style.display = match ? '' : 'none';
    if (match) matchCount++;
  });
  const c = $('search-count');
  if (c) c.textContent = q ? `${matchCount} result${matchCount !== 1 ? 's' : ''}` : '';
}

function clearSearch() {
  document.querySelectorAll('.msg-wrapper').forEach(w => w.style.display = '');
  const inp = $('search-bar')?.querySelector('input'); if (inp) inp.value = '';
  const c = $('search-count'); if (c) c.textContent = '';
}

async function decryptAndShow(encData, mime, type, fileName, domId) {
  // Cache key based on first 32 chars of encrypted data (fast, collision-resistant enough)
  const cacheKey = 'blob_' + btoa(encData.slice(0, 32).replace(/[^a-zA-Z0-9]/g,'').padEnd(8,'0')).slice(0,16);

  let url = await idbGetBlob(cacheKey).catch(() => null);

  if (!url) {
    try {
      const blob = await decBytes(encData, mime, state.roomCode);
      url = URL.createObjectURL(blob);
      await idbSetBlob(cacheKey, url);
    } catch (e) {

      const el = $(domId);
      if (el) el.innerHTML = `<div style="padding:8px;color:var(--text2);font-size:.7rem">This message could not be decrypted</div>`;
      return;
    }
  }

  const el = $(domId);
  if (!el) return;

  if (type === 'image') {
    el.innerHTML = `<img src="${esc(url)}" alt="image" loading="lazy"
      onclick="openViewer('img','${esc(url)}')" style="cursor:pointer"/>
      <div class="media-tap-hint">Tap to expand</div>`;
    el.classList.remove('loading');

  } else if (type === 'video') {
    el.innerHTML = `<div class="video-thumb" onclick="openViewer('video','${esc(url)}')">
      <div class="video-play-btn"><svg viewBox="0 0 24 24" fill="currentColor" width="28" height="28"><path d="M8 5v14l11-7z"/></svg></div>
      <div class="video-label">${esc(fileName||'Video')}</div>
    </div>`;
    el.classList.remove('loading');

  } else {
    // File — show download link
    const size = esc(fmtBytes(el.dataset?.size || 0));
    el.outerHTML = `<a class="msg-file" href="${esc(url)}" download="${esc(fileName||'file')}" target="_blank" rel="noopener">
      <div class="file-icon"><svg viewBox="0 0 20 20" fill="none" width="22" height="22">
        <path d="M4 4a2 2 0 012-2h5l5 5v9a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" stroke="currentColor" stroke-width="1.5"/>
        <path d="M11 2v5h5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg></div>
      <div class="file-info">
        <div class="file-name">${esc(fileName||'File')}</div>
      </div>
      <div class="file-dl"><svg viewBox="0 0 20 20" fill="none" width="16" height="16">
        <path d="M10 3v10M6 9l4 4 4-4M4 17h12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg></div>
    </a>`;
  }
}

/* ──────────────────────────────────────────
   DECRYPT + SHOW VOICE MESSAGE
────────────────────────────────────────── */

function showScrollFab() {
  const area = $('messages-area');
  const fab   = $('scroll-fab');
  if (!area || !fab) return;
  const fromBottom = area.scrollHeight - area.scrollTop - area.clientHeight;
  if (fromBottom > 120) {
    fab.style.display = 'flex';
    requestAnimationFrame(() => fab.classList.add('visible'));
    const badge = $('scroll-fab-badge');
    if (badge) {
      badge.textContent = _unreadCount > 0 ? (_unreadCount > 9 ? '9+' : _unreadCount) : '';
      badge.style.display = _unreadCount > 0 ? 'flex' : 'none';
    }
  }
}

function hideScrollFab() {
  const fab = $('scroll-fab');
  if (!fab) return;
  fab.classList.remove('visible');
  setTimeout(() => { if (!fab.classList.contains('visible')) fab.style.display = 'none'; }, 250);
}

function initScrollFab() {
  const area = $('messages-area');
  const fab  = $('scroll-fab');
  if (!area || !fab) return;
  area.addEventListener('scroll', () => {
    const fromBottom = area.scrollHeight - area.scrollTop - area.clientHeight;
    if (fromBottom < 60) hideScrollFab();
  }, { passive: true });
  fab.addEventListener('click', () => { scrollBottom(); hideScrollFab(); });
}


function scrollBottom() {
  const a = $('messages-area');
  if (a) requestAnimationFrame(() => {
    a.scrollTop = a.scrollHeight;
    hideScrollFab();
    _unreadCount = 0;
    document.title = 'NEXUS';
  });
}

/* ══════════════════════════════════════════════════
   MEDIA VIEWER
══════════════════════════════════════════════════ */
function openViewer(type, src) {
  const v = $('media-viewer'), img = $('mv-img'), vid = $('mv-video');
  if (!v) return;
  if (img) { img.src = ''; img.style.display = 'none'; }
  if (vid) { vid.src = ''; vid.style.display = 'none'; }
  if (type === 'img'   && img) { img.src = src; img.style.display = 'block'; }
  if (type === 'video' && vid) { vid.src = src; vid.style.display = 'block'; }
  v.style.display = 'flex';
}
function closeMediaViewer() {
  const v = $('media-viewer'); if (!v) return;
  v.style.display = 'none';
  const vid = $('mv-video'); if (vid) { vid.pause?.(); vid.src = ''; }
  const img = $('mv-img');   if (img) img.src = '';
}

/* ══════════════════════════════════════════════════
   COPY CODE
══════════════════════════════════════════════════ */
function copyRoomCode() {
  if (!state.roomCode) return;
  const code = state.roomCode, cb = () => toast('Code copied!', code, '✓');
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(code).then(cb).catch(() => fbCopy(code, cb));
  else fbCopy(code, cb);
}

function shareRoomLink() {
  if (!state.roomCode) return;
  const encoded = btoa(unescape(encodeURIComponent(state.roomCode)));
  const base    = window.location.origin + window.location.pathname;
  const url     = `${base}?r=${encoded}`;

  if (navigator.share) {
    navigator.share({
      title: 'Join my NEXUS room',
      text:  'Tap to join — you\'ll need the room code to get in.',
      url,
    }).catch(() => {});
    return;
  }
  const cb = () => toast('Invite link copied!', 'Share it and give them the code separately', '🔗');
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(url).then(cb).catch(() => fbCopy(url, cb));
  else fbCopy(url, cb);
}

function _detectInviteParam() {
  try {
    const p = new URLSearchParams(window.location.search);
    const r = p.get('r');
    if (!r) return null;
    return decodeURIComponent(escape(atob(r)));
  } catch { return null; }
}

function showInviteScreen() {
  const inp = $('invite-code-input');
  if (inp) { inp.value = ''; inp.type = 'password'; }
  const err = $('invite-error'); if (err) err.textContent = '';
  const btn = $('invite-join-btn'); if (btn) btn.disabled = true;
  showScreen('invite-screen');
}

function cancelInvite() {
  window.history.replaceState({}, '', window.location.pathname);
  showScreen('join-screen');
}

function checkInviteCode(el) {
  const btn = $('invite-join-btn');
  const err = $('invite-error'); if (err) err.textContent = '';
  if (btn) btn.disabled = (el.value.trim().length < 6);
}

async function joinFromInvite() {
  const inp  = $('invite-code-input');
  const code = (inp?.value || '').trim();
  const err  = $('invite-error');
  if (!code || code.length < 6) return;
  if (!checkRateLimit('enter')) return;

  const btn = $('invite-join-btn');
  if (btn) { btn.disabled = true; btn.querySelector('span').textContent = 'JOINING…'; }

  try {
    const roomSnap = await db.collection('rooms').doc(code).get();
    if (!roomSnap.exists) {
      _recordWrongCode();
      if (err) err.textContent = 'Room not found — check the code and try again.';
      if (btn) { btn.disabled = false; btn.querySelector('span').textContent = 'JOIN ROOM'; }
      return;
    }
    _enterRl.wrongCount  = 0;
    _enterRl.lockedUntil = 0;
    _roomEpoch = roomSnap.data()?.epoch || 0;
    const uid        = getUID();
    const memberSnap = await db.collection('rooms').doc(code).collection('members').doc(uid).get();
    const prevData   = memberSnap.exists ? memberSnap.data() : null;
    const wasApproved = prevData?.approved === true;

    state.me = buildMe(resolveName()); state.roomCode = code;
    saveSession(); saveRoom(code);

    window.history.replaceState({}, '', window.location.pathname);

    if (wasApproved) {
      await registerPresence(prevData.role || 'member', true);
      await sendSys(`${state.me.name} rejoined the room`);
      bootApp();
    } else {
      const approvalRequired = roomSnap.data()?.approvalRequired === true;
      if (approvalRequired) {
        await registerPresence('member', false);
        showWaitingScreen();
      } else {
        await registerPresence('member', true);
        await sendSys(`${state.me.name} joined the room`);
        bootApp();
      }
    }
  } catch(e) {
    if (err) err.textContent = 'Connection error. Check your internet.';
    if (btn) { btn.disabled = false; btn.querySelector('span').textContent = 'JOIN ROOM'; }
  }
}
function fbCopy(text, cb) {
  const el = Object.assign(document.createElement('textarea'), { value: text });
  el.style.cssText = 'position:fixed;left:-9999px;opacity:0';
  document.body.appendChild(el); el.focus(); el.select();
  try { document.execCommand('copy'); cb(); } catch {}
  document.body.removeChild(el);
}

/* ══════════════════════════════════════════════════
   EYE TOGGLE
══════════════════════════════════════════════════ */
function toggleVis(inputId, btnId) {
  const inp = $(inputId), btn = $(btnId); if (!inp || !btn) return;
  inp.type = inp.type === 'text' ? 'password' : 'text';
  btn.querySelector('.eye-open').style.display  = inp.type === 'password' ? 'block' : 'none';
  btn.querySelector('.eye-closed').style.display = inp.type === 'password' ? 'none'  : 'block';
}

/* ══════════════════════════════════════════════════
   LOGOUT
══════════════════════════════════════════════════ */
async function _handoffAdminRole() {
  if (!state.roomCode || !state.me) return;
  try {
    const snap = await db.collection('rooms').doc(state.roomCode)
      .collection('members')
      .where('online', '==', true)
      .where('approved', '==', true)
      .get();

    let nextUid = null, nextName = null;
    snap.forEach(doc => {
      if (doc.id !== state.me.id && doc.data().role !== 'admin' && !nextUid) {
        nextUid  = doc.id;
        nextName = doc.data().name;
      }
    });

    if (nextUid) {
      await db.collection('rooms').doc(state.roomCode)
        .collection('members').doc(nextUid)
        .update({ role: 'admin' });
      await sendSys(`${nextName} is now an admin ◆`);
    }
  } catch {}
}

async function handleLogout() {
  const ok = await showConfirm('Leave Room?', 'You can rejoin at any time using the room code.', 'LEAVE');
  if (!ok) return;

  clearMyTyping();
  clearInterval(_heartbeat);

  // D7: stop approval listener if pending
  if (_unsubApproval) { try { _unsubApproval(); } catch {} _unsubApproval = null; }
  _isAdmin = false;

  if (state.roomCode && state.me) {
    if (state.me.role === 'admin') await _handoffAdminRole();
    await sendSys(`${state.me.name} left the room`);
    await db.collection('rooms').doc(state.roomCode).collection('members').doc(state.me.id)
      .update({ online: false }).catch(() => {});
  }

  stopListeners();
  localStorage.removeItem(CONFIG.SESSION_KEY);
  localStorage.removeItem(CONFIG.ROOM_KEY);
  state.me = null; state.roomCode = null;
  _renderedIds.clear(); _lastCachedTs = 0;

  const ma = $('messages-area'); if (ma) ma.innerHTML = '';
  const ml = $('members-list');  if (ml) ml.innerHTML = '';
  const oc = $('online-count');  if (oc) oc.textContent = '0';

  closeSidebar();
  showScreen('join-screen');

  [$('input-create-code'), $('input-room-code')].forEach(el => { if (el) el.value = ''; });
  const je = $('join-error'); if (je) je.textContent = '';
  switchJoinTab('create');
}

/* ══════════════════════════════════════════════════
   SETTINGS
══════════════════════════════════════════════════ */
function openSettings() {
  const st = $('sound-toggle'), at = $('anim-toggle');
  const ap = $('approval-toggle'), approvalRow = $('approval-setting-row');
  if (st) st.checked = state.prefs.sound;
  if (at) at.checked = state.prefs.animations;

  const rotateRow = $('rotate-key-row');
  if (approvalRow) approvalRow.style.display = _isAdmin ? 'flex' : 'none';
  if (rotateRow)   rotateRow.style.display   = _isAdmin ? 'flex' : 'none';
  const epochEl = $('epoch-display');
  if (epochEl) epochEl.textContent = String(_roomEpoch);

  if (ap && _isAdmin && state.roomCode) {
    ap.checked = false;
    db.collection('rooms').doc(state.roomCode).get()
      .then(s => { if (ap) ap.checked = s.data()?.approvalRequired === true; })
      .catch(() => {});
  }
  $('settings-modal').style.display = 'flex';
}

function closeSettings() { $('settings-modal').style.display = 'none'; }
function closeModal(e)   { if (e.target.classList.contains('modal-overlay')) closeSettings(); }

function saveSettings() {
  localStorage.setItem(CONFIG.PREFS_KEY, JSON.stringify(state.prefs));
  toast('Settings saved', '', '✓'); closeSettings();
}

function toggleSoundAlerts()   { state.prefs.sound         = $('sound-toggle').checked; }
function toggleAnimations()    { state.prefs.animations    = $('anim-toggle').checked; }

function toggleApprovalGate() {
  if (!_isAdmin || !state.roomCode) return;
  const on = $('approval-toggle')?.checked ?? false;
  db.collection('rooms').doc(state.roomCode)
    .update({ approvalRequired: on })
    .then(() => toast(
      on ? 'Approval gate ON' : 'Approval gate OFF',
      on ? 'New members must be approved' : 'Anyone with the code can join freely',
      on ? '🔒' : '🔓'
    ))
    .catch(() => {});
}


/* ══════════════════════════════════════════════════
   CONFIRM DIALOG
══════════════════════════════════════════════════ */
function showConfirm(title, msg, confirmLabel = 'CONFIRM') {
  return new Promise(resolve => {
    $('nx-confirm')?.remove();
    const ov = document.createElement('div');
    ov.id = 'nx-confirm';
    ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);backdrop-filter:blur(6px);z-index:9999;display:flex;align-items:center;justify-content:center;padding:24px';
    const box = document.createElement('div');
    box.style.cssText = 'background:var(--surface2);border:1px solid var(--teal-border);border-radius:14px;padding:28px 24px;max-width:320px;width:100%;display:flex;flex-direction:column;gap:18px;box-shadow:0 16px 48px rgba(0,0,0,0.6)';
    const h = document.createElement('div'); h.style.cssText = 'font-family:var(--font-ui);font-size:.9rem;font-weight:700;color:#fff;letter-spacing:1px'; h.textContent = title;
    const m = document.createElement('div'); m.style.cssText = 'font-size:.75rem;color:var(--text2);line-height:1.7;font-family:var(--font-mono)'; m.textContent = msg;
    const row = document.createElement('div'); row.style.cssText = 'display:flex;gap:10px;justify-content:flex-end';
    const no  = document.createElement('button'); no.textContent = 'CANCEL'; no.style.cssText = 'padding:10px 20px;border-radius:8px;background:transparent;border:1px solid var(--border);color:var(--text2);font-family:var(--font-ui);font-size:.68rem;font-weight:700;letter-spacing:2px;cursor:pointer';
    const yes = document.createElement('button'); yes.textContent = confirmLabel;  yes.style.cssText = 'padding:10px 20px;border-radius:8px;background:var(--danger);border:1px solid var(--danger);color:#fff;font-family:var(--font-ui);font-size:.68rem;font-weight:700;letter-spacing:2px;cursor:pointer';
    const done = v => { ov.remove(); resolve(v); };
    no.addEventListener('click', () => done(false));
    yes.addEventListener('click', () => done(true));
    ov.addEventListener('click', e => { if (e.target === ov) done(false); });
    row.append(no, yes); box.append(h, m, row); ov.appendChild(box); document.body.appendChild(ov);
    setTimeout(() => no.focus(), 40);
  });
}

/* ──────────────────────────────────────────
   LOADING / ERROR
────────────────────────────────────────── */
function showError(msg) {
  const el = $('join-error'); if (!el) return;
  el.textContent = msg; el.style.animation = 'none';
  requestAnimationFrame(() => { el.style.animation = 'shake .3s ease'; });
}
function setLoading(btn, on, label) {
  if (!btn) return;
  const span = btn.querySelector('span');
  if (on)  { if (span) { btn.dataset.orig = span.textContent; span.textContent = label; } btn.disabled = true; }
  else     { if (span && btn.dataset.orig) span.textContent = btn.dataset.orig; btn.disabled = false; }
}

/* ──────────────────────────────────────────
   RIPPLE
────────────────────────────────────────── */

function setupClipboardPaste() {
  document.addEventListener('paste', async e => {
    if (!state.roomCode || !state.me) return;
    const items = e.clipboardData?.items;
    if (!items) return;
    for (const item of items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault();
        const file = item.getAsFile();
        if (file) await handleFileAttach({ target: { files: [file], value: '' } });
        return;
      }
    }
  });
}

function updateActionBtn() {
  const btn = $('send-btn');
  if (!btn) return;
  const hasText = ($('msg-input')?.value || '').trim().length > 0;
  btn.classList.toggle('has-input', hasText);
}

function setupActionBtn() {
  const btn = $('send-btn');
  if (!btn) return;
  btn.addEventListener('click', () => { sendMessage(); });
  btn.addEventListener('touchstart', e => {
    e.preventDefault();
    sendMessage();
  }, { passive: false });
}

function handleRipple(e) {
  if (!state.prefs.animations) return;
  if (!e.target.closest('.ripple-btn,.send-btn')) return;
  const x = e.touches?.[0]?.clientX ?? e.clientX, y = e.touches?.[0]?.clientY ?? e.clientY;
  const r = document.createElement('div');
  r.className = 'ripple-wave'; r.style.cssText = `left:${x-40}px;top:${y-40}px;width:80px;height:80px`;
  $('ripple-container')?.appendChild(r); setTimeout(() => r.remove(), 650);
}

/* ──────────────────────────────────────────
   SOUND
────────────────────────────────────────── */
function playSound(type) {
  if (!state.prefs.sound) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator(), gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    const s = { send:{freq:880,dur:.08,vol:.08}, receive:{freq:660,dur:.12,vol:.1} }[type] || {freq:880,dur:.08,vol:.08};
    osc.type = 'sine'; osc.frequency.value = s.freq;
    gain.gain.setValueAtTime(s.vol, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(.001, ctx.currentTime+s.dur);
    osc.start(); osc.stop(ctx.currentTime+s.dur);
  } catch {}
}

/* ──────────────────────────────────────────
   TOAST
────────────────────────────────────────── */
function toast(title, msg, icon='◈') {
  const c = $('toast-container'); if (!c) return;
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = `<div class="toast-icon">${esc(icon)}</div>
    <div class="toast-body">
      <div class="toast-title">${esc(title)}</div>
      ${msg ? `<div class="toast-msg">${esc(msg)}</div>` : ''}
    </div><div class="toast-bar"></div>`;
  el.addEventListener('click', () => rmToast(el));
  c.appendChild(el); setTimeout(() => rmToast(el), 4500);
}
function rmToast(el) {
  if (!el.parentNode) return;
  el.classList.add('removing'); setTimeout(() => el.remove(), 300);
}

/* ──────────────────────────────────────────
   PWA
────────────────────────────────────────── */
let _deferredInstall = null;
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault(); _deferredInstall = e;
  setTimeout(() => toast('Install NEXUS', 'Add it to your home screen.', '⬡'), 6000);
});
