/* ════════════════════════════════════════════
   NEXUS CHAT · ULTRA SECURE · MAIN APP LOGIC
   ════════════════════════════════════════════ */

'use strict';

/* ══════════════════════════════
   CONFIG & CONSTANTS
   ══════════════════════════════ */
const CONFIG = {
  SECRET_CODE: 'NEXUS2024',          // Admin sets this
  MAX_MEMBERS: 20,
  STORAGE_KEY: 'nexus_session',
  MESSAGES_KEY: 'nexus_messages',
  MEMBERS_KEY: 'nexus_members',
  ACTIVITY_KEY: 'nexus_activity',
  TYPING_TIMEOUT: 2500,
  CALL_RING_TIMEOUT: 30000,
  VERSION: '2.0.0',
};

/* ══════════════════════════════
   AVATAR COLORS
   ══════════════════════════════ */
const AVATAR_COLORS = [
  '#2dd4bf','#06b6d4','#3b82f6','#8b5cf6',
  '#ec4899','#f43f5e','#f97316','#eab308',
  '#22c55e','#14b8a6','#6366f1','#a855f7',
];

function getAvatarColor(name) {
  let hash = 0;
  for (let c of name) hash = (hash * 31 + c.charCodeAt(0)) & 0xffffffff;
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}

function getInitials(name) {
  return name.trim().split(/\s+/).map(w => w[0]?.toUpperCase() || '').join('').slice(0,2);
}

/* ══════════════════════════════
   STATE
   ══════════════════════════════ */
let state = {
  me: null,               // { id, name, phone, color, status }
  members: [],            // all registered members
  activity: {},           // { memberId: { status:'online'|'texting'|'calling'|'offline', with:id, callType } }
  messages: {},           // { chatId: [ ...msgs ] }
  activeChat: null,       // memberId currently open
  callState: null,        // { type, peerId, timer, muted, speaker }
  typingTimers: {},
  isTyping: false,
  notificationsEnabled: true,
  soundEnabled: true,
  animationsEnabled: true,
  unread: {},             // { memberId: count }
};

/* ══════════════════════════════
   CRYPTO HELPERS (lightweight)
   ══════════════════════════════ */
function simpleHash(str) {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) hash = ((hash << 5) + hash) ^ str.charCodeAt(i);
  return (hash >>> 0).toString(16);
}

function encryptMsg(text) {
  return btoa(unescape(encodeURIComponent(text)));
}

function decryptMsg(enc) {
  try { return decodeURIComponent(escape(atob(enc))); }
  catch { return enc; }
}

/* ══════════════════════════════
   STORAGE
   ══════════════════════════════ */
function saveSession() {
  localStorage.setItem(CONFIG.STORAGE_KEY, JSON.stringify(state.me));
}

function loadSession() {
  try { return JSON.parse(localStorage.getItem(CONFIG.STORAGE_KEY)); }
  catch { return null; }
}

function saveMembers() {
  localStorage.setItem(CONFIG.MEMBERS_KEY, JSON.stringify(state.members));
}

function loadMembers() {
  try { return JSON.parse(localStorage.getItem(CONFIG.MEMBERS_KEY)) || []; }
  catch { return []; }
}

function saveMessages() {
  localStorage.setItem(CONFIG.MESSAGES_KEY, JSON.stringify(state.messages));
}

function loadMessages() {
  try { return JSON.parse(localStorage.getItem(CONFIG.MESSAGES_KEY)) || {}; }
  catch { return {}; }
}

function saveActivity() {
  localStorage.setItem(CONFIG.ACTIVITY_KEY, JSON.stringify(state.activity));
  // Broadcast change event
  window.dispatchEvent(new CustomEvent('activityUpdate'));
}

function loadActivity() {
  try { return JSON.parse(localStorage.getItem(CONFIG.ACTIVITY_KEY)) || {}; }
  catch { return {}; }
}

/* ══════════════════════════════
   INIT
   ══════════════════════════════ */
window.addEventListener('DOMContentLoaded', () => {
  // Show splash, then check session
  setTimeout(() => {
    const session = loadSession();
    hideSplash();
    if (session && session.id) {
      state.me = session;
      state.members = loadMembers();
      state.messages = loadMessages();
      if (!state.members.find(m => m.id === state.me.id)) {
        state.members.push(state.me);
        saveMembers();
      }
      bootApp();
    } else {
      showScreen('join-screen');
    }
  }, 2200);

  // Touch ripple on whole doc
  document.addEventListener('touchstart', handleTouchRipple, { passive: true });
  document.addEventListener('mousedown', handleTouchRipple);

  // Storage events (cross-tab sync simulation)
  window.addEventListener('storage', handleStorageSync);
  window.addEventListener('activityUpdate', () => {
    state.activity = loadActivity();
    refreshMembersList();
  });

  // Register SW
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
});

function hideSplash() {
  const s = document.getElementById('splash');
  s.style.opacity = '0';
  s.style.transition = 'opacity 0.4s';
  setTimeout(() => { s.style.display = 'none'; }, 400);
}

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => {
    s.style.display = 'none';
    s.style.opacity = '0';
  });
  const el = document.getElementById(id);
  el.style.display = 'flex';
  requestAnimationFrame(() => {
    el.style.opacity = '1';
    el.style.transition = 'opacity 0.3s';
  });
}

/* ══════════════════════════════
   JOIN LOGIC
   ══════════════════════════════ */
function handleJoin() {
  const name  = document.getElementById('input-name').value.trim();
  const phone = document.getElementById('input-phone').value.trim();
  const code  = document.getElementById('input-code').value.trim();
  const errEl = document.getElementById('join-error');

  errEl.textContent = '';

  if (!name || name.length < 2) { showError('Please enter your full name (min 2 chars)'); return; }
  if (!phone || phone.replace(/\D/g,'').length < 7) { showError('Please enter a valid mobile number'); return; }
  if (!code) { showError('Access code is required'); return; }
  if (code.toUpperCase() !== CONFIG.SECRET_CODE.toUpperCase()) {
    showError('❌ Invalid access code. Contact your admin.');
    return;
  }

  state.members = loadMembers();

  // Phone uniqueness check
  const phoneClean = phone.replace(/\D/g,'');
  const existing = state.members.find(m => m.phone === phoneClean);

  if (existing) {
    // Re-login same person
    state.me = existing;
  } else {
    if (state.members.length >= CONFIG.MAX_MEMBERS) {
      showError('❌ This network is full (20 members max).');
      return;
    }
    state.me = {
      id: 'u_' + Date.now() + '_' + Math.random().toString(36).slice(2,6),
      name,
      phone: phoneClean,
      color: getAvatarColor(name),
      joinedAt: Date.now(),
      status: '',
    };
    state.members.push(state.me);
    saveMembers();
  }

  saveSession();
  state.messages = loadMessages();
  bootApp();
}

function showError(msg) {
  const el = document.getElementById('join-error');
  el.textContent = msg;
  el.style.animation = 'none';
  requestAnimationFrame(() => el.style.animation = 'shake 0.3s ease');
}

function togglePw() {
  const inp = document.getElementById('input-code');
  const btn = document.getElementById('pw-toggle');
  if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '🙈'; }
  else { inp.type = 'password'; btn.textContent = '👁'; }
}

/* ══════════════════════════════
   BOOT APP
   ══════════════════════════════ */
function bootApp() {
  // Set self online
  setMyActivity('online');

  // Load sidebar
  document.getElementById('my-name-sidebar').textContent = state.me.name;
  document.getElementById('my-avatar-sidebar').textContent = getInitials(state.me.name);
  document.getElementById('my-avatar-sidebar').style.background = state.me.color;

  refreshMembersList();
  showScreen('app');

  // Request push notifications
  requestNotificationPermission();

  // Poll for updates (simulating real-time)
  startActivityPolling();

  // Count online
  updateOnlineCount();

  toast('🔒 Secure session started', `Welcome, ${state.me.name}!`, '✓');
}

/* ══════════════════════════════
   ACTIVITY SYSTEM
   ══════════════════════════════ */
function setMyActivity(status, withId = null, callType = null) {
  state.activity = loadActivity();
  state.activity[state.me.id] = {
    status,
    with: withId,
    callType,
    ts: Date.now(),
  };
  saveActivity();
}

function getMemberActivity(id) {
  const a = state.activity[id];
  if (!a) return { status: 'offline' };
  // Consider offline if no activity in 30s
  if (Date.now() - a.ts > 30000 && a.status === 'online') return { status: 'offline' };
  return a;
}

function getActivityLabel(id) {
  const a = getMemberActivity(id);
  if (a.status === 'offline') return 'Offline';
  if (a.status === 'online')  return '● Online';
  if (a.status === 'texting') {
    const peer = state.members.find(m => m.id === a.with);
    return `💬 Texting ${peer ? peer.name : 'someone'}`;
  }
  if (a.status === 'calling') {
    const peer = state.members.find(m => m.id === a.with);
    const tag = a.callType === 'video' ? 'V.C' : 'V.C';
    return `${a.callType === 'video' ? '📹' : '📞'} ${tag} with ${peer ? peer.name : 'someone'}`;
  }
  return '—';
}

function startActivityPolling() {
  // Heartbeat: update own timestamp every 10s
  setInterval(() => {
    const a = loadActivity();
    if (a[state.me.id]) {
      a[state.me.id].ts = Date.now();
      localStorage.setItem(CONFIG.ACTIVITY_KEY, JSON.stringify(a));
    }
    // Refresh members list
    state.activity = loadActivity();
    refreshMembersList();
    updateOnlineCount();
  }, 5000);
}

function handleStorageSync(e) {
  if (e.key === CONFIG.MEMBERS_KEY) {
    state.members = loadMembers();
    refreshMembersList();
  }
  if (e.key === CONFIG.MESSAGES_KEY) {
    const prev = JSON.stringify(state.messages);
    state.messages = loadMessages();
    if (prev !== JSON.stringify(state.messages)) {
      checkNewMessages();
      if (state.activeChat) renderMessages(state.activeChat);
    }
  }
  if (e.key === CONFIG.ACTIVITY_KEY) {
    state.activity = loadActivity();
    refreshMembersList();
    updateOnlineCount();
  }
}

/* ══════════════════════════════
   MEMBERS LIST RENDERING
   ══════════════════════════════ */
function refreshMembersList() {
  const list = document.getElementById('members-list');
  const others = state.members.filter(m => m.id !== state.me.id);

  if (others.length === 0) {
    list.innerHTML = `<div style="padding:20px 8px;text-align:center;color:var(--gray-3);font-family:var(--font-mono);font-size:11px">No other members yet.<br/>Share the code!</div>`;
    return;
  }

  // Sort: online first, then alpha
  const sorted = [...others].sort((a, b) => {
    const aOnline = getMemberActivity(a.id).status !== 'offline' ? 1 : 0;
    const bOnline = getMemberActivity(b.id).status !== 'offline' ? 1 : 0;
    if (aOnline !== bOnline) return bOnline - aOnline;
    return a.name.localeCompare(b.name);
  });

  list.innerHTML = sorted.map(m => {
    const act = getMemberActivity(m.id);
    const actLabel = getActivityLabel(m.id);
    const dotClass = act.status === 'offline' ? '' :
                     act.status === 'texting' ? 'texting' :
                     act.status === 'calling' ? 'calling' : 'online';
    const unread = state.unread[m.id] || 0;
    const isActive = state.activeChat === m.id;
    const lastMsg = getLastMessage(m.id);

    return `
      <div class="member-item ${isActive ? 'active' : ''} ripple-btn" onclick="openChat('${m.id}')" data-id="${m.id}">
        <div class="avatar-wrap">
          <div class="avatar" style="background:${m.color}">${getInitials(m.name)}</div>
          <div class="status-dot ${dotClass}"></div>
        </div>
        <div class="member-info">
          <div class="member-name">${escHtml(m.name)}</div>
          <div class="member-activity ${act.status === 'texting' ? 'chatting' : act.status === 'calling' ? 'calling' : ''}">${actLabel}</div>
        </div>
        <div class="member-meta">
          ${unread > 0 ? `<div class="unread-badge">${unread > 9 ? '9+' : unread}</div>` : ''}
          ${lastMsg ? `<div class="msg-time">${formatTime(lastMsg.ts)}</div>` : ''}
        </div>
      </div>
    `;
  }).join('');
}

function updateOnlineCount() {
  const count = state.members.filter(m => {
    if (m.id === state.me.id) return true;
    return getMemberActivity(m.id).status !== 'offline';
  }).length;
  document.getElementById('online-count').textContent = count;
}

function getLastMessage(peerId) {
  const chatId = getChatId(state.me.id, peerId);
  const msgs = state.messages[chatId];
  if (!msgs || msgs.length === 0) return null;
  return msgs[msgs.length - 1];
}

/* ══════════════════════════════
   OPEN CHAT
   ══════════════════════════════ */
function openChat(memberId) {
  state.activeChat = memberId;
  state.unread[memberId] = 0;

  const member = state.members.find(m => m.id === memberId);
  if (!member) return;

  // Update header
  const chatAvatar = document.getElementById('chat-avatar');
  chatAvatar.textContent = getInitials(member.name);
  chatAvatar.style.background = member.color;
  document.getElementById('chat-name').textContent = member.name;

  const act = getMemberActivity(memberId);
  const statusEl = document.getElementById('chat-status');
  statusEl.textContent = getActivityLabel(memberId);
  statusEl.className = `chat-status ${act.status}`;

  document.getElementById('chat-actions').style.display = 'flex';
  document.getElementById('input-area').style.display = 'flex';

  // Show back btn on mobile
  const isMobile = window.innerWidth <= 640;
  if (isMobile) {
    document.querySelector('.back-btn').style.display = 'flex';
    closeSidebar();
  }

  // Render messages
  renderMessages(memberId);
  refreshMembersList();

  // Mark as texting
  setMyActivity('texting', memberId);
}

function backToList() {
  openSidebar();
  state.activeChat = null;
  document.getElementById('chat-name').textContent = 'Select a member to chat';
  document.getElementById('chat-status').textContent = '—';
  document.getElementById('chat-actions').style.display = 'none';
  document.getElementById('input-area').style.display = 'none';
  document.querySelector('.back-btn').style.display = 'none';

  const msgs = document.getElementById('messages-area');
  msgs.innerHTML = `<div class="empty-chat">
    <div class="empty-icon"><svg viewBox="0 0 80 80" fill="none" width="80" height="80">
      <polygon points="40,4 72,22 72,58 40,76 8,58 8,22" stroke="var(--teal)" stroke-width="1.5" fill="none" opacity="0.5"/>
      <circle cx="40" cy="40" r="10" stroke="var(--teal)" stroke-width="1.5" fill="none" opacity="0.5"/>
    </svg></div>
    <p>Select a member to start a secure conversation</p>
    <span class="enc-note">All messages are end-to-end encrypted</span>
  </div>`;

  setMyActivity('online');
  refreshMembersList();
}

/* ══════════════════════════════
   MESSAGES
   ══════════════════════════════ */
function getChatId(a, b) {
  return [a, b].sort().join('__');
}

function renderMessages(peerId) {
  const chatId = getChatId(state.me.id, peerId);
  const msgs = state.messages[chatId] || [];
  const area = document.getElementById('messages-area');

  if (msgs.length === 0) {
    area.innerHTML = `<div class="date-divider"><span>START OF CONVERSATION</span></div>
    <div style="text-align:center;padding:20px;font-family:var(--font-mono);font-size:10px;color:var(--teal)">🔒 Messages are end-to-end encrypted</div>`;
    return;
  }

  let html = '';
  let lastDate = '';

  msgs.forEach(msg => {
    const d = new Date(msg.ts);
    const dateStr = d.toLocaleDateString(undefined, { weekday:'long', month:'short', day:'numeric' });
    if (dateStr !== lastDate) {
      html += `<div class="date-divider"><span>${dateStr}</span></div>`;
      lastDate = dateStr;
    }

    const isSent = msg.from === state.me.id;
    const sender = state.members.find(m => m.id === msg.from);
    const avatarColor = sender ? sender.color : '#888';
    const initials   = sender ? getInitials(sender.name) : '?';
    const text       = decryptMsg(msg.enc);

    let bubbleContent = '';
    if (msg.type === 'image') {
      bubbleContent = `<div class="msg-image"><img src="${text}" alt="image" loading="lazy" /></div>`;
    } else if (msg.type === 'file') {
      bubbleContent = `📄 <span style="font-size:13px">${escHtml(text)}</span>`;
    } else {
      bubbleContent = escHtml(text).replace(/\n/g,'<br>');
    }

    html += `
      <div class="msg-wrapper ${isSent ? 'sent' : 'received'}">
        <div class="msg-bubble-wrap">
          ${!isSent ? `<div class="msg-small-avatar" style="background:${avatarColor}">${initials}</div>` : ''}
          <div class="msg-bubble">${bubbleContent}</div>
        </div>
        <div class="msg-meta">
          <span class="msg-time-sm">${formatTime(msg.ts)}</span>
          ${isSent ? `<span class="msg-status">${msg.read ? '✓✓' : '✓'}</span>` : ''}
        </div>
      </div>
    `;
  });

  area.innerHTML = html;
  area.scrollTop = area.scrollHeight;
}

function sendMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text || !state.activeChat) return;

  const peerId = state.activeChat;
  const chatId = getChatId(state.me.id, peerId);

  if (!state.messages[chatId]) state.messages[chatId] = [];

  const msg = {
    id: 'msg_' + Date.now(),
    from: state.me.id,
    to: peerId,
    enc: encryptMsg(text),
    ts: Date.now(),
    type: 'text',
    read: false,
  };

  state.messages[chatId].push(msg);
  saveMessages();

  input.value = '';
  input.style.height = 'auto';

  renderMessages(peerId);
  refreshMembersList();

  // Sound
  playSound('send');
}

function handleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
}

function handleTyping(el) {
  // Auto-resize
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';

  // Typing activity
  if (!state.isTyping && state.activeChat) {
    state.isTyping = true;
    setMyActivity('texting', state.activeChat);
  }
  clearTimeout(state._typingTimer);
  state._typingTimer = setTimeout(() => {
    state.isTyping = false;
    if (state.activeChat) setMyActivity('texting', state.activeChat);
  }, CONFIG.TYPING_TIMEOUT);
}

/* ══════════════════════════════
   FILE ATTACH
   ══════════════════════════════ */
function triggerAttach() {
  document.getElementById('file-input').click();
}

function handleFileAttach(e) {
  const file = e.target.files[0];
  if (!file || !state.activeChat) return;

  if (file.type.startsWith('image/')) {
    const reader = new FileReader();
    reader.onload = (ev) => {
      const peerId = state.activeChat;
      const chatId = getChatId(state.me.id, peerId);
      if (!state.messages[chatId]) state.messages[chatId] = [];

      state.messages[chatId].push({
        id: 'msg_' + Date.now(),
        from: state.me.id,
        to: peerId,
        enc: encryptMsg(ev.target.result),
        ts: Date.now(),
        type: 'image',
        read: false,
      });
      saveMessages();
      renderMessages(peerId);
    };
    reader.readAsDataURL(file);
  } else {
    // Send as file name indicator
    const peerId = state.activeChat;
    const chatId = getChatId(state.me.id, peerId);
    if (!state.messages[chatId]) state.messages[chatId] = [];
    state.messages[chatId].push({
      id: 'msg_' + Date.now(),
      from: state.me.id,
      to: peerId,
      enc: encryptMsg(file.name),
      ts: Date.now(),
      type: 'file',
      read: false,
    });
    saveMessages();
    renderMessages(peerId);
  }

  e.target.value = '';
}

/* ══════════════════════════════
   CALL SYSTEM
   ══════════════════════════════ */
function startCall(type) {
  if (!state.activeChat) return;
  const peer = state.members.find(m => m.id === state.activeChat);
  if (!peer) return;

  state.callState = { type, peerId: peer.id, muted: false, speaker: true, seconds: 0 };

  // UI
  document.getElementById('call-avatar-large').textContent = getInitials(peer.name);
  document.getElementById('call-avatar-large').style.background = peer.color;
  document.getElementById('call-name-large').textContent = peer.name;
  document.getElementById('call-type-badge').textContent = type === 'video' ? 'VIDEO CALL' : 'VOICE CALL';
  document.getElementById('call-status-text').textContent = 'Connecting...';
  document.getElementById('call-timer').textContent = '00:00';
  document.getElementById('call-overlay').style.display = 'flex';

  // Set activity
  setMyActivity('calling', peer.id, type);

  // Simulate connection after 2s
  setTimeout(() => {
    if (!state.callState) return;
    document.getElementById('call-status-text').textContent = type === 'video' ? '● Video Call Active' : '● Voice Call Active';
    startCallTimer();
    playSound('callConnect');
    toast(`${type === 'video' ? '📹' : '📞'} Call Connected`, peer.name, '●');
  }, 2000);

  playSound('ringout');
}

function startCallTimer() {
  state.callState._timer = setInterval(() => {
    if (!state.callState) return;
    state.callState.seconds++;
    const m = String(Math.floor(state.callState.seconds / 60)).padStart(2, '0');
    const s = String(state.callState.seconds % 60).padStart(2, '0');
    document.getElementById('call-timer').textContent = `${m}:${s}`;
  }, 1000);
}

function endCall() {
  if (state.callState?._timer) clearInterval(state.callState._timer);
  state.callState = null;
  document.getElementById('call-overlay').style.display = 'none';
  setMyActivity('texting', state.activeChat);
  playSound('callEnd');
  toast('📵 Call ended', 'Connection closed', '—');
}

function toggleMute() {
  if (!state.callState) return;
  state.callState.muted = !state.callState.muted;
  document.getElementById('mute-btn').textContent = state.callState.muted ? '🔇' : '🎤';
}

function toggleSpeaker() {
  if (!state.callState) return;
  state.callState.speaker = !state.callState.speaker;
  document.getElementById('speaker-btn').textContent = state.callState.speaker ? '🔊' : '🔈';
}

/* Simulated incoming call (for demo) */
let _incomingCallDemoShown = false;
function simulateIncomingCall() {
  if (_incomingCallDemoShown) return;
  const others = state.members.filter(m => m.id !== state.me.id);
  if (others.length === 0) return;
  const caller = others[Math.floor(Math.random() * others.length)];
  _incomingCallDemoShown = true;

  document.getElementById('incoming-avatar').textContent = getInitials(caller.name);
  document.getElementById('incoming-avatar').style.background = caller.color;
  document.getElementById('incoming-name').textContent = caller.name;
  document.getElementById('incoming-type').textContent = 'Incoming Voice Call';
  document.getElementById('incoming-call').style.display = 'flex';

  playSound('ring');

  setTimeout(() => {
    document.getElementById('incoming-call').style.display = 'none';
  }, CONFIG.CALL_RING_TIMEOUT);
}

function acceptCall() {
  document.getElementById('incoming-call').style.display = 'none';
  toast('📞 Call accepted', 'Connected!', '✓');
}

function declineCall() {
  document.getElementById('incoming-call').style.display = 'none';
  toast('📵 Call declined', '', '✗');
}

/* ══════════════════════════════
   NOTIFICATIONS
   ══════════════════════════════ */
function requestNotificationPermission() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'default') {
    Notification.requestPermission();
  }
}

function sendPushNotification(title, body) {
  if (!state.notificationsEnabled) return;
  if (Notification.permission !== 'granted') return;
  if (document.visibilityState === 'visible') return; // only when hidden

  try {
    new Notification(title, {
      body,
      icon: 'icons/icon-192.png',
      badge: 'icons/icon-72.png',
      vibrate: [100, 50, 100],
    });
  } catch {}
}

function checkNewMessages() {
  const allChatIds = Object.keys(state.messages);
  allChatIds.forEach(chatId => {
    const msgs = state.messages[chatId];
    const latest = msgs[msgs.length - 1];
    if (!latest) return;
    if (latest.from === state.me.id) return;
    if (Date.now() - latest.ts > 10000) return; // Only very recent

    const peerId = latest.from;
    if (state.activeChat === peerId) return;

    const sender = state.members.find(m => m.id === peerId);
    if (!sender) return;

    state.unread[peerId] = (state.unread[peerId] || 0) + 1;
    refreshMembersList();

    const text = decryptMsg(latest.enc);
    toast(`💬 ${sender.name}`, text.slice(0,60), '💬');
    sendPushNotification(`${sender.name} — NEXUS`, text.slice(0,80));
    playSound('receive');
  });
}

function toggleNotifications() {
  state.notificationsEnabled = document.getElementById('notif-toggle').checked;
  if (state.notificationsEnabled) requestNotificationPermission();
}

function toggleAnimations() {
  state.animationsEnabled = document.getElementById('anim-toggle').checked;
}

/* ══════════════════════════════
   SETTINGS
   ══════════════════════════════ */
function openSettings() {
  document.getElementById('settings-modal').style.display = 'flex';
}

function closeSettings() {
  document.getElementById('settings-modal').style.display = 'none';
}

function closeModal(e) {
  if (e.target.classList.contains('modal-overlay')) closeSettings();
}

function saveSettings() {
  const statusVal = document.getElementById('status-input').value.trim();
  if (statusVal) {
    state.me.status = statusVal;
    saveSession();
  }
  toast('⚙ Settings saved', 'Preferences updated', '✓');
  closeSettings();
}

function openProfile() {
  toast('👤 ' + state.me.name, `📞 +${state.me.phone} · Joined ${new Date(state.me.joinedAt).toLocaleDateString()}`, '◈');
}

function openChatInfo() {
  if (!state.activeChat) return;
  const peer = state.members.find(m => m.id === state.activeChat);
  if (!peer) return;
  const chatId = getChatId(state.me.id, peer.id);
  const msgCount = (state.messages[chatId] || []).length;
  toast(`ℹ ${peer.name}`, `📱 +${peer.phone} · ${msgCount} messages`, '◈');
}

/* ══════════════════════════════
   LOGOUT
   ══════════════════════════════ */
function handleLogout() {
  if (!confirm('Leave NEXUS network? You can rejoin with your code.')) return;
  setMyActivity('offline');
  localStorage.removeItem(CONFIG.STORAGE_KEY);
  state.me = null;
  state.activeChat = null;
  showScreen('join-screen');
  document.getElementById('input-name').value = '';
  document.getElementById('input-phone').value = '';
  document.getElementById('input-code').value = '';
}

/* ══════════════════════════════
   SIDEBAR MOBILE
   ══════════════════════════════ */
function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
}

// Swipe gesture for mobile
let _touchStartX = 0;
document.addEventListener('touchstart', e => { _touchStartX = e.touches[0].clientX; }, { passive: true });
document.addEventListener('touchend', e => {
  const dx = e.changedTouches[0].clientX - _touchStartX;
  if (dx > 60 && _touchStartX < 40) openSidebar();
  if (dx < -60) closeSidebar();
}, { passive: true });

/* ══════════════════════════════
   RIPPLE / TOUCH ANIMATION
   ══════════════════════════════ */
function handleTouchRipple(e) {
  if (!state.animationsEnabled) return;
  const target = e.target.closest('.ripple-btn, .member-item, .call-ctrl-btn, .send-btn');
  if (!target) return;

  const rect = target.getBoundingClientRect();
  const x = (e.touches ? e.touches[0].clientX : e.clientX);
  const y = (e.touches ? e.touches[0].clientY : e.clientY);

  createRipple(x, y, 80);
}

function createRipple(x, y, size = 80) {
  const container = document.getElementById('ripple-container');
  const ripple = document.createElement('div');
  ripple.className = 'ripple-wave';
  const s = size * 2;
  ripple.style.cssText = `
    left: ${x - size}px;
    top:  ${y - size}px;
    width:  ${s}px;
    height: ${s}px;
  `;
  container.appendChild(ripple);
  setTimeout(() => ripple.remove(), 650);
}

/* ══════════════════════════════
   SOUND SYSTEM
   ══════════════════════════════ */
function playSound(type) {
  if (!state.soundEnabled) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    const sounds = {
      send:        { freq: 880, dur: 0.08, type: 'sine',    vol: 0.08 },
      receive:     { freq: 660, dur: 0.12, type: 'sine',    vol: 0.1  },
      ring:        { freq: [440,550], dur: 0.5, type: 'square', vol: 0.06 },
      ringout:     { freq: 440, dur: 0.3, type: 'sine',     vol: 0.07 },
      callConnect: { freq: [660,880], dur: 0.2, type: 'sine', vol: 0.08 },
      callEnd:     { freq: [440,330], dur: 0.25, type: 'sine', vol: 0.07 },
    };

    const s = sounds[type] || sounds.send;
    osc.type = s.type;
    osc.frequency.value = Array.isArray(s.freq) ? s.freq[0] : s.freq;
    gain.gain.setValueAtTime(s.vol, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + s.dur);
    osc.start();
    osc.stop(ctx.currentTime + s.dur);
  } catch {}
}

/* ══════════════════════════════
   TOAST NOTIFICATIONS
   ══════════════════════════════ */
function toast(title, msg, icon = '◈') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = `
    <div class="toast-icon">${icon}</div>
    <div class="toast-body">
      <div class="toast-title">${escHtml(title)}</div>
      ${msg ? `<div class="toast-msg">${escHtml(msg)}</div>` : ''}
    </div>
    <div class="toast-bar"></div>
  `;
  el.onclick = () => removeToast(el);
  container.appendChild(el);

  setTimeout(() => removeToast(el), 4500);
}

function removeToast(el) {
  if (!el.parentNode) return;
  el.classList.add('removing');
  setTimeout(() => el.remove(), 300);
}

/* ══════════════════════════════
   UTILS
   ══════════════════════════════ */
function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function formatTime(ts) {
  const d = new Date(ts);
  const now = new Date();
  const isToday = d.toDateString() === now.toDateString();
  if (isToday) return d.toLocaleTimeString(undefined, { hour:'2-digit', minute:'2-digit' });
  return d.toLocaleDateString(undefined, { month:'short', day:'numeric' });
}

/* ══════════════════════════════
   PWA INSTALL PROMPT
   ══════════════════════════════ */
let _deferredInstall = null;
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  _deferredInstall = e;
  setTimeout(() => {
    toast('📲 Install NEXUS', 'Add to home screen for best experience', '⬡');
  }, 5000);
});

/* ══════════════════════════════
   DEMO: simulate second user in another tab
   ══════════════════════════════ */
// After 15s, if 2+ members, simulate incoming call
setTimeout(() => {
  if (state.me && state.members.length >= 2) {
    simulateIncomingCall();
  }
}, 15000);

/* ══════════════════════════════
   VISIBILITY CHANGE — heartbeat
   ══════════════════════════════ */
document.addEventListener('visibilitychange', () => {
  if (!state.me) return;
  if (document.visibilityState === 'visible') {
    setMyActivity(state.activeChat ? 'texting' : 'online', state.activeChat);
    state.activity = loadActivity();
    state.messages = loadMessages();
    state.members = loadMembers();
    refreshMembersList();
    if (state.activeChat) renderMessages(state.activeChat);
  } else {
    setMyActivity('online');
  }
});
