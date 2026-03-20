/* ════════════════════════════════════════════
   NEXUS CHAT · SERVICE WORKER
   Handles: Caching, Offline, Push Notifications
   ════════════════════════════════════════════ */

'use strict';

const CACHE_NAME  = 'nexus-v2.0.0';
const STATIC_URLS = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/manifest.json',
  'https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap',
];

/* ── INSTALL: Cache static assets ── */
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache =>
      cache.addAll(STATIC_URLS).catch(() => {})
    ).then(() => self.skipWaiting())
  );
});

/* ── ACTIVATE: Clean old caches ── */
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

/* ── FETCH: Network-first, fallback to cache ── */
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);
  // Skip non-http requests
  if (!url.protocol.startsWith('http')) return;

  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Cache successful responses
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() =>
        caches.match(event.request).then(cached => {
          if (cached) return cached;
          // Offline fallback for navigation
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html');
          }
        })
      )
  );
});

/* ── PUSH: Show notification ── */
self.addEventListener('push', event => {
  let data = { title: 'NEXUS', body: 'New message', icon: '/icons/icon-192.png' };
  try { data = { ...data, ...event.data.json() }; } catch {}

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body:    data.body,
      icon:    data.icon || '/icons/icon-192.png',
      badge:   '/icons/icon-72.png',
      vibrate: [100, 50, 100, 50, 100],
      tag:     'nexus-msg',
      renotify: true,
      data:    { url: '/' },
      actions: [
        { action: 'open',   title: 'Open' },
        { action: 'dismiss', title: 'Dismiss' },
      ],
    })
  );
});

/* ── NOTIFICATION CLICK ── */
self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'dismiss') return;

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const client of list) {
        if (client.url.includes(self.location.origin)) {
          return client.focus();
        }
      }
      return clients.openWindow('/');
    })
  );
});

/* ── BACKGROUND SYNC (for queued messages) ── */
self.addEventListener('sync', event => {
  if (event.tag === 'nexus-sync') {
    // Messages are localStorage-based, nothing to sync
    event.waitUntil(Promise.resolve());
  }
});
