/**
 * mSAS v2 — Service Worker
 * 
 * PWA offline caching for core static assets.
 * Part of Phase 8: UX Polish (UX-3).
 */

var CACHE_NAME = 'msas-v2-cache-v1';

var PRECACHE_URLS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/favicon.svg',
  '/mask-icon.svg',
  '/lib/styles.css',
  '/lib/test-result.js',
  '/lib/utils.js',
  '/lib/report-generator.js',
  '/lib/cvss-calculator.js',
  '/lib/risk-matrix.js',
  '/lib/dashboard.js',
  '/lib/scan-history.js',
  '/lib/jszip.min.js',
  '/lib/jspdf.umd.min.js',
  '/apk-auditor/',
  '/ipa-auditor/',
  '/adb-auditor/',
  '/about/'
];

// Install: cache core assets
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(PRECACHE_URLS);
    }).then(function() {
      return self.skipWaiting();
    })
  );
});

// Activate: clean old caches
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      return Promise.all(
        cacheNames.filter(function(name) {
          return name !== CACHE_NAME;
        }).map(function(name) {
          return caches.delete(name);
        })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// Fetch: network-first with cache fallback
self.addEventListener('fetch', function(event) {
  // Skip non-GET and chrome-extension requests
  if (event.request.method !== 'GET') return;
  if (event.request.url.indexOf('chrome-extension') === 0) return;

  event.respondWith(
    fetch(event.request).then(function(response) {
      // Cache successful responses
      if (response.status === 200 && response.type === 'basic') {
        var responseClone = response.clone();
        caches.open(CACHE_NAME).then(function(cache) {
          cache.put(event.request, responseClone);
        });
      }
      return response;
    }).catch(function() {
      // Offline: serve from cache
      return caches.match(event.request).then(function(cached) {
        return cached || caches.match('/');
      });
    })
  );
});
