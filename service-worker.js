const CACHE_NAME = "freela-b-hub-comercial-v19";
const ASSETS = ["./", "index.html", "admin.html", "manifest.json", "icon.svg", "freelab-hub-logo.png", "leaflet.css", "leaflet.js", "privacy.html", "terms.html", "delete-account.html", "CHECKLIST-LANCAMENTO.txt", "app-icon-192.png", "app-icon-512.png", "app-icon-maskable-512.png"];

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS)));
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))
    )
  );
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") return;
  event.respondWith(
    fetch(event.request)
      .then(response => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
