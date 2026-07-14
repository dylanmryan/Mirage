// Minimal live-feed poller (HTMX-swappable later). Refreshes any [data-poll] region.
document.querySelectorAll("[data-poll]").forEach((el) => {
  const url = el.getAttribute("data-poll");
  setInterval(async () => {
    try {
      const r = await fetch(url);
      if (r.ok) el.innerHTML = await r.text();
    } catch (e) { /* transient; retry next tick */ }
  }, 5000);
});
