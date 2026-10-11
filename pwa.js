// PWA bootstrap: register service worker; launch the mini app when started from the iOS Home Screen.
(function () {
    const standalone = window.navigator.standalone === true ||
        (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);
    if (standalone) {
        document.documentElement.classList.add('is-standalone');
        const page = location.pathname.split('/').pop() || 'index.html';
        if (page === 'index.html' && !sessionStorage.getItem('gameOS_pwa_started')) {
            sessionStorage.setItem('gameOS_pwa_started', '1');
            location.replace('app.html');
        }
    }
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => {}));
    }
})();
