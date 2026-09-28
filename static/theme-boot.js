// Theme bootstrap - referenced from socrates.html's <head> WITHOUT
// defer/async so it parser-blocks and sets data-theme before first paint
// (prevents a flash of the default dark theme for users on other themes).
// Kept as a separate file, not inline, so the Content-Security-Policy can
// be a strict script-src 'self' with no inline-script carve-outs.
(function () {
    try {
        var t = localStorage.getItem('socrates-theme');
        // Renamed themes: 'light' became 'white', and 'c64' (3.0.0-3.1.0)
        // became 'breadbin-blue'. Any other unknown key falls back to the
        // default in socrates.js's init().
        if (t == 'light') localStorage.setItem('socrates-theme', t = 'white');
        if (t == 'c64') localStorage.setItem('socrates-theme', t = 'breadbin-blue');
        if (t && t != 'dark') document.documentElement.setAttribute('data-theme', t);
    } catch (e) {}
})();
