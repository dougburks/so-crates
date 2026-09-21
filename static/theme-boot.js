// Theme bootstrap - referenced from socrates.html's <head> WITHOUT
// defer/async so it parser-blocks and sets data-theme before first paint
// (prevents a flash of the default dark theme for users on other themes).
// Kept as a separate file, not inline, so the Content-Security-Policy can
// be a strict script-src 'self' with no inline-script carve-outs.
(function () {
    try {
        var t = localStorage.getItem('socrates-theme');
        if (t == 'light') localStorage.setItem('socrates-theme', t = 'white');
        if (t && t != 'dark') document.documentElement.setAttribute('data-theme', t);
    } catch (e) {}
})();
