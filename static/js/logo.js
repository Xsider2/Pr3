/* Smart Study — бренд-знак: академическая шапочка + перо (по фото 5 и 6) */
(function () {
    "use strict";
    var target = document.getElementById("logo-mark");
    if (!target) return;
    var svg = [
        '<svg class="logo__mark" viewBox="0 0 64 64" role="img" aria-label="Smart Study">',
        '<rect x="1" y="1" width="62" height="62" rx="18" fill="#59171b"/>',
        '<path d="M32 12 8 21.5 32 31l24-9.5z" fill="#fca311"/>',
        '<path d="M32 33.5 14 26.2v7.1c0 5.7 8.1 10.2 18 10.2s18-4.5 18-10.2v-7.1z" fill="#fed7b8"/>',
        '<path d="M32 44.5v5.5l-4.5 2 4.5 2 4.5-2-4.5-2z" fill="#fbe6d3" opacity=".85"/>',
        '<path d="M52 23.5v11.4" stroke="#fca311" stroke-width="2" stroke-linecap="round"/>',
        '<circle cx="52" cy="37.4" r="2.6" fill="#fca311"/>',
        '<circle cx="32" cy="21.5" r="2.2" fill="#59171b" opacity=".55"/>',
        "</svg>"
    ].join("");
    target.innerHTML = svg;
})();
