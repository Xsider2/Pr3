/* Smart Study — общий скрипт интерфейса */
(function () {
    "use strict";

    var sidebar = document.getElementById("sidebar");
    var scrim = document.getElementById("scrim");
    var toggle = document.getElementById("menuToggle");

    function closeSidebar() {
        if (!sidebar) return;
        sidebar.classList.remove("is-open");
        if (scrim) scrim.classList.remove("is-open");
        if (toggle) toggle.setAttribute("aria-expanded", "false");
    }

    function openSidebar() {
        if (!sidebar) return;
        sidebar.classList.add("is-open");
        if (scrim) scrim.classList.add("is-open");
        if (toggle) toggle.setAttribute("aria-expanded", "true");
    }

    if (toggle) {
        toggle.addEventListener("click", function () {
            if (sidebar && sidebar.classList.contains("is-open")) {
                closeSidebar();
            } else {
                openSidebar();
            }
        });
    }
    if (scrim) scrim.addEventListener("click", closeSidebar);
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") closeSidebar();
    });

    document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
        el.addEventListener("change", function () {
            if (el.form) el.form.submit();
        });
    });

    document.querySelectorAll("[data-confirm]").forEach(function (el) {
        el.addEventListener("submit", function (e) {
            if (!window.confirm(el.getAttribute("data-confirm"))) {
                e.preventDefault();
            }
        });
    });

    document.querySelectorAll("[data-note-toggle]").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var target = document.getElementById(btn.getAttribute("data-note-toggle"));
            if (!target) return;
            var hidden = target.hasAttribute("hidden");
            if (hidden) {
                target.removeAttribute("hidden");
                var field = target.querySelector("textarea");
                if (field) field.focus();
            } else {
                target.setAttribute("hidden", "");
            }
        });
    });

    // Подтверждение для кнопок вне форм с data-confirm (например, «Отключить Moodle»).
    document.querySelectorAll("[data-confirm-click]").forEach(function (el) {
        el.addEventListener("click", function (e) {
            if (!window.confirm(el.getAttribute("data-confirm-click"))) {
                e.preventDefault();
            }
        });
    });

    // Ссылка «Назад» на страницах ошибок: возвращает на прошлую страницу, если она есть.
    document.querySelectorAll("[data-back]").forEach(function (el) {
        el.addEventListener("click", function (e) {
            if (window.history.length > 1) {
                e.preventDefault();
                window.history.back();
            }
        });
    });

    // Вкладки-якоря (Настройки): подсвечиваем ту, что соответствует адресу #раздела.
    var anchorTabs = document.querySelectorAll(".tabs .tab[href^='#']");
    function syncTabs() {
        if (!anchorTabs.length) return;
        var current = window.location.hash || anchorTabs[0].getAttribute("href");
        anchorTabs.forEach(function (tab) {
            tab.classList.toggle("is-active", tab.getAttribute("href") === current);
        });
    }
    window.addEventListener("hashchange", syncTabs);
    syncTabs();
})();
