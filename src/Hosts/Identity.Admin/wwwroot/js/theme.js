// Light / dark / system appearance. The server renders <html data-theme> from the "avash-theme" cookie, so the
// first paint is already right; this script only switches it. Any element with data-theme-option="light|dark|system"
// is a switch, on static pages and interactive components alike (no Blazor interop needed).
(() => {
    const cookie = "avash-theme";
    const modes = ["light", "dark", "system"];
    const root = document.documentElement;

    const current = () => (modes.includes(root.dataset.theme) ? root.dataset.theme : "system");

    const sync = () => {
        for (const option of document.querySelectorAll("[data-theme-option]")) {
            option.setAttribute("aria-pressed", String(option.dataset.themeOption === current()));
        }
    };

    const set = (mode) => {
        if (!modes.includes(mode)) return;
        root.dataset.theme = mode;
        document.cookie = `${cookie}=${mode}; path=/; max-age=31536000; samesite=lax`;
        sync();
    };

    // Skip link: move keyboard focus (not only the scroll position) into the main region.
    document.addEventListener("click", (event) => {
        const skip = event.target.closest("a.av-skip-link");
        if (!skip) return;
        const target = document.getElementById(skip.getAttribute("href").slice(1));
        if (!target) return;
        event.preventDefault();
        target.focus();
    });

    document.addEventListener("click", (event) => {
        const option = event.target.closest("[data-theme-option]");
        if (!option) return;
        event.preventDefault();
        set(option.dataset.themeOption);
    });

    // Interactive components render their switches after this script ran.
    new MutationObserver(sync).observe(root, { childList: true, subtree: true });
    window.avashTheme = { set, current };
    sync();
})();
