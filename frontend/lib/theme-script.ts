// Kept out of lib/theme.ts ("use client") so the server layout can inline it in <head>.
export const STORAGE_KEY = "theme";

// Runs before the first paint: the saved choice, else the system preference (no flash of the wrong theme)
export const THEME_INIT_SCRIPT = `(function(){var d=document.documentElement,t;try{t=localStorage.getItem("${STORAGE_KEY}")}catch(e){}
if(t!=="light"&&t!=="dark"){t=window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"}
d.dataset.theme=t})()`;
