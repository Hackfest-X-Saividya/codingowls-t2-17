"use client";

import { useSyncExternalStore } from "react";

import { STORAGE_KEY } from "@/lib/theme-script";

// The theme lives on <html data-theme="dark|light">. THEME_INIT_SCRIPT (lib/theme-script.ts) sets
// it before the first paint; the toggle changes it and saves the choice.
export type Theme = "dark" | "light";

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function setTheme(theme: Theme, remember = true) {
  document.documentElement.dataset.theme = theme;
  if (!remember) return;
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // storage blocked (private mode): the choice lasts until the page is reloaded
  }
}

export function hasSavedTheme(): boolean {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved === "light" || saved === "dark";
  } catch {
    return false;
  }
}

function subscribe(onChange: () => void) {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  return () => observer.disconnect();
}

/** The active theme, for components that pick colours in code (charts, syntax highlighting). */
export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, currentTheme, () => "dark");
}
