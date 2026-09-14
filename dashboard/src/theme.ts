/**
 * The customizable signal palette. Swapping themes only ever touches
 * --accent/--accent-2 (see index.css) — never the neutrals or the
 * severity ramp — so a viewer can restyle the whole app (Landing,
 * Login, Dashboard alike, since they all read the same tokens) without
 * ever making an alert harder to read.
 */

export interface ThemeOption {
  id: "brass" | "crimson" | "violet";
  label: string;
  accent: string;
  accent2: string;
}

export const THEMES: ThemeOption[] = [
  { id: "brass", label: "Signal Brass", accent: "#d3a03c", accent2: "#49c9c2" },
  { id: "crimson", label: "Crimson Watch", accent: "#e0475e", accent2: "#7c9cff" },
  { id: "violet", label: "Violet Spectrum", accent: "#b98cf0", accent2: "#58e6a6" },
];

const KEY = "nids_theme";

export function getStoredTheme(): ThemeOption["id"] {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "crimson" || v === "violet" || v === "brass") return v;
  } catch {
    // Storage unavailable — fall through to the default.
  }
  return "brass";
}

export function applyTheme(id: ThemeOption["id"]): void {
  if (id === "brass") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", id);
  }
  try {
    localStorage.setItem(KEY, id);
  } catch {
    // Fine — it just won't stick across a reload this time.
  }
}
