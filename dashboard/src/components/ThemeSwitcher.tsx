import { useEffect, useState } from "react";
import { applyTheme, getStoredTheme, THEMES, type ThemeOption } from "../theme";
import "./ThemeSwitcher.css";

/** Applies whatever theme was last picked as soon as the app mounts —
 * lives at the root so it runs once regardless of which page loads
 * first. */
export function ThemeBoot() {
  useEffect(() => {
    applyTheme(getStoredTheme());
  }, []);
  return null;
}

export function ThemeSwitcher() {
  const [active, setActive] = useState<ThemeOption["id"]>(getStoredTheme());

  const pick = (id: ThemeOption["id"]) => {
    applyTheme(id);
    setActive(id);
  };

  return (
    <div className="theme-switcher" role="group" aria-label="Signal color">
      {THEMES.map((t) => (
        <button
          key={t.id}
          type="button"
          className={`theme-swatch ${active === t.id ? "is-active" : ""}`}
          style={{ background: `linear-gradient(135deg, ${t.accent}, ${t.accent2})` }}
          onClick={() => pick(t.id)}
          title={t.label}
          aria-label={t.label}
          aria-pressed={active === t.id}
        />
      ))}
    </div>
  );
}
