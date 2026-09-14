/**
 * Demo mode's "login" gates nothing real — there's no user database
 * anywhere in this project (see demoStore.ts). It exists so the Landing
 * → Login → Dashboard flow reads like a real product, not to actually
 * authenticate anyone. This just remembers that a viewer clicked through
 * the gate once, so refreshing /dashboard doesn't bounce them back to
 * /login every time.
 */

const KEY = "nids_demo_authed";

export function isDemoAuthed(): boolean {
  try {
    return sessionStorage.getItem(KEY) === "1";
  } catch {
    // Private browsing / blocked storage — fail open to "not authed" so
    // the flow still makes sense (you just re-click through each visit).
    return false;
  }
}

export function setDemoAuthed(value: boolean): void {
  try {
    if (value) sessionStorage.setItem(KEY, "1");
    else sessionStorage.removeItem(KEY);
  } catch {
    // Nothing to fall back to — the gate just won't "stick" this session.
  }
}
