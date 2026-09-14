import type { JSX } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { ThemeBoot } from "./components/ThemeSwitcher";
import { isDemoAuthed } from "./demoAuth";
import { DEMO_MODE } from "./demoStore";
import { Dashboard } from "./pages/Dashboard";
import { Landing } from "./pages/Landing";
import { Login } from "./pages/Login";

function RequireDemoAuth({ children }: { children: JSX.Element }) {
  return isDemoAuthed() ? children : <Navigate to="/login" replace />;
}

function App() {
  // Outside demo mode this is the real, backend-connected dashboard — an
  // operator running `docker compose up` should land straight on it, not
  // on marketing copy or a decorative login. The Landing → Login flow
  // only exists for the portfolio-facing demo build.
  if (!DEMO_MODE) {
    return <Dashboard />;
  }

  return (
    <>
      <ThemeBoot />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route
          path="/dashboard"
          element={
            <RequireDemoAuth>
              <Dashboard />
            </RequireDemoAuth>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}

export default App;
