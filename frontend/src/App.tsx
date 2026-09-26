import { Navigate, Route, Routes } from "react-router-dom";

import { RequireAuth, RequireRole } from "./auth/guards";
import { AppLayout } from "./layouts/AppLayout";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { AlertsPage } from "./pages/AlertsPage";
import { AuditPage } from "./pages/AuditPage";
import { CorrelationSettingsPage } from "./pages/CorrelationSettingsPage";
import { IncidentDetailPage } from "./pages/IncidentDetailPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { LoginPage } from "./pages/LoginPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { SettingsPage } from "./pages/SettingsPage";
import { StatusPage } from "./pages/StatusPage";
import { UsersPage } from "./pages/UsersPage";

/** Routes only; the router and AuthProvider come from main.tsx (or from tests). */
export function App() {
  return (
    <Routes>
      <Route path="login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppLayout />}>
          <Route index element={<Navigate to="/status" replace />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="alerts/:alertId" element={<AlertDetailPage />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
          <Route path="status" element={<StatusPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route element={<RequireRole minimum="ADMIN" />}>
            <Route path="users" element={<UsersPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="correlation" element={<CorrelationSettingsPage />} />
          </Route>
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  );
}
