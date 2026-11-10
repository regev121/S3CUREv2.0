import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import { MainLayout, AuthLayout } from "./layout";
import { PrivateRoute } from "./components/PrivateRoute";
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import NotFound from "./pages/NotFound";
import Dashboard from "./pages/Dashboard";
import Scan from "./pages/Scan";
import Simulation from "./pages/Simulation";
import IamManager from "./pages/IamManager";
import Config from "./pages/Config";

function ProtectedRoutes() {
  return (
    <>
      <Route
        path="/"
        element={
          <PrivateRoute>
            <MainLayout />
          </PrivateRoute>
        }
      >
        {/* Nested under / so: index = /, dashboard = /dashboard, etc. */}
        <Route index element={<Navigate to="/scan" replace />} />
        <Route path="dashboard" element={<PrivateRoute roles={["ADMIN", "AUDITOR"]}><Dashboard /></PrivateRoute>} />
        <Route path="scan" element={<Scan />} />
        <Route path="simulation" element={<PrivateRoute roles={["ADMIN"]}><Simulation /></PrivateRoute>} />
        <Route path="iam" element={<PrivateRoute roles={["ADMIN"]}><IamManager /></PrivateRoute>} />
        <Route path="config" element={<PrivateRoute roles={["ADMIN"]}><Config /></PrivateRoute>} />
      </Route>
    </>
  );
}

function AppRoutes() {
  return (
    <Routes>
      <Route element={<AuthLayout />}>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
      </Route>
      {ProtectedRoutes()}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
