import { NavLink, useNavigate, useLocation } from "react-router-dom";
import { Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  ScanSearch,
  FlaskConical,
  Users,
  Settings,
  LogOut,
  Shield,
  Wifi,
} from "lucide-react";
import { cn } from "../lib/utils";
import { useAuth } from "../context/auth";
import { Button } from "../components/Button";

// Define all possible items
const ALL_NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, roles: ["ADMIN", "AUDITOR"] },
  { to: "/scan", label: "Scanner", icon: ScanSearch, roles: ["ADMIN", "AUDITOR", "USER"] },
  { to: "/simulation", label: "Simulator", icon: FlaskConical, roles: ["ADMIN"] },
  { to: "/iam", label: "IAM Manager", icon: Users, roles: ["ADMIN"] },
  { to: "/config", label: "Config", icon: Settings, roles: ["ADMIN"] },
];

function Breadcrumbs() {
  const location = useLocation();
  const pathnames = location.pathname.split("/").filter(Boolean);
  if (pathnames.length === 0)
    return <span className="text-body-secondary">Dashboard</span>;
  const labels = pathnames.map((p) => p.charAt(0).toUpperCase() + p.slice(1));
  return (
    <nav className="d-flex align-items-center gap-2 small">
      {labels.map((label, i) => (
        <span key={i} className="d-flex align-items-center gap-2">
          {i > 0 && <span className="text-secondary">/</span>}
          <span
            className={
              i === labels.length - 1
                ? "text-light fw-medium"
                : "text-body-secondary"
            }
          >
            {label}
          </span>
        </span>
      ))}
    </nav>
  );
}

export function MainLayout() {
  const navigate = useNavigate();
  const { logout, user } = useAuth();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const role = user?.role || "USER";

  // Filter items
  const navItems = ALL_NAV_ITEMS.filter(item => item.roles.includes(role));

  return (
    <div className="min-vh-100 d-flex bg-dark">
      <aside
        className="flex-shrink-0 border-end border-secondary bg-dark position-fixed start-0 top-0 bottom-0 z-2 overflow-auto"
        style={{ width: "14rem" }}
      >
        <div className="d-flex align-items-center gap-2 border-bottom border-secondary px-3 py-3">
          <Shield
            className="text-primary"
            style={{ width: "1.75rem", height: "1.75rem" }}
          />
          <span className="fw-semibold text-light">S3CURE</span>
        </div>
        <div className="d-flex flex-column p-2 gap-1">
          {navItems.map(({ to, label, icon }) => {
            const Icon = icon;
            return (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  cn(
                    "nav-link d-flex align-items-center gap-2 rounded px-3 py-2 text-body-secondary text-decoration-none",
                    isActive ? "active" : "hover-bg-secondary"
                  )
                }
              >
                <Icon style={{ width: "1.25rem", height: "1.25rem" }} />
                {label}
              </NavLink>
            );
          })}
        </div>
      </aside>

      <div
        className="flex-grow-1 d-flex flex-column"
        style={{ marginLeft: "14rem" }}
      >
        <header className="sticky-top z-1 d-flex align-items-center justify-content-between border-bottom border-secondary bg-dark px-4 py-3">
          <Breadcrumbs />
          <div className="d-flex align-items-center gap-3">
            <span className="d-flex align-items-center gap-2 small text-body-secondary">
              <Wifi
                className="text-success"
                style={{ width: "1rem", height: "1rem" }}
              />
              System Status: Online
            </span>
             {/* Show user info/role for debug/clarity */}
             <div className="small text-end lh-1">
                <div className="text-light fw-medium">{user?.username}</div>
                <div className="text-body-secondary" style={{fontSize: '0.7rem'}}>{role}</div>
             </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLogout}
              className="text-body-secondary"
            >
              <LogOut
                style={{ width: "1rem", height: "1rem" }}
                className="me-1"
              />
              Logout
            </Button>
          </div>
        </header>

        <main className="p-4 flex-grow-1">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
