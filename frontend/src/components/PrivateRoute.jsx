import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/auth";
import { Spinner } from "react-bootstrap";

export function PrivateRoute({ children, roles }) {
  const { isAuthenticated, isInitialized, user } = useAuth();
  const location = useLocation();

  if (!isInitialized) {
    return (
      <div className="min-vh-100 d-flex align-items-center justify-content-center bg-dark">
        <Spinner animation="border" variant="primary" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (!user) {
    return <div className="p-4 text-light">Unable to load your profile. Refresh to try again.</div>;
  }

  if (roles && !roles.includes(user.role)) {
    return <Navigate to="/scan" replace />;
  }

  return children;
}
