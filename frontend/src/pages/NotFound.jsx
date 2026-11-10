import { Link } from "react-router-dom";
import { ShieldAlert, Home } from "lucide-react";
import { Button } from "../components/Button";

export default function NotFound() {
  return (
    <div className="min-vh-100 d-flex flex-column align-items-center justify-content-center p-4 bg-dark">
      <div className="text-center" style={{ maxWidth: "28rem" }}>
        <div className="rounded-circle bg-danger bg-opacity-25 d-inline-flex p-4 mb-4">
          <ShieldAlert
            className="text-danger"
            style={{ width: "4rem", height: "4rem" }}
          />
        </div>
        <h1 className="display-4 fw-bold text-light mb-2">404</h1>
        <p className="text-body-secondary fs-5 mb-1">
          Access Denied / Resource Not Found
        </p>
        <p className="text-secondary small mb-4">
          The requested resource does not exist or you do not have permission to
          access it.
        </p>
        <div className="d-flex justify-content-center gap-2 flex-wrap">
          <Link to="/dashboard">
            <Button
              variant="primary"
              className="d-inline-flex align-items-center gap-2"
            >
              <Home style={{ width: "1rem", height: "1rem" }} />
              Return to Base
            </Button>
          </Link>
          <Link to="/login">
            <Button variant="ghost">Sign In</Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
