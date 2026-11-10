import { Outlet } from "react-router-dom";

export function AuthLayout() {
  return (
    <div className="min-vh-100 d-flex flex-column align-items-center justify-content-center p-4 bg-dark">
      <div className="w-100" style={{ maxWidth: "28rem" }}>
        <Outlet />
      </div>
    </div>
  );
}
