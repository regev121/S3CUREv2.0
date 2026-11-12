import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import api from "../../services/api";
import { useAuth } from "../../context/auth";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "../../components/Card";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.append("username", username);
      params.append("password", password);

      const { data } = await api.post("/api/auth/login", params.toString(), {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });

      const token = data.access_token;
      if (token) {
        const profile = await login(token);
        navigate(profile.role === "USER" ? "/scan" : "/dashboard", { replace: true });
      }
    } catch (err) {
      const msg =
        err.response?.data?.detail ?? "Login failed. Check credentials.";
      setError(Array.isArray(msg) ? msg.join(", ") : msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="border-secondary">
      <CardHeader>
        <div className="d-flex align-items-center gap-3">
          <div className="rounded bg-primary bg-opacity-25 p-2">
            <Shield
              className="text-primary"
              style={{ width: "2rem", height: "2rem" }}
            />
          </div>
          <div>
            <CardTitle>S3CURE</CardTitle>
            <p className="text-body-secondary small mb-0 mt-1">
              Sign in to continue
            </p>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit}>
          <Input
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            autoComplete="username"
            required
          />
          <Input
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            autoComplete="current-password"
            required
          />
          {error && (
            <div className="alert alert-danger py-2 small" role="alert">
              {error}
            </div>
          )}
          <Button
            type="submit"
            className="w-100"
            loading={loading}
            disabled={loading}
          >
            Sign In
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
