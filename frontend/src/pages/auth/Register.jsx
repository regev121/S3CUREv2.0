import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import api from "../../services/api";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "../../components/Card";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";

export default function Register() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api.post("/api/auth/register", { username, password });
      navigate("/iam", { replace: true, state: { accountCreated: username } });
    } catch (err) {
      const msg = err.response?.data?.detail ?? "Registration failed.";
      setError(Array.isArray(msg) ? msg.map((issue) => issue.msg).join(", ") : msg);
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
            <CardTitle>Create S3CURE account</CardTitle>
            <p className="text-body-secondary small mb-0 mt-1">
              Create an app login and a MinIO identity with the same username.
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
            autoComplete="new-password"
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
            Create account
          </Button>
        </form>
        <p className="mt-4 text-center small text-body-secondary mb-0">
          <Link to="/iam" className="text-primary fw-medium">
            Back to IAM Manager
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}
