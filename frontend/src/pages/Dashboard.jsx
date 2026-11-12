import { Card, CardHeader, CardTitle, CardContent } from "../components/Card";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { Users, AlertTriangle, Activity, Heart, RefreshCw, Clock, ShieldAlert, HardDrive, Wifi } from "lucide-react";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { useEffect, useState } from "react";
import api from "../services/api";

const CHART_COLORS = {
  line: "#0d6efd",
  grid: "rgba(255,255,255,0.06)",
  text: "#adb5bd",
};

function formatDate(date) {
  return date ? new Date(date).toLocaleString([], { dateStyle: "short", timeStyle: "short" }) : "—";
}

function formatBytes(bytes) {
  if (bytes == null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let unit = 0;
  while (bytes >= 1024 && unit < units.length - 1) {
    bytes /= 1024;
    unit += 1;
  }
  return bytes.toLocaleString([], { maximumFractionDigits: 1 }) + " " + units[unit];
}

/**
 * Reusable Statistic Card Component.
 * Displays a key metric with an icon and optional subtext.
 */
function StatCard({ icon, label, value, sub, variant }) {
  const Icon = icon;
  return (
    <Card className="border-secondary h-100">
      <CardContent className="d-flex align-items-center gap-3">
        <div
          className={`rounded-3 p-2 bg-opacity-25 ${
            variant === "danger"
              ? "bg-danger"
              : variant === "success"
              ? "bg-success"
              : variant === "warning"
              ? "bg-warning"
              : "bg-primary"
          }`}
        >
          <Icon
            className="text-white"
            style={{ width: "1.75rem", height: "1.75rem" }}
          />
        </div>
        <div>
          <p className="text-body-secondary small mb-0">{label}</p>
          <p className="fw-bold text-light mb-0 fs-4">{value}</p>
          {sub && <p className="text-body-secondary small mb-0">{sub}</p>}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Executive Dashboard.
 * Provides a high-level overview of the organization's security posture.
 * key Features:
 * - Aggregated Risk Metrics (Total Users, Avg Score, Critical Issues).
 * - Temporal Risk Analysis (7-day trend).
 * - Severity Distribution Visualization.
 * - Global Scan Trigger.
 */
export default function Dashboard() {
  const [stats, setStats] = useState({
    totalUsersScanned: 0,
    avgRiskScore: 0,
    criticalViolations: 0,
    systemHealth: "Unknown",
  });
  const [historyViews, setHistoryViews] = useState([]);
  const [historyViewId, setHistoryViewId] = useState("general");
  const [violationsBySeverity, setViolationsBySeverity] = useState([]);
  const [recentActivity, setRecentActivity] = useState([]);
  const [telemetry, setTelemetry] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);

  /**
   * Retrieves dashboard analytics from the backend.
   * Optimizes performance by aggregating data on the server-side.
   */
  const fetchDashboardData = async () => {
    try {
      const { data } = await api.get("/api/scan/dashboard/stats");
      if (data) {
         setStats(data.stats || {});
         setHistoryViews(data.riskHistoryViews || [
           { id: "general", label: "General (last 7 days)", history: data.riskHistory || [] },
         ]);
         setViolationsBySeverity(data.violationsBySeverity || []);
         setRecentActivity(data.recentActivity || []);
         setTelemetry(data.telemetry);
         setError("");
      }
    } catch (error) {
      setError(error.response?.data?.detail || "Unable to load dashboard data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  /**
   * Initiates a comprehensive security scan for all registered users.
   * This is a long-running operation that refreshes all backend risk models.
   */
  const handleGlobalScan = async () => {
      if (!window.confirm("Run a comprehensive Global Scan for all users? This might take a few moments.")) return;

      setScanLoading(true);
      try {
          const { data } = await api.post("/api/scan/all");
          await fetchDashboardData();
          const failures = data.details.filter((row) => row.status === "error").length;
          if (failures) setError("Unable to complete " + failures + " scan(s).");
      } catch (error) {
          setError(error.response?.data?.detail || "Unable to run the global scan.");
      } finally {
          setScanLoading(false);
      }
  };

  const getBadgeVariant = (status) => {
      switch (status) {
          case 'Healthy': return 'success';
          case 'Moderate': return 'warning';
          case 'High Risk': return 'danger';
          case 'Critical': return 'danger';
          default: return 'secondary';
      }
  };

  const getStatusColorStyle = (status) => {
      if (status === 'High Risk') return { backgroundColor: '#fd7e14', color: '#fff' };
      return {};
  };

  const historyView = historyViews.find((view) => view.id === historyViewId) ?? historyViews[0];
  const hasViolations = violationsBySeverity.some((entry) => entry.value > 0);
  const distribution = hasViolations
    ? violationsBySeverity.filter((entry) => entry.value > 0)
    : [{ name: "No recorded violations", value: 1, color: "#495057" }];

  return (
    <div>
      <div className="d-flex align-items-center justify-content-between mb-4">
        <div>
           <h1 className="h2 fw-bold text-light mb-1">Dashboard</h1>
           <p className="text-body-secondary mb-0">
             High-level view of the organization&apos;s security posture.
           </p>
        </div>
        <Button
                variant="primary"
                onClick={handleGlobalScan}
                disabled={scanLoading || loading}
                title="Run a fresh scan for all users"
            >
                {scanLoading ? (
                    <>
                        <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                        Scanning...
                    </>
                ) : (
                    <>
                        <RefreshCw size={18} className="me-2" />
                        Run Global Scan
                    </>
                )}
        </Button>
      </div>

      {error && <div className="alert alert-danger" role="alert">{error}</div>}
      {telemetry?.archiveAvailable === false && (
        <div className="alert alert-warning" role="status">Scan archive is currently unavailable.</div>
      )}
      <div className="row g-3 mb-4">
        <div className="col-sm-6 col-xl-3">
          <StatCard
            icon={Users}
            label="Total Users Scanned"
            value={stats.totalUsersScanned}
            variant="primary"
          />
        </div>
        <div className="col-sm-6 col-xl-3">
          <StatCard
            icon={Activity}
            label="Avg Risk Score"
            value={stats.avgRiskScore ?? "—"}
            sub={stats.comparableUsers == null ? "0–100 scale" : stats.comparableUsers + " comparable users"}
            variant="warning"
          />
        </div>
        <div className="col-sm-6 col-xl-3">
          <StatCard
            icon={AlertTriangle}
            label="Critical Violations"
            value={stats.criticalViolations}
            variant="danger"
          />
        </div>
        <div className="col-sm-6 col-xl-3">
          <StatCard
            icon={Heart}
            label="System Health"
            value={stats.systemHealth}
            variant="success"
          />
        </div>
      </div>

      <div className="row g-3 mb-4">
        <div className="col-lg-8">
          <Card className="border-secondary h-100">
            <CardHeader>
              <div className="d-flex flex-wrap align-items-center justify-content-between gap-2">
                <CardTitle>Risk Score History</CardTitle>
                <select className="form-select form-select-sm bg-dark text-light border-secondary w-auto"
                  aria-label="Risk history view" value={historyView?.id ?? ""}
                  onChange={(event) => setHistoryViewId(event.target.value)}>
                  {historyViews.map((view) => (
                    <option key={view.id} value={view.id}>{view.label}</option>
                  ))}
                </select>
              </div>
              {historyView?.dateEstimated && (
                <p className="small text-body-secondary mb-0">Date of the first archived scan with this configuration</p>
              )}
            </CardHeader>
            <CardContent>
              <div style={{ height: 280 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={historyView?.history ?? []}
                    margin={{ top: 5, right: 20, left: 0, bottom: 5 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke={CHART_COLORS.grid}
                    />
                    <XAxis
                      dataKey="day"
                      stroke={CHART_COLORS.text}
                      tick={{ fill: CHART_COLORS.text, fontSize: 12 }}
                    />
                    <YAxis
                      stroke={CHART_COLORS.text}
                      tick={{ fill: CHART_COLORS.text, fontSize: 12 }}
                      domain={[0, 100]}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#212529",
                        border: "1px solid #495057",
                        borderRadius: "8px",
                      }}
                      labelStyle={{ color: "#dee2e6" }}
                      itemStyle={{ color: "#dee2e6" }}
                    />
                    <Line
                      type="linear"
                      connectNulls
                      isAnimationActive={false}
                      dataKey="score"
                      name="Average risk score"
                      stroke={CHART_COLORS.line}
                      strokeWidth={2}
                      dot={{ fill: CHART_COLORS.line, r: 4 }}
                      activeDot={{ r: 6 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </div>
        <div className="col-lg-4">
          <Card className="border-secondary h-100">
            <CardHeader>
              <CardTitle>Violations by Severity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="position-relative" style={{ height: 260 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={distribution}
                      isAnimationActive={false}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={90}
                      paddingAngle={2}
                      dataKey="value"
                      nameKey="name"
                      label={hasViolations ? ({ name, value }) => name + ": " + value : false}
                      labelLine={{ stroke: CHART_COLORS.text }}
                    >
                      {distribution.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} />
                      ))}
                    </Pie>
                    {hasViolations && (
                      <Tooltip contentStyle={{ backgroundColor: "#212529", border: "1px solid #495057" }} />
                    )}
                  </PieChart>
                </ResponsiveContainer>
                <div className="position-absolute top-50 start-50 translate-middle text-center"
                  style={{ pointerEvents: "none" }}>
                  <strong className="fs-4 text-light d-block">{stats.avgRiskScore ?? "—"}</strong>
                  <span className="small text-body-secondary">{stats.systemHealth}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="row g-3 mb-4" aria-label="Operational telemetry">
        <div className="col-sm-6 col-xl-3">
          <StatCard icon={Clock} label="Last Scan" value={formatDate(stats.lastScan)} />
        </div>
        <div className="col-sm-6 col-xl-3">
          <StatCard icon={ShieldAlert} label="Highest Risk"
            value={stats.mostAtRisk?.user ?? "—"}
            sub={stats.mostAtRisk ? stats.mostAtRisk.score + " / 100" : null} />
        </div>
        <div className="col-sm-6 col-xl-3">
          <StatCard icon={HardDrive} label="MinIO Drive Space Free"
            value={formatBytes(telemetry?.availableBytes)}
            sub={telemetry?.totalBytes == null ? null : "of " + formatBytes(telemetry.totalBytes)} />
        </div>
        <div className="col-sm-6 col-xl-3">
          <StatCard icon={Wifi} label="Service Availability"
            value={telemetry ? "MinIO " + (telemetry.minioOnline ? "online" : "offline") : "—"}
            sub={telemetry ? [
              "API online",
              "DB " + (telemetry.databaseOnline ? "online" : "offline"),
              telemetry.minioLatencyMs == null ? null : telemetry.minioLatencyMs + " ms",
              telemetry.uptimeSeconds == null ? null : Math.floor(telemetry.uptimeSeconds / 60) + " min uptime",
            ].filter(Boolean).join(" · ") : null} />
        </div>
      </div>

      <Card className="border-secondary">
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="table-responsive">
            <table className="table table-dark table-hover table-borderless mb-0">
              <thead>
                <tr className="border-secondary">
                  <th className="ps-4 text-body-secondary fw-normal">User</th>
                  <th className="text-body-secondary fw-normal">Score</th>
                  <th className="text-body-secondary fw-normal">Time</th>
                  <th className="pe-4 text-body-secondary fw-normal">Status</th>
                </tr>
              </thead>
              <tbody>
                {recentActivity.length === 0 ? (
                    <tr className="border-secondary">
                        <td colSpan="5" className="text-center text-body-secondary py-4">No recent activity found.</td>
                    </tr>
                ) : (
                    recentActivity.map((row) => (
                    <tr key={row.id} className="border-secondary">
                        <td className="ps-4">
                        <span className="text-light">{row.user}</span>
                        </td>
                        <td>
                        <span className="text-light">{row.score}</span>
                        </td>
                        <td className="text-body-secondary small">{formatDate(row.time)}</td>
                        <td className="text-body-secondary small" title={row.riskConfigVersion ?? undefined}>
                          {row.riskConfigLabel ?? "Legacy scans"}
                        </td>
                        <td className="pe-4">
                        <Badge
                            variant={getBadgeVariant(row.status)}
                            style={getStatusColorStyle(row.status)}
                        >
                            {row.status}
                        </Badge>
                        </td>
                    </tr>
                    ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
