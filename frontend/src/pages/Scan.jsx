import { useState, useCallback, useEffect } from "react";
import Graph from "react-graph-vis";
import api from "../services/api";
import { Card, CardHeader, CardTitle, CardContent } from "../components/Card";
import { Button } from "../components/Button";
import FindingList from "../components/FindingList";
import { Badge } from "../components/Badge";
import { Spinner } from "react-bootstrap";
import { User, ShieldAlert, Search, Network } from "lucide-react";
import { useAuth } from "../context/auth";

/**
 * Generates an SVG string for graph nodes based on the node type.
 * Returns a Data URI for use in Vis.js 'image' shape.
 */
const getSvgIcon = (type) => {
  const encodeSvg = (svg) => "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);

  // Theme: Solarized/Pastel for Cyber Security Context
  const colors = {
    USER: "#dcb67a", // Muted Gold
    POLICY: "#c586c0", // VSCode Purple-ish
    RESOURCE: "#4ec9b0", // VSCode Green-ish
  };

  const color = colors[type] || "#cccccc";

  const icons = {
    USER: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
    POLICY: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`,
    RESOURCE: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`
  };

  return encodeSvg(icons[type] || icons.RESOURCE);
};

// --- VIS.JS Graph Configuration ---
const graphOptions = {
  layout: {
    hierarchical: false,
  },
  nodes: {
    font: {
      color: "#e6edf3", // Github Light Text
      face: "Segoe UI, sans-serif",
      size: 14,
      background: "#0d1117",
    },
    borderWidth: 0,
    shadow: true,
    shapeProperties: {
        useBorderWithImage: false
    }
  },
  edges: {
    color: { color: "#30363d", highlight: "#58a6ff" },
    arrows: { to: { enabled: true, scaleFactor: 0.8 } },
    smooth: { type: "continuous", forceDirection: "none" },
    font: {
        color: "#8b949e",
        size: 10,
        align: "middle",
        background: "#0d1117",
        strokeWidth: 0
    },
    width: 1, // Delicate lines for complex graphs
    selectionWidth: 2
  },
  physics: {
    stabilization: true,
    solver: 'forceAtlas2Based',
    forceAtlas2Based: {
        gravitationalConstant: -50,
        centralGravity: 0.01,
        springConstant: 0.08,
        springLength: 100,
        damping: 0.4,
        avoidOverlap: 1
    },
    maxVelocity: 50,
    minVelocity: 0.1
  },
  interaction: {
    hover: true,
    tooltipDelay: 300,
    zoomView: true,
  },
  height: "100%",
};

// --- Sub-Components ---

function getGaugeColor(score) {
  if (score == null) return "#6c757d";
  if (score <= 30) return "#198754";
  if (score <= 70) return "#fd7e14";
  return "#dc3545";
}

function RiskGauge({ score }) {
  const color = getGaugeColor(score);
  const value = score != null ? Math.round(score) : "—";
  const circumference = 2 * Math.PI * 90;
  const strokeDash = score != null ? (score / 100) * circumference : 0;

  return (
    <div className="position-relative d-inline-block">
      <svg width={220} height={220} className="d-block mx-auto">
        <circle
          cx={110}
          cy={110}
          r={90}
          fill="none"
          stroke="#212529"
          strokeWidth={14}
        />
        <circle
          cx={110}
          cy={110}
          r={90}
          fill="none"
          stroke={color}
          strokeWidth={14}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - strokeDash}
          strokeLinecap="round"
          transform="rotate(-90 110 110)"
          style={{ transition: "stroke-dashoffset 0.5s ease" }}
        />
      </svg>
      <div
        className="position-absolute top-50 start-50 translate-middle text-center"
        style={{ marginLeft: "-0.5rem", marginTop: "-0.5rem" }}
      >
        <span className="fw-bold display-4" style={{ color }}>
          {value}
        </span>
        <span className="d-block small text-body-secondary">Risk Score</span>
      </div>
    </div>
  );
}

function ScanContent() {
  const { user } = useAuth();
  const [username, setUsername] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  // Graph state: { nodes: [], edges: [] }
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  // Key to force re-render graph when data changes totally
  const [graphKey, setGraphKey] = useState(0);

  const role = user?.role || "USER";
  const isSelfScanOnly = role === "USER";

  const [usersList, setUsersList] = useState([]);

  useEffect(() => {
    // Populate user dropdown if allowed
    const fetchUsers = async () => {
      try {
        const { data } = await api.get("/api/scan/users");
        if (data.users) setUsersList(data.users);
      } catch (e) {
        console.error("Failed to fetch users list", e);
      }
    };
    if (!isSelfScanOnly) fetchUsers();
  }, [isSelfScanOnly]);

  const handleScan = useCallback(async (targetUser) => {
    // Determine target based on input or self-scan restriction
    const userToScan =
      targetUser || (isSelfScanOnly ? user?.username : username);

    if (!userToScan?.trim()) return;

    if (userToScan !== username) setUsername(userToScan);

    setError(null);
    setResult(null);
    setGraphData({ nodes: [], edges: [] });
    setLoading(true);

    try {
      const { data } = await api.post(
        `/api/scan/user/${encodeURIComponent(userToScan)}`
      );
      setResult(data);

      if (data.graph_data) {
        // --- PROCESS NODES FOR VISUALS ---
        const processedNodes = data.graph_data.nodes.map(node => {
            const nodeType = node.type || "RESOURCE";
            return {
                ...node,
                shape: "image",
                image: getSvgIcon(nodeType),
                size: 24,
                color: {
                    background: "#0d1117",
                    border: "#0d1117"
                },
                label: node.label.length > 20 ? node.label.substring(0, 18) + '...' : node.label
            };
        });

        // Helper to text-wrap long edge labels
        const formatLabel = (label) => {
            if (!label || label.length < 30) return label;
            const parts = label.split(',');
            if (parts.length <= 3) return label;

            let newLabel = "";
            let counter = 0;
            parts.forEach((part, idx) => {
                newLabel += part + (idx < parts.length - 1 ? "," : "");
                counter++;
                if (counter >= 3 && idx < parts.length - 1) {
                    newLabel += "\n";
                    counter = 0;
                }
            });
            return newLabel;
        };

        const processedEdges = data.graph_data.edges.map(edge => ({
            ...edge,
            color: "#30363d",
            label: formatLabel((edge.label ?? "").replace(/\\n/g, "\n"))
        }));

        setGraphData({ nodes: processedNodes, edges: processedEdges });
      } else {
        setGraphData({ nodes: [], edges: [] });
      }
      setGraphKey((prev) => prev + 1); // Reset graph component
    } catch (err) {
      const msg =
        err.response?.data?.detail ??
        err.message ??
        "User not found or scan failed.";
      setError(String(msg));
    } finally {
      setLoading(false);
    }
  }, [username, isSelfScanOnly, user]);

  return (
    <div className="row g-3 h-100">
      {/* Left Panel: Scan Controls & Results */}
      <div className="col-lg-4 d-flex flex-column">
        <Card className="border-secondary flex-grow-1 d-flex flex-column">
          <CardHeader>
            <CardTitle className="d-flex align-items-center gap-2">
              <Search style={{ width: "1.25rem", height: "1.25rem" }} />
              Scan User
            </CardTitle>
          </CardHeader>
          <CardContent className="d-flex flex-column flex-grow-1">
            {isSelfScanOnly ? (
              <div className="mb-3">
                <p className="text-body-secondary small mb-3">
                  As a standard user, you can only scan your own profile.
                </p>
                <Button
                  variant="primary"
                  size="lg"
                  className="w-100 py-3 fw-bold"
                  onClick={() => handleScan(user?.username)}
                  loading={loading}
                  disabled={loading}
                >
                  <ShieldAlert className="me-2" />
                  Scan My Profile
                </Button>
              </div>
            ) : (
              <div className="d-flex gap-2 mb-3">
                <select
                  className="form-select form-select-lg bg-dark border-secondary text-light"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={loading}
                >
                  <option value="">Select a user...</option>
                  {usersList.map((u) => (
                    <option key={u} value={u}>
                      {u}
                    </option>
                  ))}
                </select>
                <Button
                  variant="primary"
                  onClick={() => handleScan()}
                  loading={loading}
                  disabled={loading || !username}
                  className="flex-shrink-0"
                >
                  Scan
                </Button>
              </div>
            )}

            {error && (
              <div className="alert alert-danger py-2 small mb-3" role="alert">
                {error}
              </div>
            )}

            {loading && (
              <div className="text-center py-4">
                <Spinner animation="border" variant="primary" />
                <p className="text-body-secondary small mt-2 mb-0">
                  Analyzing user...
                </p>
              </div>
            )}

            {!loading && result && (
              <>
                <div className="text-center mb-4">
                  <RiskGauge score={result.score} />
                </div>
                <div
                  className="flex-grow-1 overflow-auto"
                  style={{ minHeight: 120 }}
                >
                  <p className="small text-body-secondary mb-2 fw-semibold">
                    Violations (
                    {result.violations_count ?? result.violations?.length ?? 0})
                  </p>
                  <FindingList
                    findings={result.violation_details ?? result.violations}
                    emptyText="No violations found."
                  />
                </div>
              </>
            )}

            {!loading && !result && !error && (
              <div className="text-center py-4 text-body-secondary small">
                <User
                  style={{ width: "3rem", height: "3rem" }}
                  className="mb-2 opacity-50"
                />
                <p className="mb-0">
                  Enter a username and click Scan to analyze risk.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Right Panel - Visualization Graph */}
      <div className="col-lg-8" style={{ minHeight: 500 }}>
        <Card className="border-secondary h-100">
          <CardHeader className="d-flex justify-content-between align-items-center">
            <div>
              <CardTitle className="d-flex align-items-center gap-2">
                <Network style={{ width: "1.25rem", height: "1.25rem" }} />
                Network Risk Graph
              </CardTitle>
              <p className="text-body-secondary small mb-0 mt-1">
                Visualizing User → Policies → Resources
              </p>
            </div>
            {graphData.nodes.length > 0 && (
                 <Badge variant="outline" className="text-info border-info">
                    {graphData.nodes.length} Nodes
                 </Badge>
            )}
          </CardHeader>
          <CardContent className="p-0 position-relative" style={{ height: "450px", overflow: 'hidden' }}>
             <div style={{ width: '100%', height: '100%', backgroundColor: '#0d1117' }}>
                {graphData.nodes.length > 0 ? (
                    <Graph
                        key={graphKey}
                        graph={graphData}
                        options={graphOptions}
                    />
                ) : (
                    <div className="w-100 h-100 d-flex align-items-center justify-content-center text-body-secondary">
                        {loading ? 'Generating model...' : 'No graph data available.'}
                    </div>
                )}
             </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default function Scan() {
  return (
    <div>
      <h1 className="h2 fw-bold text-light mb-3">Scanner</h1>
      <p className="text-body-secondary mb-4">
        Enter a username to run a risk analysis and view the cyber risk graph.
      </p>
      <ScanContent />
    </div>
  );
}
