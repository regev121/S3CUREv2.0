import { useEffect, useState } from "react";
import {
  FlaskConical,
  Plus,
  X,
  ArrowRight,
  TrendingDown,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";
import api from "../services/api";
import { Card, CardHeader, CardTitle, CardContent } from "../components/Card";
import { Button } from "../components/Button";
import { Badge } from "../components/Badge";

const FIELDS = [
  ["add_policies", "Add Policies", "policies"],
  ["remove_policies", "Remove Policies", "direct_policies"],
  ["add_groups", "Add to Groups", "groups"],
  ["remove_groups", "Remove from Groups", "member_groups"],
];

function ChangeSelect({ field, label, options, selected, onAdd, onRemove }) {
  const [value, setValue] = useState("");
  return (
    <div className="mb-3">
      <label className="form-label text-body-secondary small" htmlFor={field}>{label}</label>
      <div className="d-flex gap-2 mb-2">
        <select id={field} className="form-select bg-dark text-light border-secondary"
          value={value} onChange={(event) => setValue(event.target.value)}>
          <option value="">Select an option</option>
          {options.filter((item) => !selected.includes(item)).map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>
        <Button variant="secondary" size="sm" aria-label={label} disabled={!value}
          onClick={() => { onAdd(value); setValue(""); }}>
          <Plus size={16} />
        </Button>
      </div>
      <div className="d-flex flex-wrap gap-2">
        {selected.map((item) => (
          <Badge key={item} variant="secondary" className="d-flex align-items-center gap-1">
            {item}
            <button type="button" className="btn btn-sm p-0 border-0 text-white"
              aria-label={"Remove " + item} onClick={() => onRemove(item)}>
              <X size={12} />
            </button>
          </Badge>
        ))}
      </div>
    </div>
  );
}

export default function Simulation() {
  const [username, setUsername] = useState("");
  const [users, setUsers] = useState([]);
  const [options, setOptions] = useState(null);
  const [changes, setChanges] = useState({});
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    api.get("/api/scan/users", { signal: controller.signal })
      .then(({ data }) => setUsers(data.users))
      .catch(() => { if (!controller.signal.aborted) setError("Unable to load users."); });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!username) return;
    const controller = new AbortController();
    api.get("/api/scan/simulate/options/" + encodeURIComponent(username), { signal: controller.signal })
      .then(({ data }) => setOptions(data))
      .catch(() => { if (!controller.signal.aborted) setError("Unable to load policies and groups."); });
    return () => controller.abort();
  }, [username]);

  const chooseUser = (event) => {
    setUsername(event.target.value);
    setChanges({});
    setOptions(null);
    setResult(null);
    setError("");
  };

  const runSimulation = async () => {
    setLoading(true);
    setResult(null);
    setError("");
    try {
      const { data } = await api.post("/api/scan/simulate", { username, ...changes });
      setResult(data);
    } catch (error) {
      setError(typeof error.response?.data?.detail === "string"
        ? error.response.data.detail : "Unable to run this simulation.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container-fluid p-0">
      <div className="d-flex align-items-center gap-3 mb-4">
        <div className="bg-primary bg-opacity-10 p-2 rounded">
          <FlaskConical className="text-primary" size={24} />
        </div>
        <div>
          <h1 className="h3 fw-bold text-light mb-0">Risk Simulator</h1>
          <p className="text-body-secondary mb-0 small">
            Model changes to policies and groups to predict risk impact.
          </p>
        </div>
      </div>

      <div className="row g-4">
        {/* Left Column: Configuration Controls */}
        <div className="col-lg-5">
          <Card className="border-secondary h-100">
            <CardHeader>
              <CardTitle>Configuration</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="mb-4">
                <label className="form-label text-light" htmlFor="simulation-user">Target User</label>
                <select id="simulation-user" className="form-select bg-dark text-light border-secondary"
                  value={username} onChange={chooseUser} disabled={loading}>
                  <option value="">Select a user</option>
                  {users.map((name) => <option key={name} value={name}>{name}</option>)}
                </select>
              </div>

              <hr className="border-secondary my-4" />
              <fieldset disabled={loading || !options}>
                {FIELDS.map(([field, label, list]) => (
                  <ChangeSelect key={username + field} field={field} label={label}
                    options={options?.[list] ?? []} selected={changes[field] ?? []}
                    onAdd={(item) => setChanges((prev) => ({
                      ...prev, [field]: [...(prev[field] ?? []), item],
                    }))}
                    onRemove={(item) => setChanges((prev) => ({
                      ...prev, [field]: prev[field].filter((entry) => entry !== item),
                    }))} />
                ))}
              </fieldset>
              {error && <div role="alert" className="alert alert-danger py-2">{error}</div>}
              <div className="mt-4">
                <Button
                  className="w-100"
                  variant="primary"
                  onClick={runSimulation}
                  disabled={loading || !options}
                >
                  {loading ? "Simulating..." : "Run Simulation"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Comparative Results */}
        <div className="col-lg-7">
          {!result ? (
            <div className="h-100 d-flex flex-column align-items-center justify-content-center text-body-secondary border border-secondary border-dashed rounded p-5 bg-dark">
              <FlaskConical size={48} className="mb-3 opacity-25" />
              <p>Run a simulation to see results here.</p>
            </div>
          ) : (
            <div className="d-flex flex-column gap-4">
              {/* Score Comparison Cards */}
              <div className="row g-3">
                <div className="col-md-5">
                  <Card className="border-secondary text-center h-100">
                    <CardHeader><CardTitle className="text-body-secondary small">Current Reality</CardTitle></CardHeader>
                    <CardContent>
                      <div className="display-4 fw-bold text-light mb-2">
                        {result.comparison.current_score}
                      </div>
                      <Badge variant="outline">Risk Score</Badge>
                    </CardContent>
                  </Card>
                </div>

                <div className="col-md-2 d-flex align-items-center justify-content-center">
                  <ArrowRight className="text-body-secondary" size={32} />
                </div>

                <div className="col-md-5">
                  <Card className={`border-${result.comparison.is_improvement ? 'success' : result.comparison.delta > 0 ? 'danger' : 'secondary'} h-100 text-center position-relative overflow-hidden`}>
                     <div className={`position-absolute top-0 start-0 w-100 h-100 bg-${result.comparison.is_improvement ? 'success' : result.comparison.delta > 0 ? 'danger' : 'secondary'} opacity-10 z-0`}></div>
                    <CardHeader className="z-1 position-relative"><CardTitle className="small">Simulated Reality</CardTitle></CardHeader>
                    <CardContent className="z-1 position-relative">
                      <div className="display-4 fw-bold text-light mb-2">
                        {result.comparison.simulated_score}
                      </div>
                      <div className="d-flex align-items-center justify-content-center gap-2">
                         {result.comparison.delta !== 0 && (
                             result.comparison.is_improvement ? (
                                 <span className="text-success d-flex align-items-center small fw-bold">
                                     <TrendingDown size={16} className="me-1"/>
                                     {result.comparison.delta}
                                 </span>
                             ) : (
                                 <span className="text-danger d-flex align-items-center small fw-bold">
                                     <TrendingUp size={16} className="me-1"/>
                                     +{result.comparison.delta}
                                 </span>
                             )
                         )}
                         <Badge variant={result.comparison.is_improvement ? "success" : result.comparison.delta > 0 ? "danger" : "secondary"}>
                             {result.comparison.status}
                         </Badge>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>

              {/* Violations List */}
              <Card className="border-secondary">
                <CardHeader>
                  <CardTitle className="d-flex align-items-center gap-2">
                    <AlertTriangle size={18} className="text-warning"/>
                    Simulated Violations
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {result.simulated_violations.length === 0 ? (
                    <div className="text-center py-4 text-success">
                      <CheckCircle size={32} className="mb-2" />
                      <p className="mb-0">No violations found in this simulation.</p>
                    </div>
                  ) : (
                    <ul className="list-group list-group-flush bg-transparent">
                      {result.simulated_violations.map((v, i) => (
                        <li key={i} className="list-group-item bg-transparent text-light border-secondary px-0">
                          • {v}
                        </li>
                      ))}
                    </ul>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
