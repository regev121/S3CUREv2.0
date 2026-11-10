import { useEffect, useId, useState } from "react";
import { Users, Shield, UserPlus, UserMinus, Link, Unlink } from "lucide-react";
import api from "../services/api";
import { Card, CardHeader, CardTitle, CardContent } from "../components/Card";
import { Button } from "../components/Button";
import { Badge } from "../components/Badge";

const ACTIONS = {
  policies: [
    { title: "Attach Policy", path: "policy/attach", icon: Link },
    { title: "Detach Policy", path: "policy/detach", icon: Unlink, destructive: true },
  ],
  groups: [
    { title: "Add to Group", path: "group/add-member", icon: UserPlus },
    { title: "Remove from Group", path: "group/remove-member", icon: UserMinus, destructive: true },
  ],
};

function IamSelect({ label, options, value, onChange, disabled }) {
  const id = useId();
  return (
    <div className="mb-3">
      <label htmlFor={id} className="form-label text-body-secondary small">{label}</label>
      <select id={id} className="form-select bg-dark border-secondary text-light"
        value={value} onChange={(event) => onChange(event.target.value)} disabled={disabled}>
        <option value="">Select {label === "Username" ? "a user" : label === "Policy" ? "a policy" : "a group"}</option>
        {options.map((name) => <option key={name} value={name}>{name}</option>)}
      </select>
    </div>
  );
}

function IamAction({ action, tab, catalog, busy, onAction }) {
  const [username, setUsername] = useState("");
  const [selection, setSelection] = useState("");
  const Icon = action.icon;
  const isPolicy = tab === "policies";

  const submit = async (event) => {
    event.preventDefault();
    const field = isPolicy ? "policy_name" : "group_name";
    if (await onAction(action.path, { username, [field]: selection })) {
      setUsername("");
      setSelection("");
    }
  };

  return (
    <form className="p-3 border border-secondary rounded bg-dark-subtle h-100" onSubmit={submit}>
      <h2 className="h6 d-flex align-items-center gap-2 mb-3">
        <Icon size={18} className={action.destructive ? "text-warning" : "text-info"} />
        {action.title}
      </h2>
      <IamSelect label="Username" options={catalog?.users ?? []} value={username}
        onChange={setUsername} disabled={busy || !catalog} />
      <IamSelect label={isPolicy ? "Policy" : "Group"} options={catalog?.[tab] ?? []}
        value={selection} onChange={setSelection} disabled={busy || !catalog} />
      <Button type="submit" className={"w-100 " + (action.destructive ? "border-warning text-warning" : "")}
        variant={action.destructive ? "outline" : "primary"} disabled={busy || !username || !selection}>
        {action.title}
      </Button>
    </form>
  );
}

export default function IamManager() {
  const [activeTab, setActiveTab] = useState("policies");
  const [catalog, setCatalog] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    api.get("/api/scan/iam/options", { signal: controller.signal })
      .then(({ data }) => setCatalog(data))
      .catch(() => {
        if (!controller.signal.aborted) setMessage({ type: "danger", text: "Unable to load IAM options." });
      });
    return () => controller.abort();
  }, []);

  const handleAction = async (path, body) => {
    setBusy(true);
    setMessage(null);
    try {
      const { data } = await api.post("/api/scan/" + path, body);
      setMessage({ type: "success", text: data.message });
      return true;
    } catch (error) {
      setMessage({ type: "danger", text: error.response?.data?.detail || "Unable to update IAM." });
      return false;
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="d-flex align-items-center gap-3 mb-4">
        <div className="bg-primary bg-opacity-10 p-2 rounded">
          <Users className="text-primary" size={24} />
        </div>
        <div>
          <h1 className="h3 fw-bold text-light mb-0">IAM Manager</h1>
          <p className="text-body-secondary mb-0 small">Manage users, groups, and policy attachments in MinIO.</p>
        </div>
      </div>

      <div className="row g-3">
        <div className="col-lg-8">
          <Card className="border-secondary">
            <CardHeader className="d-flex gap-2 border-bottom border-secondary">
              <Button variant={activeTab === "policies" ? "primary" : "ghost"} disabled={busy}
                onClick={() => setActiveTab("policies")}><Shield size={16} className="me-2" />Policies</Button>
              <Button variant={activeTab === "groups" ? "primary" : "ghost"} disabled={busy}
                onClick={() => setActiveTab("groups")}><Users size={16} className="me-2" />Groups</Button>
            </CardHeader>
            <CardContent className="pt-4">
              {message && <div className={"alert alert-" + message.type} role="status">{message.text}</div>}
              <div className="row g-3">
                {ACTIONS[activeTab].map((action) => (
                  <div className="col-md-6" key={action.path}>
                    <IamAction action={action} tab={activeTab} catalog={catalog} busy={busy} onAction={handleAction} />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
        <div className="col-lg-4">
          <Card className="border-secondary h-100">
            <CardHeader><CardTitle>Usage Tips</CardTitle></CardHeader>
            <CardContent>
              <p className="small text-body-secondary"><Badge variant="secondary">Note</Badge> Changes apply directly to MinIO.</p>
              <p className="small text-body-secondary mb-0"><Badge variant="secondary">Tip</Badge> Preview changes in the Simulator before applying them.</p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
