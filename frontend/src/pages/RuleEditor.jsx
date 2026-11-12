import { useEffect, useState } from "react";
import { Form, Modal } from "react-bootstrap";
import { FileUp, Braces } from "lucide-react";
import { Button } from "../components/Button";
import api from "../services/api";

const sample = {
  Version: "2012-10-17",
  Statement: [{
    Effect: "Allow",
    Action: ["s3:DeleteObject"],
    Resource: ["arn:aws:s3:::prod-bucket/*"],
  }],
};
const modes = [["guided", "Guided"], ["manual", "Manual JSON"], ["import", "Import from MinIO"]];

function errorMessage(error) {
  const detail = error.response?.data?.detail;
  if (Array.isArray(detail) && detail.length) {
    const issue = detail[0];
    const field = issue.loc?.slice(1).join(".");
    return [field, issue.msg?.replace(/^Value error, /, "")].filter(Boolean).join(" · ");
  }
  return typeof detail === "string" ? detail : "Unable to validate the rule.";
}

export default function RuleEditor({ rule, onClose, onApply }) {
  const [mode, setMode] = useState(rule?.policy ? "manual" : "guided");
  const [description, setDescription] = useState(rule?.description ?? "");
  const [weight, setWeight] = useState(rule?.severity ?? 7);
  const [actions, setActions] = useState(rule?.risky_actions?.join(", ") ?? "");
  const [resource, setResource] = useState(rule?.resource_pattern ?? "*");
  const [global, setGlobal] = useState(rule?.require_global_grant ?? false);
  const [json, setJson] = useState(JSON.stringify(rule?.policy ?? sample, null, 2));
  const [source, setSource] = useState(rule?.source_policy ?? "");
  const [policyName, setPolicyName] = useState("");
  const [policies, setPolicies] = useState(null);
  const [catalogError, setCatalogError] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const anonymousRule = rule?.id === "R001" || rule?.description === "CRITICAL: Public Access to Production Data";

  useEffect(() => {
    if (mode !== "import") return;
    const request = new AbortController();
    api.get("/api/scan/config/policies", { signal: request.signal })
      .then(({ data }) => { setPolicies(data.policies); setCatalogError(""); })
      .catch((error) => { if (!request.signal.aborted) setCatalogError(errorMessage(error)); });
    return () => request.abort();
  }, [mode]);

  const importPolicy = async () => {
    setError("");
    setBusy(true);
    try {
      const { data } = await api.get("/api/scan/config/policies/" + encodeURIComponent(policyName));
      setJson(JSON.stringify(data.policy, null, 2));
      setSource(policyName);
      if (!description.trim()) setDescription("Permissions in " + policyName);
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const importFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    event.target.value = "";
    setError("");
    try {
      setJson(JSON.stringify(JSON.parse(await file.text()), null, 2));
      setSource("");
      setMode("manual");
      if (!description.trim()) setDescription(file.name.replace(/\.json$/i, ""));
    } catch {
      setError("The selected file must contain valid JSON.");
    }
  };

  const format = () => {
    setError("");
    try {
      setJson(JSON.stringify(JSON.parse(json), null, 2));
    } catch {
      setError("Enter valid JSON before formatting.");
    }
  };

  const apply = async (event) => {
    event.preventDefault();
    setError("");
    let definition;
    if (mode === "guided") {
      definition = {
        risky_actions: actions.split(/[,\n]/).map((action) => action.trim()).filter(Boolean),
        resource_pattern: resource.trim(),
        require_global_grant: global,
      };
    } else {
      try {
        definition = { policy: JSON.parse(json), source_policy: source || undefined };
      } catch {
        setError("Enter valid IAM policy JSON.");
        return;
      }
    }
    setBusy(true);
    try {
      const { data } = await api.post("/api/scan/config/risks/validate", {
        id: rule?.id,
        category: rule?.category,
        description: description.trim(),
        severity: Number(weight),
        ...definition,
      });
      onApply(data);
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal show onHide={busy ? undefined : onClose} size="lg" centered scrollable
      contentClassName="bg-dark border-secondary text-light" aria-labelledby="rule-editor-title">
      <Form onSubmit={apply} className="d-flex flex-column overflow-hidden">
        <Modal.Header closeButton={!busy} className="border-secondary">
          <Modal.Title id="rule-editor-title">{rule ? "Edit risk rule" : "Add a risk rule"}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {!anonymousRule && (
            <div className="config-tabs nav nav-pills gap-1 mb-4" role="group" aria-label="Rule editor mode">
              {modes.map(([id, label]) => (
                <button key={id} type="button" className={"nav-link" + (mode === id ? " active" : "")}
                  aria-pressed={mode === id} disabled={busy}
                  onClick={() => { setMode(id); setError(""); }}>{label}</button>
              ))}
            </div>
          )}
          <div className="row g-3 mb-3">
            <Form.Group className="col-md-9" controlId="rule-title">
              <Form.Label>Rule name</Form.Label>
              <Form.Control value={description} required placeholder="e.g. Delete production objects"
                onChange={(event) => setDescription(event.target.value)} />
            </Form.Group>
            <Form.Group className="col-md-3" controlId="rule-weight">
              <Form.Label>Weight</Form.Label>
              <Form.Control type="number" min="0" step="1" required value={weight}
                onChange={(event) => setWeight(event.target.value)} />
            </Form.Group>
          </div>
          {mode === "guided" ? (
            <>
              <Form.Group className="mb-3" controlId="rule-actions">
                <Form.Label>Actions to flag</Form.Label>
                <Form.Control as="textarea" rows={2} className="font-monospace" value={actions} required
                  placeholder="s3:DeleteObject, s3:DeleteBucket"
                  onChange={(event) => setActions(event.target.value)} />
                <Form.Text>Use commas or new lines. Wildcards * and ? are supported.</Form.Text>
              </Form.Group>
              <Form.Group className="mb-3" controlId="rule-resource">
                <Form.Label>Resource pattern</Form.Label>
                <Form.Control className="font-monospace" value={resource} required
                  onChange={(event) => setResource(event.target.value)} />
              </Form.Group>
              <Form.Check id="rule-global" label="Only match deployment-wide access" checked={global}
                onChange={(event) => setGlobal(event.target.checked)} />
            </>
          ) : (
            <>
              {mode === "import" && (
                <Form.Group className="mb-3" controlId="rule-policy-source">
                  <Form.Label>MinIO policy</Form.Label>
                  <div className="d-flex flex-wrap gap-2">
                    <Form.Select className="flex-grow-1 w-auto" value={policyName} disabled={!policies || busy}
                      onChange={(event) => setPolicyName(event.target.value)}>
                      <option value="">{policies ? "Select a policy" : "Loading policies…"}</option>
                      {policies?.map((name) => <option key={name} value={name}>{name}</option>)}
                    </Form.Select>
                    <Button variant="secondary" disabled={!policyName || busy} onClick={importPolicy}>Load policy</Button>
                  </div>
                  {catalogError && <div className="text-warning small mt-2">{catalogError}</div>}
                </Form.Group>
              )}
              <div className="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2">
                <Form.Label htmlFor="rule-json" className="mb-0">IAM policy JSON</Form.Label>
                <div className="d-flex flex-wrap gap-2">
                  <label className="btn btn-sm btn-outline-light mb-0">
                    <FileUp size={15} className="me-1" />Upload JSON
                    <input type="file" accept=".json,application/json" className="visually-hidden"
                      disabled={busy} onChange={importFile} />
                  </label>
                  <Button variant="secondary" size="sm" onClick={format} disabled={busy}>
                    <Braces size={15} className="me-1" />Format
                  </Button>
                </div>
              </div>
              <Form.Control id="rule-json" as="textarea" rows={12} value={json} required spellCheck={false}
                className="font-monospace config-json-editor" onChange={(event) => setJson(event.target.value)} />
              {source && <p className="small text-body-secondary mt-2 mb-0">Source policy · {source}</p>}
              <Form.Text>
                Allow statements define the access to flag. Deny statements exclude scope, or define the
                access to flag when the document contains only Deny statements.
              </Form.Text>
            </>
          )}
          {error && <div className="alert alert-danger mt-3 mb-0" role="alert">{error}</div>}
        </Modal.Body>
        <Modal.Footer className="border-secondary">
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="submit" loading={busy} disabled={mode === "import" && (!source || source !== policyName)}>
            {rule ? "Apply changes" : "Add to draft"}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
}
