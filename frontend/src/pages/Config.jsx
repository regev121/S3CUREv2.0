import { useCallback, useEffect, useState } from "react";
import { Badge, Form, Spinner } from "react-bootstrap";
import { BookOpen, Plus, Pencil, Save, ScanLine, Search, Trash2 } from "lucide-react";
import { Card, CardContent } from "../components/Card";
import { Button } from "../components/Button";
import api from "../services/api";
import RuleEditor from "./RuleEditor";

function ruleTitle(rule) {
  return rule.description.replace(/^(CRITICAL|HIGH|MEDIUM|LOW):\s*/i, "");
}

function ruleCategory(rule) {
  return rule.category || "General";
}

function weightTone(weight) {
  if (weight >= 9) return "danger";
  if (weight >= 7) return "warning";
  return "secondary";
}

function RuleRow({ rule, onEdit, onRemove, onAdd, added }) {
  return (
    <article className="config-rule">
      <div className="d-flex flex-wrap align-items-start justify-content-between gap-3">
        <div className="config-rule-title">
          <div className="d-flex flex-wrap gap-2 align-items-center">
            <h3 className="h6 mb-0">{ruleTitle(rule)}</h3>
            <Badge bg={weightTone(rule.severity)} pill>Weight {rule.severity}</Badge>
          </div>
          <p className="text-body-secondary small mt-1 mb-0">
            {[ruleCategory(rule), rule.source_policy ? "MinIO · " + rule.source_policy :
              rule.policy ? "IAM policy" : "Guided rule"].join(" · ")}
          </p>
        </div>
        <div className="d-flex align-items-center gap-2">
          {onEdit && (
            <>
              <Button variant="secondary" size="sm" onClick={onEdit}
                aria-label={"Edit " + ruleTitle(rule)}><Pencil size={14} className="me-1" />Edit</Button>
              <Button variant="ghost" size="sm" onClick={onRemove}
                aria-label={"Remove " + ruleTitle(rule)}><Trash2 size={16} /></Button>
            </>
          )}
          {onAdd && (
            <Button variant="secondary" size="sm" disabled={added} onClick={onAdd}>
              {added ? "Added" : "Add rule"}
            </Button>
          )}
        </div>
      </div>
      <details className="mt-2 small">
        <summary className="text-body-secondary">View matching criteria</summary>
        {rule.policy ? (
          <pre className="config-policy-preview p-3 rounded mt-2 mb-0">{JSON.stringify(rule.policy, null, 2)}</pre>
        ) : (
          <dl className="config-rule-scope mt-2 mb-0">
            <dt>Resource</dt><dd><code>{rule.resource_pattern}</code></dd>
            <dt>Actions</dt><dd><code>{rule.risky_actions?.join(", ")}</code></dd>
            {rule.require_global_grant && <><dt>Scope</dt><dd>Deployment-wide access</dd></>}
          </dl>
        )}
      </details>
    </article>
  );
}

function responseMessage(error, fallback) {
  const detail = error.response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
}

export default function Config() {
  const [rules, setRules] = useState([]);
  const [savedRules, setSavedRules] = useState(rules);
  const [catalog, setCatalog] = useState([]);
  const [revision, setRevision] = useState(null);
  const [label, setLabel] = useState("");
  const [view, setView] = useState("rules");
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [editing, setEditing] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [message, setMessage] = useState(null);

  const load = useCallback(async (signal) => {
    setLoading(true);
    setMessage(null);
    try {
      const [{ data: config }, { data: templates }] = await Promise.all([
        api.get("/api/scan/config/risks", { signal }),
        api.get("/api/scan/config/risk-catalog", { signal }),
      ]);
      setRules(config.risk_rules);
      setSavedRules(config.risk_rules);
      setRevision(config.revision ?? null);
      setLabel(config.label);
      setCatalog(templates.rules);
      setLoadFailed(false);
    } catch (error) {
      if (!signal?.aborted) {
        setLoadFailed(true);
        setMessage({ type: "danger", text: responseMessage(error, "Unable to load the risk configuration.") });
      }
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const request = new AbortController();
    load(request.signal);
    return () => request.abort();
  }, [load]);

  const dirty = rules !== savedRules;
  const activeIds = new Set(rules.map((rule) => rule.id).filter(Boolean));
  const available = catalog.filter((rule) => !activeIds.has(rule.id));
  const rows = view === "rules" ? rules : catalog;
  const categories = [...new Set(rows.map(ruleCategory))].sort();
  const term = query.trim().toLowerCase();
  const visible = rows.map((rule, index) => ({ rule, index })).filter(({ rule }) =>
    (!category || ruleCategory(rule) === category) &&
    (!term || JSON.stringify(rule).toLowerCase().includes(term))
  );
  const totalWeight = rules.reduce((sum, rule) => sum + rule.severity, 0);

  const selectView = (next) => {
    setView(next);
    setCategory("");
  };

  const addRules = (entries) => {
    setRules((current) => [...current, ...entries]);
    setMessage(null);
  };

  const applyRule = (rule) => {
    setRules((current) => editing.index === null ? [...current, rule] :
      current.map((entry, index) => index === editing.index ? rule : entry));
    setEditing(null);
    setMessage(null);
  };

  const save = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const { data } = await api.post("/api/scan/config/risks", { risk_rules: rules, base_revision: revision });
      setRevision(data.revision);
      setLabel(data.label);
      setSavedRules(rules);
      setMessage({ type: "success", text: "Configuration saved. The next scan will use these rules." });
    } catch (error) {
      setMessage({ type: "danger", text: responseMessage(error, "Unable to save the risk configuration.") });
    } finally {
      setSaving(false);
    }
  };

  const scanAll = async () => {
    if (!window.confirm("Run a new scan for every user with the saved configuration?")) return;
    setScanning(true);
    setMessage(null);
    try {
      const { data } = await api.post("/api/scan/initialize");
      const scanned = data.details.filter((result) => result.status === "scanned").length;
      const failed = data.details.length - scanned;
      setMessage({
        type: failed ? "warning" : "success",
        text: "Scanned " + scanned + " users." + (failed ? " " + failed + " scans failed." : ""),
      });
    } catch (error) {
      setMessage({ type: "danger", text: responseMessage(error, "Unable to scan all users.") });
    } finally {
      setScanning(false);
    }
  };

  return (
    <section className="risk-config" aria-labelledby="risk-config-heading">
      <div className="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-4">
        <div>
          <h1 id="risk-config-heading" className="h2 fw-bold text-light mb-1">Risk configuration</h1>
          <p className="text-body-secondary mb-0">Choose which permissions affect the risk score.</p>
        </div>
        <div className="d-flex flex-wrap align-items-center gap-2">
          {dirty && <span className="small text-warning me-1">Unsaved changes</span>}
          {(dirty || loadFailed) && (
            <Button variant="secondary" onClick={() => load()} disabled={saving || loading}>
              {dirty ? "Discard draft" : "Retry"}
            </Button>
          )}
          <Button onClick={save} disabled={loading || loadFailed || !dirty} loading={saving}>
            <Save size={16} className="me-2" />Save configuration
          </Button>
        </div>
      </div>

      {message && <div className={"alert alert-" + message.type + " py-2"} role="status">{message.text}</div>}

      {loading ? <div className="text-center py-5"><Spinner animation="border" variant="primary" /></div> :
        !loadFailed && (
          <>
            <div className="config-summary border border-secondary rounded px-3 py-3 mb-4">
              <div>
                <span className="d-block small text-body-secondary">{dirty ? "Rules in draft" : "Active rules"}</span>
                <strong className="fs-5">{rules.length}</strong>
              </div>
              <div>
                <span className="d-block small text-body-secondary">Total weight</span>
                <strong className="fs-5">{totalWeight}</strong>
              </div>
              <div className="flex-grow-1">
                <span className="d-block small text-body-secondary">Saved configuration</span>
                <strong className="text-break">{label}</strong>
              </div>
              <Button variant="secondary" size="sm" onClick={scanAll} loading={scanning} disabled={saving}>
                <ScanLine size={16} className="me-2" />Scan all users
              </Button>
            </div>

            <fieldset disabled={saving} className="m-0 p-0 border-0">
              <Card>
                <CardContent className="p-0">
                  <div className="d-flex flex-wrap justify-content-between align-items-center gap-3 px-3 pt-3">
                    <div className="config-tabs nav nav-pills gap-1" role="group" aria-label="Rule views">
                      <button type="button" className={"nav-link" + (view === "rules" ? " active" : "")}
                        aria-pressed={view === "rules"} onClick={() => selectView("rules")}>Active rules</button>
                      <button type="button" className={"nav-link" + (view === "catalog" ? " active" : "")}
                        aria-pressed={view === "catalog"} onClick={() => selectView("catalog")}>
                        <BookOpen size={16} className="me-2" />Rule catalog
                      </button>
                    </div>
                    {view === "rules" ? (
                      <Button onClick={() => setEditing({ index: null, rule: null })}>
                        <Plus size={16} className="me-2" />Add rule
                      </Button>
                    ) : (
                      <Button onClick={() => addRules(available)} disabled={!available.length}>Add all available rules</Button>
                    )}
                  </div>
                  <div className="d-flex flex-wrap gap-2 p-3 border-bottom border-secondary">
                    <div className="config-search">
                      <Search size={17} aria-hidden="true" />
                      <Form.Control type="search" aria-label="Search rules" placeholder="Search rules, actions or resources"
                        value={query} onChange={(event) => setQuery(event.target.value)} />
                    </div>
                    <Form.Select aria-label="Filter by category" className="w-auto" value={category}
                      onChange={(event) => setCategory(event.target.value)}>
                      <option value="">All categories</option>
                      {categories.map((name) => <option key={name} value={name}>{name}</option>)}
                    </Form.Select>
                  </div>
                  {visible.length ? (
                    <div>
                      {visible.map(({ rule, index }) => (
                        <RuleRow key={rule.id ?? index} rule={rule}
                          onEdit={view === "rules" ? () => setEditing({ index, rule }) : undefined}
                          onRemove={() => {
                            setRules((current) => current.filter((_, position) => position !== index));
                            setMessage(null);
                          }}
                          onAdd={view === "catalog" ? () => addRules([rule]) : undefined}
                          added={activeIds.has(rule.id)} />
                      ))}
                    </div>
                  ) : (
                    <p className="text-body-secondary text-center p-4 mb-0">
                      {rows.length ? "No rules match your search." : "Add a rule or choose one from the catalog."}
                    </p>
                  )}
                </CardContent>
              </Card>
            </fieldset>
          </>
        )}

      {editing && <RuleEditor rule={editing.rule} onClose={() => setEditing(null)} onApply={applyRule} />}
    </section>
  );
}
