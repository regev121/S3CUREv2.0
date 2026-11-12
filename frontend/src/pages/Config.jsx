import { useState, useEffect } from "react";
import api from "../services/api";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "../components/Card";
import { Button } from "../components/Button";
import { useAuth } from "../context/auth";
import { Table, Badge, Modal, Form, Spinner } from "react-bootstrap";
import {
  Settings,
  Plus,
  Edit,
  Trash2,
  Save,
  RotateCcw,
} from "lucide-react";

/**
 * Risk Configuration Management Page.
 * Allows administrators to define, weight, and manage global risk detection rules.
 * Features:
 * - CRUD operations for Role-Based Assessment Criteria.
 * - System-wide Scan Initialization.
 * - Role-Based Access Control (Admin only for edits).
 */
export default function Config() {
  const { user } = useAuth();
  const [rules, setRules] = useState([]);
  const [configLabel, setConfigLabel] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [initLoading, setInitLoading] = useState(false);

  // Modal State Management
  const [showModal, setShowModal] = useState(false);
  const [editingIndex, setEditingIndex] = useState(null); // null indicates Creation Mode
  const [formData, setFormData] = useState({
    description: "",
    severity: 10,
    resource_pattern: "",
    risky_actions: "",
    require_global_grant: false,
  });

  const canEdit = user?.role === "ADMIN";

  useEffect(() => {
    fetchRules();
  }, []);

  /**
   * Retrieves the current risk configuration from the backend.
   */
  const fetchRules = async () => {
    setLoading(true);
    try {
      const { data } = await api.get("/api/scan/config/risks");
      setConfigLabel(data.label ?? "");
      // Backward compatibility: Handle both wrapper object and direct array responses
      if (data.risk_rules) {
        setRules(data.risk_rules);
      } else if (Array.isArray(data)) {
        setRules(data);
      } else {
        setRules([]);
      }
    } catch (err) {
      console.error("Failed to load rules", err);
      setRules([]);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Triggers a system-wide initialization of security scans for all users.
   * This is a batch operation to populate the dashboard.
   */
  const handleInitialize = async () => {
      if (!window.confirm("This will scan ALL users in the system. Continue?")) return;
      setInitLoading(true);
      try {
          const { data } = await api.post("/api/scan/initialize");
          alert(`Initialization Complete: ${data.details.length} users scanned.`);
      } catch (e) {
          alert("Initialization failed: " + e.message);
      } finally {
          setInitLoading(false);
      }
  };

  // --- CRUD Operations ---

  const handleAdd = () => {
    setFormData({
      description: "",
      severity: 10,
      resource_pattern: "",
      risky_actions: "",
      require_global_grant: false,
    });
    setEditingIndex(null);
    setShowModal(true);
  };

  const handleEdit = (index) => {
    const rule = rules[index];
    setFormData({
      description: rule.description,
      severity: rule.severity,
      resource_pattern: rule.resource_pattern,
      risky_actions: Array.isArray(rule.risky_actions)
        ? rule.risky_actions.join(", ")
        : rule.risky_actions || "",
      require_global_grant: Boolean(rule.require_global_grant),
    });
    setEditingIndex(index);
    setShowModal(true);
  };

  const handleDelete = (index) => {
    if (window.confirm("Are you sure you want to delete this rule?")) {
      const newRules = [...rules];
      newRules.splice(index, 1);
      setRules(newRules);
    }
  };

  const handleSaveModal = (e) => {
    e.preventDefault();

    // Normalize actions string to array
    const actionsArray = formData.risky_actions
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    const newRule = {
      id: rules[editingIndex]?.id,
      description: formData.description,
      severity: parseInt(formData.severity),
      resource_pattern: formData.resource_pattern,
      risky_actions: actionsArray,
      require_global_grant: formData.require_global_grant,
    };

    const newRules = [...rules];
    if (editingIndex !== null) {
      newRules[editingIndex] = newRule;
    } else {
      newRules.push(newRule);
    }

    setRules(newRules);
    setShowModal(false);
  };

  /**
   * Persists the local modified ruleset to the backend.
   */
  const handleSaveChanges = async () => {
    setSaving(true);
    try {
      const { data } = await api.post("/api/scan/config/risks", { risk_rules: rules });
      setConfigLabel(data.label ?? "");
      alert("Configuration saved successfully!");
    } catch (err) {
      console.error(err);
      alert("Failed to save configuration.");
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    if (window.confirm("Discard unsaved changes and reload from server?")) {
      fetchRules();
    }
  };

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h1 className="h2 fw-bold text-light mb-1">Risk Configuration</h1>
          <p className="text-body-secondary mb-0">
            {configLabel || "Manage detection rules and risk scoring logic."}
          </p>
        </div>
        <div className="d-flex gap-2">
           <Button
              variant="outline-secondary"
              onClick={handleInitialize}
              loading={initLoading}
              disabled={initLoading}
              className="d-flex align-items-center gap-2"
           >
              <RotateCcw size={16} />
              Initialize Scans
           </Button>
           {canEdit && (
              <>
                 <Button
                    variant="secondary"
                    onClick={handleReset}
                    disabled={saving}
                    className="d-flex align-items-center gap-2"
                 >
                    <RotateCcw size={16} />
                    Reset
                 </Button>
                 <Button
                    variant="primary"
                    onClick={handleSaveChanges}
                    loading={saving}
                    disabled={saving}
                    className="d-flex align-items-center gap-2"
                 >
                    <Save size={16} />
                    Save Changes
                 </Button>
              </>
           )}
        </div>
      </div>

      <Card className="border-secondary">
        <CardHeader className="d-flex justify-content-between align-items-center border-secondary">
          <CardTitle className="d-flex align-items-center gap-2">
            <Settings className="text-primary" />
            Detection Rules
          </CardTitle>
          {canEdit && (
            <Button size="sm" variant="success" onClick={handleAdd}>
              <Plus size={16} className="me-1" />
              Add Rule
            </Button>
          )}
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="text-center py-5">
              <Spinner animation="border" variant="primary" />
            </div>
          ) : (
            <Table
              hover
              variant="dark"
              responsive
              className="mb-0 align-middle"
              style={{ background: "transparent" }}
            >
              <thead className="bg-dark text-body-secondary">
                <tr>
                  <th style={{ width: "5%" }}>#</th>
                  <th style={{ width: "30%" }}>Description</th>
                  <th style={{ width: "10%" }}>Severity</th>
                  <th style={{ width: "20%" }}>Resource Pattern</th>
                  <th style={{ width: "25%" }}>Risky Actions</th>
                  {canEdit && <th style={{ width: "10%" }} className="text-end">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, idx) => (
                  <tr key={idx}>
                    <td className="text-body-secondary">{idx + 1}</td>
                    <td className="fw-medium text-light">{rule.description}</td>
                    <td>
                      <Badge
                        bg={
                          rule.severity >= 9
                            ? "danger" // Critical
                            : rule.severity >= 7
                            ? "warning" // High
                            : "info" // Medium/Low
                        }
                        className="px-2 py-1"
                      >
                        {rule.severity}
                      </Badge>
                    </td>
                    <td className="text-info font-monospace small">
                      {rule.resource_pattern}
                    </td>
                    <td>
                      <div className="d-flex flex-wrap gap-1">
                        {(rule.risky_actions || []).map((action, i) => (
                          <Badge
                            key={i}
                            bg="secondary"
                            className="fw-normal font-monospace small"
                          >
                            {action}
                          </Badge>
                        ))}
                      </div>
                    </td>
                    {canEdit && (
                      <td className="text-end">
                        <Button
                          variant="link"
                          size="sm"
                          className="text-primary p-1 me-1"
                          onClick={() => handleEdit(idx)}
                        >
                          <Edit size={16} />
                        </Button>
                        <Button
                          variant="link"
                          size="sm"
                          className="text-danger p-1"
                          onClick={() => handleDelete(idx)}
                        >
                          <Trash2 size={16} />
                        </Button>
                      </td>
                    )}
                  </tr>
                ))}
                {rules.length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center py-4 text-body-secondary">
                      No rules defined.
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Edit/Add Modal */}
      <Modal
        show={showModal}
        onHide={() => setShowModal(false)}
        centered
        variant="dark"
        contentClassName="bg-dark border-secondary text-light"
      >
        <Modal.Header closeButton className="border-secondary">
          <Modal.Title>{editingIndex !== null ? "Edit Rule" : "Add Rule"}</Modal.Title>
        </Modal.Header>
        <Form onSubmit={handleSaveModal}>
          <Modal.Body>
            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control
                type="text"
                required
                className="bg-dark border-secondary text-light focus-ring-primary"
                value={formData.description}
                onChange={(e) =>
                  setFormData({ ...formData, description: e.target.value })
                }
              />
            </Form.Group>

            <div className="row">
              <div className="col-md-4">
                <Form.Group className="mb-3">
                  <Form.Label>Severity (1-10)</Form.Label>
                  <Form.Control
                    type="number"
                    min="1"
                    max="10"
                    required
                    className="bg-dark border-secondary text-light"
                    value={formData.severity}
                    onChange={(e) =>
                      setFormData({ ...formData, severity: e.target.value })
                    }
                  />
                </Form.Group>
              </div>
              <div className="col-md-8">
                <Form.Group className="mb-3">
                  <Form.Label>Resource Pattern (AWS ARN / Glob)</Form.Label>
                  <Form.Control
                    type="text"
                    required
                    placeholder="e.g., arn:aws:s3:::* or *"
                    className="bg-dark border-secondary text-light font-monospace"
                    value={formData.resource_pattern}
                    onChange={(e) =>
                      setFormData({ ...formData, resource_pattern: e.target.value })
                    }
                  />
                </Form.Group>
              </div>
            </div>

            <Form.Group className="mb-3">
              <Form.Label>Risky Actions (Comma separated)</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                required
                placeholder="e.g., s3:PutObject, s3:DeleteBucket"
                className="bg-dark border-secondary text-light font-monospace"
                value={formData.risky_actions}
                onChange={(e) =>
                  setFormData({ ...formData, risky_actions: e.target.value })
                }
              />
              <Form.Text className="text-body-secondary">
                 Separate multiple actions with commas. Wildcards supported.
              </Form.Text>
            </Form.Group>
            <Form.Check
              id="require-global-grant"
              label="Require a deployment-wide grant"
              checked={formData.require_global_grant}
              onChange={(e) =>
                setFormData({ ...formData, require_global_grant: e.target.checked })
              }
            />
            <Form.Text className="text-body-secondary">
              Match grants on all resources. With * or s3:* in the action list, require the full action scope.
            </Form.Text>
          </Modal.Body>
          <Modal.Footer className="border-secondary">
            <Button variant="outline-secondary" onClick={() => setShowModal(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit">
              {editingIndex !== null ? "Update Rule" : "Add Rule"}
            </Button>
          </Modal.Footer>
        </Form>
      </Modal>
    </div>
  );
}
