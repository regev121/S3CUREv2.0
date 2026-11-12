from backend.demo_risk import run_demo


def test_demo_preserves_read_access_and_removes_delete_access_in_simulation():
    data = run_demo()
    archived = data["archived_scan"]
    simulation = data["simulation"]

    assert archived["risk_score"] == simulation["before"] == 34.55
    assert len(archived["risk_config_version"]) == 64
    assert simulation["after"] == 16.36
    assert simulation["delta"] == -18.19
    assert simulation["effective_groups_after_simulation"] == ["prod-editors"]
    assert simulation["archived_scans"] == 1
    assert [grant["action"] for finding in simulation["findings"] for grant in finding["evidence"]] == [
        "s3:GetObject",
    ]
