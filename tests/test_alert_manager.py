
from pathlib import Path
import shutil

from src.detection.alert_manager import AlertManager


def main():
    print("=" * 60)
    print("          AuditSentinel ALERT MANAGER TEST")
    print("=" * 60)

    base_dir = Path("dataset/samples/alert_manager_test")

    if base_dir.exists():
        shutil.rmtree(base_dir)

    base_dir.mkdir(parents=True, exist_ok=True)

    manager = AlertManager(
        storage_path=base_dir / "alerts.jsonl"
    )

    # TEST 1: Score an alert from detector and SQL operation evidence.
    print("\n[TEST 1] Score Alert")

    critical_result = {
        "record_index": 0,
        "mode": "supervised",
        "predicted_label": "attack",
        "verdict": "SUSPICIOUS",
        "confidence": 0.96,
        "alert": True,
    }

    outcome = manager.create_alert(
        detection_result=critical_result,
        model_id="test-model-001",
        model_name="Test Random Forest",
        record={
            "username": "admin",
            "src_ip": "192.168.1.10",
            "query": "SELECT * FROM users UNION SELECT * FROM accounts",
            "password": "should_not_be_saved",
        },
    )

    assert outcome["status"] == "CREATED"
    assert outcome["alert"]["severity"] == "MEDIUM"
    assert "password" not in outcome["alert"]["context"]

    critical_id = outcome["alert"]["alert_id"]

    print("[PASS] Score Alert")

    # TEST 2: Create a high alert.
    print("\n[TEST 2] Create High Alert")

    high_result = {
        "record_index": 1,
        "mode": "supervised",
        "predicted_label": "attack",
        "verdict": "SUSPICIOUS",
        "confidence": 0.75,
    }

    high = manager.create_alert(high_result)

    assert high["alert"]["severity"] == "HIGH"

    print("[PASS] Create High Alert")

    # TEST 3: Create an anomaly alert.
    print("\n[TEST 3] Create Anomaly Alert")

    anomaly_result = {
        "record_index": 2,
        "mode": "unsupervised",
        "verdict": "ANOMALY",
        "anomaly_score": -0.12,
    }

    anomaly = manager.create_alert(anomaly_result)

    assert anomaly["alert"]["severity"] == "HIGH"

    print("[PASS] Create Medium Alert")

    # TEST 4: Create a review alert.
    print("\n[TEST 4] Create Review Alert")

    review_result = {
        "record_index": 3,
        "mode": "supervised",
        "predicted_label": "unclassified",
        "verdict": "REVIEW",
    }

    review = manager.create_alert(review_result)

    assert review["alert"]["severity"] == "MEDIUM"

    print("[PASS] Create Review Alert")

    # TEST 5: Ignore normal results.
    print("\n[TEST 5] Ignore Normal Results")

    normal_result = {
        "record_index": 4,
        "mode": "supervised",
        "predicted_label": "normal",
        "verdict": "NORMAL",
        "confidence": 0.99,
    }

    normal = manager.create_alert(normal_result)

    assert normal["status"] == "NO_ALERT"

    print("[PASS] Ignore Normal Results")

    # TEST 6: Ingest batch detection output.
    print("\n[TEST 6] Batch Alert Ingestion")

    detection_output = {
        "status": "COMPLETED",
        "model_id": "batch-model",
        "model_name": "Batch Detection Model",
        "results": [
            {
                "record_index": 0,
                "mode": "supervised",
                "verdict": "SUSPICIOUS",
                "predicted_label": "attack",
                "confidence": 0.95,
            },
            {
                "record_index": 1,
                "mode": "supervised",
                "verdict": "NORMAL",
                "predicted_label": "normal",
                "confidence": 0.98,
            },
        ],
    }

    records = [
        {
            "username": "root",
            "src_ip": "10.0.0.1",
        },
        {
            "username": "guest",
            "src_ip": "10.0.0.2",
        },
    ]

    batch = manager.ingest_detection(
        detection_output,
        records=records,
    )

    assert batch["alerts_created"] == 1
    assert batch["records_skipped"] == 1
    assert batch["alerts"][0]["context"]["username"] == "root"

    print("[PASS] Batch Alert Ingestion")

    # TEST 7: Filter alerts.
    print("\n[TEST 7] Alert Filtering")

    critical_alerts = manager.list_alerts(
        severity="CRITICAL"
    )

    assert len(critical_alerts) == 2

    new_alerts = manager.list_alerts(
        status="NEW"
    )

    assert len(new_alerts) == 5

    print("[PASS] Alert Filtering")

    # TEST 8: Acknowledge alert.
    print("\n[TEST 8] Acknowledge Alert")

    acknowledged = manager.update_status(
        critical_id,
        "ACKNOWLEDGED",
    )

    assert acknowledged["status"] == "UPDATED"
    assert acknowledged["alert"]["status"] == "ACKNOWLEDGED"

    print("[PASS] Acknowledge Alert")

    # TEST 9: Resolve alert.
    print("\n[TEST 9] Resolve Alert")

    resolved = manager.update_status(
        critical_id,
        "RESOLVED",
        resolution="Reviewed and confirmed as a test event.",
    )

    assert resolved["alert"]["status"] == "RESOLVED"
    assert resolved["alert"]["resolution"]

    print("[PASS] Resolve Alert")

    # TEST 10: Reject resolution without a note.
    print("\n[TEST 10] Require Resolution Note")

    another_alert = manager.create_alert(
        detection_result=critical_result
    )

    try:
        manager.update_status(
            another_alert["alert"]["alert_id"],
            "RESOLVED",
        )

        raise AssertionError("Resolution note should be required")

    except ValueError as exc:
        assert "resolution note" in str(exc).lower()

    print("[PASS] Require Resolution Note")

    # TEST 11: Reject unknown alert.
    print("\n[TEST 11] Reject Unknown Alert")

    try:
        manager.update_status(
            "unknown-alert-id",
            "ACKNOWLEDGED",
        )

        raise AssertionError("Unknown alert should be rejected")

    except KeyError:
        pass

    print("[PASS] Reject Unknown Alert")

    # TEST 12: Statistics.
    print("\n[TEST 12] Alert Statistics")

    statistics = manager.get_statistics()

    print("Total alerts:", statistics["total_alerts"])
    print("Severity counts:", statistics["severity_counts"])
    print("Status counts:", statistics["status_counts"])

    assert statistics["total_alerts"] == 6
    assert statistics["severity_counts"]["CRITICAL"] == 3
    assert statistics["severity_counts"]["HIGH"] == 1
    assert statistics["severity_counts"]["MEDIUM"] == 1
    assert statistics["severity_counts"]["LOW"] == 1

    print("[PASS] Alert Statistics")

    # TEST 13: Verify persistent JSONL storage.
    print("\n[TEST 13] Persistent Storage")

    new_manager = AlertManager(
        storage_path=base_dir / "alerts.jsonl"
    )

    persisted_alerts = new_manager.list_alerts()

    assert len(persisted_alerts) == 6
    assert Path(base_dir / "alerts.jsonl").exists()

    print("[PASS] Persistent Storage")

    print("\n" + "=" * 60)
    print("ALL ALERT MANAGER TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
