
from src.investigation.engine import InvestigationEngine


def main():
    engine = InvestigationEngine(
        model="qwen2.5:1.5b",
        timeout=180
    )

    print("Checking Ollama connection...")
    connection = engine.check_connection()
    print(connection)

    if not connection.get("connected"):
        raise SystemExit(
            "Ollama is not available. Check Ollama service."
        )

    alert = {
        "alert_id": "REAL-TEST-001",
        "severity": "HIGH",
        "mode": "supervised",
        "verdict": "SUSPICIOUS",
        "predicted_label": "attack",
        "confidence": 0.92,
        "model_name": "Test Detection Model",
        "context": {
            "username": "admin",
            "src_ip": "192.168.1.100",
            "query": (
                "SELECT * FROM users "
                "UNION SELECT username, password FROM accounts"
            ),
            "action": "SELECT",
            "status": "FAILED"
        }
    }

    print("\nSending alert to AI Investigation Engine...")
    result = engine.investigate(alert)

    print("\nINVESTIGATION STATUS:")
    print(result.get("status"))

    print("\nINVESTIGATION REPORT:")
    report = result.get("report", {})

    for key, value in report.items():
        print(f"\n{key}:")
        print(value)

    if result.get("status") != "COMPLETED":
        raise SystemExit("Investigation failed.")

print("\nINVESTIGATION TEST PASSED!")


if __name__ == "__main__":
    main()
