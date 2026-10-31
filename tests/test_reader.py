
from pathlib import Path

from src.reader.detector import detect_format
from src.reader.analyzer import analyze_file


def main():
    print("=" * 50)
    print("       AuditSentinel UNIVERSAL READER TEST")
    print("=" * 50)

    # Create a small test dataset.
    test_dir = Path("dataset/samples")
    test_dir.mkdir(parents=True, exist_ok=True)

    test_file = test_dir / "test.csv"

    test_file.write_text(
        "username,action,status\n"
        "admin,login,success\n"
        "guest,login,failed\n"
        "root,query,success\n",
        encoding="utf-8"
    )

    # Test 1: Format detection.
    print("\n[TEST 1] Format Detection")

    detection = detect_format(test_file)
    print(detection)

    assert detection["format"] == "csv"
    assert detection["status"] == "SUPPORTED"

    print("[PASS] Format Detection")

    # Test 2: File analysis.
    print("\n[TEST 2] File Analysis")

    analysis = analyze_file(test_file)
    print(analysis)

    assert analysis["status"] == "ANALYZED"
    assert analysis["format"] == "csv"

    print("[PASS] File Analysis")

    # Test 3: Python source safety.
    print("\n[TEST 3] Python Source Safety")

    python_file = test_dir / "sample.py"

    python_file.write_text(
        "print('This file must never execute')\n",
        encoding="utf-8"
    )

    python_analysis = analyze_file(python_file)

    assert python_analysis["details"]["execution"] == "NEVER_EXECUTED"

    print("[PASS] Python Source Safety")

    print("\n" + "=" * 50)
    print("ALL TESTS PASSED")
    print("=" * 50)


if __name__ == "__main__":
    main()
