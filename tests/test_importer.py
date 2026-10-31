
from pathlib import Path

from src.reader.importer import scan_path


def main():
    print("=" * 50)
    print("       AuditSentinel IMPORTER TEST")
    print("=" * 50)

    test_dir = Path("dataset/samples/importer_test")
    test_dir.mkdir(parents=True, exist_ok=True)

    # Create synthetic test files.
    (test_dir / "users.csv").write_text(
        "username,action\nadmin,login\nguest,logout\n",
        encoding="utf-8"
    )

    (test_dir / "events.log").write_text(
        "2026-10-30 LOGIN SUCCESS\n"
        "2026-10-30 LOGIN FAILED\n",
        encoding="utf-8"
    )

    (test_dir / "unknown.xyz").write_text(
        "Synthetic unsupported file",
        encoding="utf-8"
    )

    # Test 1: Scan a single file.
    print("\n[TEST 1] Single File Scan")

    result = scan_path(test_dir / "users.csv")

    assert result["total_files"] == 1
    assert result["supported"] == 1

    print("[PASS] Single File Scan")

    # Test 2: Scan a directory.
    print("\n[TEST 2] Folder Scan")

    result = scan_path(test_dir)

    print("Total:", result["total_files"])
    print("Supported:", result["supported"])
    print("Unsupported:", result["unsupported"])

    assert result["total_files"] == 3
    assert result["supported"] == 2
    assert result["unsupported"] == 1

    print("[PASS] Folder Scan")

    # Test 3: Ignore virtual environment folders.
    print("\n[TEST 3] Ignore Directories")

    ignored_dir = test_dir / ".venv"
    ignored_dir.mkdir(exist_ok=True)

    (ignored_dir / "ignored.csv").write_text(
        "should,not,be,scanned",
        encoding="utf-8"
    )

    result = scan_path(test_dir)

    assert result["total_files"] == 3

    print("[PASS] Ignore Directories")

    print("\n" + "=" * 50)
    print("ALL IMPORTER TESTS PASSED")
    print("=" * 50)


if __name__ == "__main__":
    main()
