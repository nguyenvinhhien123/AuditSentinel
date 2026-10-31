
from pathlib import Path

import json
import polars as pl
from openpyxl import Workbook

from src.reader.parser import parse_file


def main():
    print("=" * 55)
    print("          AuditSentinel UNIVERSAL PARSER TEST")
    print("=" * 55)

    test_dir = Path("dataset/samples/parser_test")
    test_dir.mkdir(parents=True, exist_ok=True)

    # Create synthetic test files.
    (test_dir / "sample.csv").write_text(
        "username,action\nadmin,login\nguest,logout\n",
        encoding="utf-8"
    )

    (test_dir / "sample.tsv").write_text(
        "username\taction\nadmin\tlogin\n",
        encoding="utf-8"
    )

    (test_dir / "sample.json").write_text(
        json.dumps({
            "event": "login",
            "username": "admin",
            "status": "success"
        }),
        encoding="utf-8"
    )

    (test_dir / "sample.jsonl").write_text(
        '{"event":"login","status":"success"}\n'
        '{"event":"query","status":"success"}\n',
        encoding="utf-8"
    )

    (test_dir / "sample.yaml").write_text(
        "event: login\nusername: admin\nstatus: success\n",
        encoding="utf-8"
    )

    (test_dir / "sample.xml").write_text(
        '<events><event user="admin">login</event></events>',
        encoding="utf-8"
    )

    (test_dir / "sample.log").write_text(
        "2026-10-30 LOGIN SUCCESS\n"
        "2026-10-30 LOGIN FAILED\n",
        encoding="utf-8"
    )

    (test_dir / "sample.py").write_text(
        "print('This code must never execute')\n",
        encoding="utf-8"
    )

    # Create Excel file.
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["username", "action"])
    sheet.append(["admin", "login"])
    workbook.save(test_dir / "sample.xlsx")

    # Create Parquet file.
    pl.DataFrame({
        "username": ["admin", "guest"],
        "action": ["login", "logout"]
    }).write_parquet(test_dir / "sample.parquet")

    test_files = [
        "sample.csv",
        "sample.tsv",
        "sample.json",
        "sample.jsonl",
        "sample.yaml",
        "sample.xml",
        "sample.log",
        "sample.py",
        "sample.xlsx",
        "sample.parquet",
    ]

    passed = 0

    for filename in test_files:
        print(f"\n[TEST] {filename}")

        result = parse_file(test_dir / filename)

        print("Status:", result["status"])
        print("Format:", result.get("format"))

        assert result["status"] == "PARSED", result

        if filename == "sample.py":
            assert result["details"]["execution"] == "NEVER_EXECUTED"

        print("[PASS]", filename)
        passed += 1

    print("\n" + "=" * 55)
    print(f"RESULT: {passed}/{len(test_files)} TESTS PASSED")
    print("=" * 55)


if __name__ == "__main__":
    main()
