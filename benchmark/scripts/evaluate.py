#!/usr/bin/env python3
"""
WyScan benchmark validator.

This script runs the built CLI against each benchmark directory and writes a
single markdown summary to benchmark/BENCHMARK_RESULTS.md.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = ROOT / "benchmark"
RESULTS_PATH = BENCHMARK_DIR / "BENCHMARK_RESULTS.md"
CLI_PATH = ROOT / "dist" / "cli" / "index.js"
CODE_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx", ".rs"}


@dataclass
class BenchmarkResult:
    name: str
    languages: str
    expected_result: str
    actual_result: str
    status: str
    notes: str


def benchmark_directories() -> list[Path]:
    return sorted(
        [path for path in BENCHMARK_DIR.iterdir() if path.is_dir() and path.name != "scripts"],
        key=lambda path: path.name,
    )


def load_manifest(system_dir: Path) -> tuple[int | None, list[str]]:
    manifest_path = system_dir / "cee_manifest.json"
    if not manifest_path.exists():
        return None, []

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_findings = manifest.get("expected_findings")
    expected = len(expected_findings) if isinstance(expected_findings, list) else None
    languages = manifest.get("metadata", {}).get("languages", [])
    return expected, languages


def load_manifest_data(system_dir: Path) -> dict[str, Any] | None:
    manifest_path = system_dir / "cee_manifest.json"
    if not manifest_path.exists():
        return None

    return json.loads(manifest_path.read_text(encoding="utf-8"))


def count_code_files(system_dir: Path) -> int:
    return sum(1 for path in system_dir.rglob("*") if path.is_file() and path.suffix in CODE_EXTENSIONS)


def run_scan(system_dir: Path) -> tuple[int, dict]:
    import tempfile

    # Use a temp file to avoid subprocess buffer limits on large outputs
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        process = subprocess.run(
            f"node {CLI_PATH} scan {system_dir} --json > {tmp_path}",
            cwd=ROOT,
            shell=True,
            text=True,
            capture_output=True,
            check=False,
        )

        json_output = Path(tmp_path).read_text(encoding="utf-8")
        if not json_output.strip():
            raise RuntimeError(f"No JSON output for {system_dir.name}: {process.stderr.strip()}")

        return process.returncode, json.loads(json_output)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def actual_result_text(exit_code: int, report: dict) -> str:
    summary = report["summary"]
    coverage = report["coverage"]
    cees = report.get("cees", [])
    afb04_cees = [cee for cee in cees if cee.get("afb_type") == "AFB04"]
    return (
        f"{len(cees)} cees, {len(afb04_cees)} afb04 findings "
        f"({summary['critical']}C/{summary['warning']}W/{summary['info']}I), "
        f"exit {exit_code}, analyzed {coverage['files_analyzed']}, "
        f"skipped {coverage['files_skipped']}, failed {len(coverage['failed_files'])}"
    )


def normalize_relative_path(system_dir: Path, file_path: str | None) -> str | None:
    if not file_path:
        return None

    try:
        return Path(file_path).resolve().relative_to(system_dir.resolve()).as_posix()
    except ValueError:
        return Path(file_path).as_posix()


def cee_matches(system_dir: Path, actual: dict, expected: dict) -> bool:
    expected_tool = expected.get("tool_registration")
    expected_file = expected.get("file")
    expected_operation = expected.get("operation")
    expected_afb = expected.get("afb_type")

    actual_file = normalize_relative_path(system_dir, actual.get("file"))
    actual_operation = actual.get("operation", "")
    actual_tool = actual.get("tool")
    actual_afb = actual.get("afb_type")

    if expected_tool and actual_tool != expected_tool:
        return False

    if expected_file and actual_file != expected_file:
        return False

    if expected_operation and expected_operation not in actual_operation:
        return False

    if expected_afb is not None and actual_afb != expected_afb:
        return False

    return True


def validate_expected_cees(system_dir: Path, report: dict, manifest: dict[str, Any]) -> tuple[bool, str]:
    cees = report.get("cees", [])
    expected_cees = manifest.get("expected_cees", [])
    expected_cee_min = manifest.get("expected_cee_min")

    missing = []
    for expected in expected_cees:
        if not any(cee_matches(system_dir, actual, expected) for actual in cees):
            missing.append(f"{expected.get('tool_registration')}->{expected.get('operation')}")

    if missing:
        return False, f"Missing required CEEs: {', '.join(missing[:5])}"

    if expected_cee_min is not None and len(cees) < expected_cee_min:
        return False, f"Expected at least {expected_cee_min} CEEs but saw {len(cees)}"

    if expected_cees or expected_cee_min is not None:
        return True, f"CEE validation passed with {len(cees)} inventoried events"

    return True, ""


def classify_result(system_dir: Path, exit_code: int, report: dict, expected_count: int | None, languages: list[str], code_files: int, manifest: dict[str, Any] | None) -> BenchmarkResult:
    language_label = ", ".join(languages) if languages else "unknown"
    coverage = report["coverage"]
    findings = len(report["findings"])
    cees = report.get("cees", [])
    failed_files = len(coverage["failed_files"])
    partial = bool(coverage["partial"])
    cee_ok, cee_note = validate_expected_cees(system_dir, report, manifest or {})

    if expected_count is not None and languages == ["python"] and code_files > 0:
        status = "PASS" if findings == expected_count and failed_files == 0 and not partial and cee_ok else "FAIL"
        notes = f"Python manifest count matched exactly. {cee_note or f'{len(cees)} CEEs were inventoried.'}" if status == "PASS" else (cee_note if not cee_ok else "Python manifest count or coverage did not match.")
        return BenchmarkResult(
            name=system_dir.name,
            languages=language_label,
            expected_result=f"Exact match with {expected_count} expected Python findings" + (" plus CEE validation" if (manifest or {}).get("expected_cees") or (manifest or {}).get("expected_cee_min") is not None else ""),
            actual_result=actual_result_text(exit_code, report),
            status=status,
            notes=notes,
        )

    if expected_count is None and code_files > 0:
        status = "PASS" if failed_files == 0 and findings > 0 and cee_ok else "FAIL"
        notes = cee_note if cee_note else (f"Operational smoke run only; no manifest is available in this snapshot. {len(cees)} CEEs were inventoried." if status == "PASS" else "Smoke run did not produce a usable Python result.")
        return BenchmarkResult(
            name=system_dir.name,
            languages=language_label,
            expected_result="Operational Python scan with no failed files" + (" plus CEE validation" if (manifest or {}).get("expected_cees") or (manifest or {}).get("expected_cee_min") is not None else ""),
            actual_result=actual_result_text(exit_code, report),
            status=status,
            notes=notes,
        )

    if code_files == 0:
        status = "NOT VALIDATED" if findings == 0 and failed_files == 0 else "FAIL"
        notes = "This repo snapshot contains no analyzable source files for this fixture. The result is informational only and does not validate skipped-language handling." if status == "NOT VALIDATED" else "Missing-code fixture produced an unexpected result."
        return BenchmarkResult(
            name=system_dir.name,
            languages=language_label,
            expected_result="No analyzable source files in current snapshot",
            actual_result=actual_result_text(exit_code, report),
            status=status,
            notes=notes,
        )

    status = "PASS" if failed_files == 0 else "FAIL"
    notes = "Observed current scanner behavior on this fixture." if status == "PASS" else "Scan completed with failed files."
    return BenchmarkResult(
        name=system_dir.name,
        languages=language_label,
        expected_result="Observed current scanner behavior",
        actual_result=actual_result_text(exit_code, report),
        status=status,
        notes=notes,
    )


def write_report(results: list[BenchmarkResult]) -> None:
    python_exact_cases = [result for result in results if result.expected_result.startswith("Exact match")]
    passed_python_exact = sum(1 for result in python_exact_cases if result.status == "PASS")
    asset_limited = [result for result in results if "No analyzable source files" in result.expected_result]
    cee_validated = [result for result in results if "CEE validation" in result.expected_result]

    lines: list[str] = []
    lines.append("# WyScan Benchmark Results")
    lines.append("")
    lines.append(f"**Run Date:** {date.today().isoformat()}")
    lines.append(f"**Benchmarks Evaluated:** {len(results)}")
    lines.append(f"**Python Exact-Match Cases:** {passed_python_exact}/{len(python_exact_cases)} passed")
    lines.append(f"**Python CEE-Validated Cases:** {sum(1 for result in cee_validated if result.status == 'PASS')}/{len(cee_validated)} passed")
    lines.append(f"**Asset-Limited Cases:** {len(asset_limited)}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| System | Languages | Expected result | Actual result | Status | Notes |")
    lines.append("|--------|-----------|-----------------|---------------|--------|-------|")

    for result in results:
        lines.append(
            f"| {result.name} | {result.languages} | {result.expected_result} | {result.actual_result} | {result.status} | {result.notes} |"
        )

    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append("- PASS on an exact-match Python case means the current scanner found the same number of findings as the benchmark manifest and reported no failed files.")
    lines.append("- PASS on a CEE-validated Python case means the current scanner also satisfied the manifest's required CEE identities or minimum CEE coverage.")
    lines.append("- NOT VALIDATED on an asset-limited case means the repository snapshot contained no analyzable source files. The result is informational only and does not validate language support or skipped-language handling.")
    lines.append("- These results validate the scanner. Rust finding support is not yet implemented.")

    RESULTS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    if not CLI_PATH.exists():
        raise SystemExit(f"Built CLI not found: {CLI_PATH}")

    results: list[BenchmarkResult] = []
    for system_dir in benchmark_directories():
        manifest = load_manifest_data(system_dir)
        expected_count, languages = load_manifest(system_dir)
        code_files = count_code_files(system_dir)
        exit_code, report = run_scan(system_dir)
        results.append(classify_result(system_dir, exit_code, report, expected_count, languages, code_files, manifest))

    write_report(results)
    print(f"Wrote {RESULTS_PATH}")


if __name__ == "__main__":
    main()
