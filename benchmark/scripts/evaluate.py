#!/usr/bin/env python3
"""
WyScan benchmark validator for the current Python-first scanner.

This script runs the built CLI against each benchmark directory and writes a
single markdown summary to benchmark/BENCHMARK_RESULTS.md.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import date
from pathlib import Path


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
    expected = len(manifest.get("expected_findings", []))
    languages = manifest.get("metadata", {}).get("languages", [])
    return expected, languages


def count_code_files(system_dir: Path) -> int:
    return sum(1 for path in system_dir.rglob("*") if path.is_file() and path.suffix in CODE_EXTENSIONS)


def run_scan(system_dir: Path) -> tuple[int, dict]:
    process = subprocess.run(
        ["node", str(CLI_PATH), "scan", str(system_dir), "--json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    if not process.stdout.strip():
        raise RuntimeError(f"No JSON output for {system_dir.name}: {process.stderr.strip()}")

    return process.returncode, json.loads(process.stdout)


def actual_result_text(exit_code: int, report: dict) -> str:
    summary = report["summary"]
    coverage = report["coverage"]
    return (
        f"{len(report['findings'])} findings "
        f"({summary['critical']}C/{summary['warning']}W/{summary['info']}I), "
        f"exit {exit_code}, analyzed {coverage['files_analyzed']}, "
        f"skipped {coverage['files_skipped']}, failed {len(coverage['failed_files'])}"
    )


def classify_result(system_dir: Path, exit_code: int, report: dict, expected_count: int | None, languages: list[str], code_files: int) -> BenchmarkResult:
    language_label = ", ".join(languages) if languages else "unknown"
    coverage = report["coverage"]
    findings = len(report["findings"])
    failed_files = len(coverage["failed_files"])
    partial = bool(coverage["partial"])

    if expected_count is not None and languages == ["python"] and code_files > 0:
        status = "PASS" if findings == expected_count and failed_files == 0 and not partial else "FAIL"
        notes = "Python manifest count matched exactly." if status == "PASS" else "Python manifest count or coverage did not match."
        return BenchmarkResult(
            name=system_dir.name,
            languages=language_label,
            expected_result=f"Exact match with {expected_count} expected Python findings",
            actual_result=actual_result_text(exit_code, report),
            status=status,
            notes=notes,
        )

    if expected_count is None and code_files > 0:
        status = "PASS" if failed_files == 0 and findings > 0 else "FAIL"
        notes = "Operational smoke run only; no manifest is available in this snapshot." if status == "PASS" else "Smoke run did not produce a usable Python result."
        return BenchmarkResult(
            name=system_dir.name,
            languages=language_label,
            expected_result="Operational Python scan with no failed files",
            actual_result=actual_result_text(exit_code, report),
            status=status,
            notes=notes,
        )

    if code_files == 0:
        status = "PASS" if findings == 0 and failed_files == 0 else "FAIL"
        notes = "This repo snapshot contains no analyzable source files for this fixture. The result does not validate skipped-language handling." if status == "PASS" else "Missing-code fixture produced an unexpected result."
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

    lines: list[str] = []
    lines.append("# WyScan Benchmark Results")
    lines.append("")
    lines.append(f"**Run Date:** {date.today().isoformat()}")
    lines.append(f"**Benchmarks Evaluated:** {len(results)}")
    lines.append(f"**Python Exact-Match Cases:** {passed_python_exact}/{len(python_exact_cases)} passed")
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
    lines.append("- PASS on an asset-limited case means the repository snapshot contained no analyzable source files and the scanner reported no findings and no failed files.")
    lines.append("- These results validate the current Python-first scanner. They do not claim TypeScript, JavaScript, or Rust finding support.")

    RESULTS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    if not CLI_PATH.exists():
        raise SystemExit(f"Built CLI not found: {CLI_PATH}")

    results: list[BenchmarkResult] = []
    for system_dir in benchmark_directories():
        expected_count, languages = load_manifest(system_dir)
        code_files = count_code_files(system_dir)
        exit_code, report = run_scan(system_dir)
        results.append(classify_result(system_dir, exit_code, report, expected_count, languages, code_files))

    write_report(results)
    print(f"Wrote {RESULTS_PATH}")


if __name__ == "__main__":
    main()
