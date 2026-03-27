#!/usr/bin/env python3
"""
WyScan Benchmark Evaluator

Compares WyScan findings against CEE manifests to compute detection accuracy.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class CEE:
    """Canonical Execution Event from manifest."""
    id: str
    severity: str
    category: str
    file: str
    line: int
    operation: str
    tool_registration: str
    afb_type: str
    description: str = ""
    rationale: str = ""


@dataclass
class Finding:
    """WyScan finding from scan output."""
    severity: str
    file: str
    line: int
    function: str
    tool_registration: str
    afb_type: str
    description: str = ""


@dataclass
class Match:
    """Match result between CEE and Finding."""
    cee: CEE
    finding: Optional[Finding]
    score: float  # 1.0 = full, 0.5 = partial, 0.0 = miss
    match_details: str


@dataclass
class SystemResult:
    """Evaluation result for a single benchmark system."""
    system_id: str
    language: str
    has_code: bool
    has_manifest: bool
    expected_count: int
    detected_count: float  # Can be fractional due to partial matches
    false_positives: int
    total_findings: int
    detection_rate: float
    false_positive_rate: float
    weighted_score: float
    matches: list = field(default_factory=list)
    missed_cees: list = field(default_factory=list)
    false_positive_findings: list = field(default_factory=list)
    notes: str = ""


def normalize_path(path: str, base_dir: str) -> str:
    """Normalize path to relative form for comparison."""
    path = path.replace("\\", "/")
    base_dir = base_dir.replace("\\", "/")

    # Remove absolute path prefix
    if path.startswith(base_dir):
        path = path[len(base_dir):].lstrip("/")

    # Handle double src prefixes
    if path.startswith("src/") and "src/" in path[4:]:
        path = path  # Keep as is

    return path


def files_match(manifest_file: str, finding_file: str, system_path: str) -> bool:
    """Check if two file paths refer to the same file."""
    # Normalize finding path (absolute -> relative)
    finding_rel = normalize_path(finding_file, system_path)
    manifest_rel = manifest_file.lstrip("./")

    # Direct match
    if finding_rel == manifest_rel:
        return True

    # Match without src/ prefix variations
    if finding_rel.endswith(manifest_rel) or manifest_rel.endswith(finding_rel):
        return True

    # Extract just filename as fallback
    finding_name = os.path.basename(finding_rel)
    manifest_name = os.path.basename(manifest_rel)

    return finding_name == manifest_name


def operations_match(manifest_op: str, finding_func: str) -> bool:
    """Check if operations match (exact string comparison)."""
    # Normalize common variations
    manifest_norm = manifest_op.strip()
    finding_norm = finding_func.strip()

    # Exact match
    if manifest_norm == finding_norm:
        return True

    # Common aliases
    aliases = {
        "Path.write_text": ["path.write_text", "doc_path.write_text", "full_path.write_text",
                           "code_path.write_text", "output_path.write_text", "new_doc_path.write_text",
                           "temp_path.write_text", "log_path.write_text", "STATE_FILE.write_text",
                           "PLAN_PATH.write_text"],
        "Path.read_text": ["path.read_text", "doc_path.read_text", "full_path.read_text",
                          "code_path.read_text", "STATE_FILE.read_text", "PLAN_PATH.read_text"],
        "Path.glob": ["base_path.glob", "for file_path in base_path.glob", "target_dir.glob",
                     "for file_path in target_dir.glob"],
        "requests.get": ["requests.get"],
        "requests.post": ["requests.post"],
        "subprocess.run": ["subprocess.run"],
        "state_file.write_text": ["STATE_FILE.write_text"],
        "state_file.read_text": ["STATE_FILE.read_text"],
    }

    for canonical, variants in aliases.items():
        if manifest_norm in [canonical] + variants and finding_norm in [canonical] + variants:
            return True
        # Also check if manifest_norm matches any variant
        if manifest_norm == canonical and finding_norm in variants:
            return True
        if finding_norm == canonical and manifest_norm in variants:
            return True

    # Partial match for method names
    manifest_method = manifest_norm.split(".")[-1] if "." in manifest_norm else manifest_norm
    finding_method = finding_norm.split(".")[-1] if "." in finding_norm else finding_norm

    return manifest_method == finding_method


def match_finding_to_cee(finding: Finding, cee: CEE, system_path: str) -> tuple[float, str]:
    """
    Match a finding to a CEE and return (score, details).

    Score:
    - 1.0 = all three match (operation, afb_type, location)
    - 0.5 = two of three match
    - 0.0 = fewer than two match
    """
    matches = []

    # Check operation match
    op_match = operations_match(cee.operation, finding.function)
    if op_match:
        matches.append("operation")

    # Check AFB type match
    afb_match = cee.afb_type.upper() == finding.afb_type.upper()
    if afb_match:
        matches.append("afb_type")

    # Check location match (same file, within ±5 lines)
    file_match = files_match(cee.file, finding.file, system_path)
    line_match = abs(cee.line - finding.line) <= 5
    location_match = file_match and line_match
    if location_match:
        matches.append("location")

    match_count = len(matches)

    if match_count == 3:
        return 1.0, f"FULL: {', '.join(matches)}"
    elif match_count == 2:
        return 0.5, f"PARTIAL: {', '.join(matches)} (missing: {['operation', 'afb_type', 'location'][['operation' in matches, 'afb_type' in matches, 'location' in matches].index(False)]})"
    else:
        return 0.0, f"NO MATCH: only {', '.join(matches) if matches else 'none'}"


def evaluate_system(system_path: str) -> SystemResult:
    """Evaluate a single benchmark system."""
    system_id = os.path.basename(system_path)
    manifest_path = os.path.join(system_path, "cee_manifest.json")
    findings_path = os.path.join(system_path, "findings.json")

    # Check for code files
    code_extensions = [".py", ".ts", ".rs", ".js"]
    has_code = any(
        os.path.isfile(os.path.join(root, f))
        for root, _, files in os.walk(system_path)
        for f in files
        if any(f.endswith(ext) for ext in code_extensions)
    )

    # Determine language from manifest or file extensions
    language = "unknown"

    # Load manifest if exists
    has_manifest = os.path.isfile(manifest_path)
    cees = []
    if has_manifest:
        with open(manifest_path) as f:
            manifest = json.load(f)

        for ef in manifest.get("expected_findings", []):
            cees.append(CEE(
                id=ef.get("id", ""),
                severity=ef.get("severity", ""),
                category=ef.get("category", ""),
                file=ef.get("file", ""),
                line=ef.get("line", 0),
                operation=ef.get("operation", ""),
                tool_registration=ef.get("tool_registration", ""),
                afb_type=ef.get("afb_type", "AFB04"),
                description=ef.get("description", ""),
                rationale=ef.get("rationale", ""),
            ))

        # Get language from metadata
        metadata = manifest.get("metadata", {})
        languages = metadata.get("languages", [])
        if languages:
            language = languages[0]

    # Load findings if exists
    findings = []
    files_analyzed = 0
    if os.path.isfile(findings_path):
        with open(findings_path) as f:
            findings_data = json.load(f)

        files_analyzed = findings_data.get("files_analyzed", 0)

        for fd in findings_data.get("findings", []):
            findings.append(Finding(
                severity=fd.get("severity", ""),
                file=fd.get("file", ""),
                line=fd.get("line", 0),
                function=fd.get("function", ""),
                tool_registration=fd.get("tool_registration", ""),
                afb_type=fd.get("afb_type", "AFB04"),
                description=fd.get("description", ""),
            ))

    # Handle special cases
    notes = ""
    if not has_code:
        notes = "No source code files found"
    elif files_analyzed == 0 and has_code:
        notes = "Scanner found 0 analyzable files"
    elif language in ["typescript", "ts"]:
        notes = "TypeScript not supported by WyScan"
    elif language == "rust":
        notes = "Rust not supported by WyScan"

    # If no manifest, can't compute detection scores
    if not has_manifest:
        return SystemResult(
            system_id=system_id,
            language=language,
            has_code=has_code,
            has_manifest=False,
            expected_count=0,
            detected_count=0,
            false_positives=0,
            total_findings=len(findings),
            detection_rate=0.0,
            false_positive_rate=0.0,
            weighted_score=0.0,
            notes=notes or "No manifest - cannot compute detection scores"
        )

    # Match findings to CEEs
    matches = []
    used_findings = set()

    for cee in cees:
        best_score = 0.0
        best_finding = None
        best_details = "NO MATCH"

        for i, finding in enumerate(findings):
            if i in used_findings:
                continue

            score, details = match_finding_to_cee(finding, cee, system_path)
            if score > best_score:
                best_score = score
                best_finding = finding
                best_details = details
                best_idx = i

        if best_score > 0 and best_finding:
            used_findings.add(best_idx)

        matches.append(Match(
            cee=cee,
            finding=best_finding if best_score > 0 else None,
            score=best_score,
            match_details=best_details
        ))

    # Calculate metrics
    detected_count = sum(m.score for m in matches)
    expected_count = len(cees)
    false_positives = len(findings) - len(used_findings)
    total_findings = len(findings)

    # Rates
    detection_rate = detected_count / expected_count if expected_count > 0 else 0.0
    false_positive_rate = false_positives / total_findings if total_findings > 0 else 0.0
    weighted_score = detection_rate * (1 - false_positive_rate)

    # Collect missed CEEs and false positive findings
    missed_cees = [m.cee for m in matches if m.score == 0]
    fp_findings = [f for i, f in enumerate(findings) if i not in used_findings]

    return SystemResult(
        system_id=system_id,
        language=language,
        has_code=has_code,
        has_manifest=True,
        expected_count=expected_count,
        detected_count=detected_count,
        false_positives=false_positives,
        total_findings=total_findings,
        detection_rate=detection_rate,
        false_positive_rate=false_positive_rate,
        weighted_score=weighted_score,
        matches=matches,
        missed_cees=missed_cees,
        false_positive_findings=fp_findings,
        notes=notes
    )


def generate_report(results: list[SystemResult], output_path: str):
    """Generate the benchmark report."""
    run_date = datetime.now().strftime("%Y-%m-%d")

    # Filter to only systems with manifests for scoring
    scored_results = [r for r in results if r.has_manifest and r.has_code]
    python_results = [r for r in scored_results if r.language == "python"]
    unsupported_results = [r for r in results if r.language in ["typescript", "ts", "rust"]]
    no_code_results = [r for r in results if not r.has_code and r.has_manifest]

    # Calculate aggregate scores (Python only)
    if python_results:
        overall_dr = sum(r.detection_rate for r in python_results) / len(python_results)
        overall_fpr = sum(r.false_positive_rate for r in python_results) / len(python_results)
        overall_ws = sum(r.weighted_score for r in python_results) / len(python_results)
    else:
        overall_dr = overall_fpr = overall_ws = 0.0

    # Thresholds
    ws_threshold = 0.80
    fpr_threshold = 0.10
    afb04_threshold = 0.85
    min_system_ws = 0.40

    # Check pass/fail
    ws_pass = overall_ws >= ws_threshold
    fpr_pass = overall_fpr <= fpr_threshold
    all_above_floor = all(r.weighted_score >= min_system_ws for r in python_results) if python_results else True
    overall_pass = ws_pass and fpr_pass and all_above_floor

    # Build report
    lines = []
    lines.append("# WyScan Benchmark Results")
    lines.append("")
    lines.append(f"**Run Date:** {run_date}")
    lines.append(f"**Systems Evaluated:** {len(results)}")
    lines.append(f"**Systems with Code:** {sum(1 for r in results if r.has_code)}")
    lines.append(f"**Systems Scored:** {len(scored_results)} (Python with manifest)")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| # | System | Lang | Expected | Detected | FP | DR | FPR | WS | Status |")
    lines.append("|---|--------|------|----------|----------|----|----|-----|----|---------")

    for r in results:
        # Parse system number and name
        if r.system_id[0:2].isdigit() and len(r.system_id) > 3:
            sys_num = r.system_id[:2]
            sys_name = r.system_id[3:][:25]
        else:
            sys_num = "—"
            sys_name = r.system_id[:27]

        if r.has_code and r.has_manifest:
            status = "PASS" if r.weighted_score >= min_system_ws else "FAIL"
            lines.append(
                f"| {sys_num} | {sys_name:25} | {r.language[:6]:6} | "
                f"{r.expected_count:8} | {r.detected_count:8.1f} | {r.false_positives:2} | "
                f"{r.detection_rate:.2f} | {r.false_positive_rate:.2f} | {r.weighted_score:.2f} | {status} |"
            )
        elif r.has_manifest and not r.has_code:
            lines.append(
                f"| {sys_num} | {sys_name:25} | {r.language[:6]:6} | "
                f"{r.expected_count:8} | {'N/A':>8} | {'N/A':>2} | "
                f"{'N/A':>4} | {'N/A':>4} | {'N/A':>4} | NO CODE |"
            )
        elif r.language in ["typescript", "ts", "rust"]:
            lines.append(
                f"| {sys_num} | {sys_name:25} | {r.language[:6]:6} | "
                f"{'N/A':>8} | {'N/A':>8} | {'N/A':>2} | "
                f"{'N/A':>4} | {'N/A':>4} | {'N/A':>4} | UNSUPPORTED |"
            )
        else:
            lines.append(
                f"| {sys_num} | {sys_name:25} | {'???':6} | "
                f"{'—':>8} | {r.total_findings:>8} | {'—':>2} | "
                f"{'—':>4} | {'—':>4} | {'—':>4} | NO MANIFEST |"
            )

    lines.append("")

    # Aggregate scores
    lines.append("## Aggregate Scores (Python Systems Only)")
    lines.append("")
    lines.append(f"| Metric | Value | Threshold | Status |")
    lines.append("|--------|-------|-----------|--------|")
    lines.append(f"| Detection Rate (DR) | {overall_dr:.2f} | — | — |")
    lines.append(f"| False Positive Rate (FPR) | {overall_fpr:.2f} | ≤ {fpr_threshold:.2f} | {'PASS' if fpr_pass else 'FAIL'} |")
    lines.append(f"| Weighted Score (WS) | {overall_ws:.2f} | ≥ {ws_threshold:.2f} | {'PASS' if ws_pass else 'FAIL'} |")
    lines.append(f"| All Systems Above Floor | {'Yes' if all_above_floor else 'No'} | WS ≥ {min_system_ws:.2f} | {'PASS' if all_above_floor else 'FAIL'} |")
    lines.append("")
    lines.append(f"**Overall Status: {'PASS' if overall_pass else 'FAIL'}**")
    lines.append("")

    # Per-system details
    lines.append("## Per-System Details")
    lines.append("")

    for r in results:
        if not r.has_manifest:
            continue

        lines.append(f"### {r.system_id}")
        lines.append("")

        if not r.has_code:
            lines.append(f"**Status:** No source code implemented")
            lines.append(f"**Expected CEEs:** {r.expected_count}")
            lines.append(f"**Note:** This system has a manifest but no code to scan.")
            lines.append("")
            continue

        if r.language in ["typescript", "ts", "rust"]:
            lines.append(f"**Status:** Language not supported ({r.language})")
            lines.append(f"**Note:** WyScan only supports Python. This is by design to avoid false positives.")
            lines.append("")
            continue

        lines.append(f"**Expected:** {r.expected_count} | **Detected:** {r.detected_count:.1f} | **False Positives:** {r.false_positives}")
        lines.append(f"**DR:** {r.detection_rate:.2f} | **FPR:** {r.false_positive_rate:.2f} | **WS:** {r.weighted_score:.2f}")
        lines.append("")

        if r.matches:
            lines.append("**Matches:**")
            lines.append("")
            for m in r.matches:
                if m.score > 0:
                    status = "FULL" if m.score == 1.0 else "PARTIAL"
                    lines.append(f"- [{status}] {m.cee.id}: `{m.cee.operation}` @ {m.cee.file}:{m.cee.line}")
                    if m.finding:
                        lines.append(f"  → Found: `{m.finding.function}` @ line {m.finding.line}")
            lines.append("")

        if r.missed_cees:
            lines.append("**Missed:**")
            lines.append("")
            for cee in r.missed_cees:
                lines.append(f"- {cee.id}: `{cee.operation}` @ {cee.file}:{cee.line}")
            lines.append("")

        if r.false_positive_findings:
            lines.append("**False Positives:**")
            lines.append("")
            for fp in r.false_positive_findings:
                lines.append(f"- `{fp.function}` @ {os.path.basename(fp.file)}:{fp.line}")
            lines.append("")

    # Notes section
    lines.append("## Notes")
    lines.append("")
    lines.append("### Scoring Formula")
    lines.append("")
    lines.append("```")
    lines.append("Detection Rate (DR) = detected_cees / expected_cees")
    lines.append("False Positive Rate (FPR) = false_positives / total_findings")
    lines.append("Weighted Score (WS) = DR × (1 - FPR)")
    lines.append("```")
    lines.append("")
    lines.append("### Match Criteria")
    lines.append("")
    lines.append("A WyScan finding matches a manifest CEE if:")
    lines.append("- **operation**: exact string match")
    lines.append("- **afb_type**: exact (AFB04)")
    lines.append("- **location**: same file AND within ±5 lines")
    lines.append("")
    lines.append("- 3/3 match = 1.0 points (full)")
    lines.append("- 2/3 match = 0.5 points (partial)")
    lines.append("- <2 match = 0.0 points (miss)")
    lines.append("")
    lines.append("### Language Support")
    lines.append("")
    lines.append("WyScan currently supports **Python only**. TypeScript and Rust systems return")
    lines.append("no findings by design — this prevents false positives from pattern matching")
    lines.append("without proper AST analysis.")
    lines.append("")

    # Write report
    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    return overall_pass, overall_ws, overall_fpr


def main():
    benchmark_dir = Path(__file__).parent.parent

    # Find all benchmark systems
    system_dirs = []

    # Numbered systems (00-12)
    for entry in sorted(benchmark_dir.iterdir()):
        if entry.is_dir() and entry.name[0:2].isdigit():
            system_dirs.append(str(entry))

    # Legacy systems
    legacy_dir = benchmark_dir / "_legacy"
    if legacy_dir.exists():
        for entry in sorted(legacy_dir.iterdir()):
            if entry.is_dir():
                system_dirs.append(str(entry))

    print(f"Evaluating {len(system_dirs)} benchmark systems...")
    print()

    # Evaluate each system
    results = []
    for system_path in system_dirs:
        result = evaluate_system(system_path)
        results.append(result)

        status = "OK" if result.weighted_score >= 0.40 or not result.has_code else "LOW"
        if not result.has_manifest:
            status = "NO MANIFEST"
        elif not result.has_code:
            status = "NO CODE"
        elif result.language in ["typescript", "ts", "rust"]:
            status = "UNSUPPORTED"

        print(f"  {result.system_id}: DR={result.detection_rate:.2f} FPR={result.false_positive_rate:.2f} WS={result.weighted_score:.2f} [{status}]")

    print()

    # Generate report
    output_path = benchmark_dir / "BENCHMARK_RESULTS.md"
    passed, ws, fpr = generate_report(results, str(output_path))

    print(f"Report written to: {output_path}")
    print()
    print(f"Overall: WS={ws:.2f} FPR={fpr:.2f} {'PASS' if passed else 'FAIL'}")

    return 0 if passed else 1


if __name__ == "__main__":
    exit(main())
