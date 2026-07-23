#!/usr/bin/env python3

from __future__ import annotations

import argparse, csv, json, shutil, subprocess, sys
from pathlib import Path
from typing import Any

# Snyk exit codes: 0 = no vulns, 1 = vulns found, 2 = try again, 3 = no supported project detected.
SNYK_OK_EXIT_CODES = {0, 1}
SCAN_TIMEOUT_SECONDS = 300
CSV_COLUMNS = ["package_name", "package_version", "vulnerability_type", "remediation_steps"]

# Validates that the target directory exists and contains a package.json
def resolve_scan_dir(raw_path: str) -> Path:
    scan_dir = Path(raw_path).expanduser().resolve()
    if not scan_dir.is_dir():
        raise NotADirectoryError(f"Scan path does not exist or is not a directory: {scan_dir}")
    if not (scan_dir / "package.json").is_file():
        raise FileNotFoundError(f"No package.json found in: {scan_dir}")
    return scan_dir

# Locates the snyk executable on PATH without invoking a shell.
def ensure_snyk_available() -> str:
    snyk_path = shutil.which("snyk")
    if not snyk_path:
        raise EnvironmentError(
            "Snyk CLI not found on PATH. Install it first, e.g.:\n"
            "  npm install -g snyk\n"
            "and authenticate with:\n"
            "  snyk auth"
        )
    return snyk_path

# Runs the Snyk CLI (`snyk test --json`) and returns the parsed JSON output.
def run_snyk_test(snyk_path: str, scan_dir: Path) -> dict:
    cmd = [snyk_path, "test", "--json"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(scan_dir),
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"Snyk scan timed out after {SCAN_TIMEOUT_SECONDS}s") from exc

    if proc.returncode not in SNYK_OK_EXIT_CODES:
        # Exit codes 2/3 (or anything unexpected) indicate the scan itself failed.
        stderr_snippet = (proc.stderr or "").strip()[:500]
        raise RuntimeError(f"snyk test failed (exit code {proc.returncode}). {stderr_snippet}"
        )

    stdout = (proc.stdout or "").strip()
    if not stdout:
        raise RuntimeError("snyk test returned no output to parse.")

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Failed to parse Snyk JSON output.") from exc

# Normalizes Snyk's JSON structure into flat rows for the CSV.
# Snyk may return either a single project object or a list of project objects (multi-project scans).
def extract_findings(scan_result: dict | list) -> list[dict[str, str]]:
    projects = scan_result if isinstance(scan_result, list) else [scan_result]
    rows: list[dict[str, str]] = []

    for project in projects:
        if not isinstance(project, dict):
            continue
        vulnerabilities = project.get("vulnerabilities") or []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            package_name = vuln.get("packageName") or vuln.get("name") or "unknown"
            package_version = vuln.get("version") or "unknown"

            vuln_types = vuln.get("identifiers", {}).get("CWE") if isinstance(
                vuln.get("identifiers"), dict
            ) else None
            vulnerability_type = (
                vuln.get("title")
                or (", ".join(vuln_types) if vuln_types else None)
                or vuln.get("severity")
                or "unknown"
            )

            remediation_steps = build_remediation(vuln)

            rows.append(
                {
                    "package_name": package_name,
                    "package_version": package_version,
                    "vulnerability_type": vulnerability_type,
                    "remediation_steps": remediation_steps,
                }
            )

    return rows


# Composes a human-readable remediation string from Snyk vuln data.
def build_remediation(vuln: dict) -> str:
    is_upgradable = vuln.get("isUpgradable")
    is_patchable = vuln.get("isPatchable")
    upgrade_path = vuln.get("upgradePath") or []
    fixed_in = vuln.get("fixedIn") or []

    if is_upgradable and upgrade_path:
        target = next((p for p in upgrade_path if p), None)
        if target:
            return f"Upgrade to {target}"
        return "Upgrade to the latest patched version"
    if fixed_in:
        return f"Upgrade to a version in: {', '.join(fixed_in)}"
    if is_patchable:
        return "Apply available Snyk patch (run `snyk protect`)"
    return "No direct fix available yet; monitor advisory and consider replacing/pinning the package"


# Writes the extracted findings to a CSV file.
def write_csv(rows: list[dict[str, str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in CSV_COLUMNS})


# Parses the command-line arguments for the script.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Snyk vulnerability scan and export results to CSV.")
    parser.add_argument(
        "--path",
        default=".",
        help="Directory containing package.json to scan (default: current directory).",
    )
    parser.add_argument(
        "--output",
        default="snyk_vulnerabilities.csv",
        help="Path to the output CSV file (default: ./snyk_vulnerabilities.csv).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        scan_dir = resolve_scan_dir(args.path)
        snyk_path = ensure_snyk_available()
        print(f"[*] Scanning {scan_dir} with Snyk...")
        scan_result = run_snyk_test(snyk_path, scan_dir)
        rows = extract_findings(scan_result)
        write_csv(rows, Path(args.output).expanduser().resolve())
        print(f"[+] Scan complete. {len(rows)} vulnerabilities found.")
        print(f"[+] Report written to: {output_path}")
        return 0
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
