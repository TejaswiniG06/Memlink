#!/usr/bin/env python3
"""MemLink preliminary RWX/file-evidence discrepancy checker.

This script analyses Volatility CSV outputs case-by-case. It does not claim
that filescan contains PID ownership. PID-linked evidence comes from handles;
filescan is used only as independent filename/path evidence.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


REQUIRED_FILES = ("malfind.csv", "pslist.csv", "handles.csv", "filescan.csv")
RWX = "PAGE_EXECUTE_READWRITE"


def norm_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def clean(value: object) -> str:
    return "" if value is None else str(value).strip()


def clean_pid(value: object) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        fields = [clean(x) for x in (reader.fieldnames or [])]
        rows = [{clean(k): clean(v) for k, v in row.items() if k is not None} for row in reader]
    if not fields:
        raise ValueError(f"No CSV header found in {path}")
    return rows, fields


def find_column(fields: list[str], *candidates: str, required: bool = True) -> str | None:
    lookup = {norm_header(field): field for field in fields}
    for candidate in candidates:
        match = lookup.get(norm_header(candidate))
        if match:
            return match
    if required:
        raise ValueError(
            f"Required column not found. Tried {candidates}; available columns: {fields}"
        )
    return None


def basename_windows(value: str) -> str:
    text = clean(value).replace("/", "\\").rstrip("\\").lower()
    return text.rsplit("\\", 1)[-1]


def path_mentions_process(path_value: str, process_name: str) -> bool:
    process = basename_windows(process_name)
    if not process:
        return False
    return basename_windows(path_value) == process


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def analyse_case(case_dir: Path) -> dict[str, object]:
    missing = [name for name in REQUIRED_FILES if not (case_dir / name).is_file()]
    if missing:
        return {
            "case": case_dir.name,
            "status": "skipped_missing_files",
            "missing_files": missing,
        }

    malfind, mf_fields = read_csv(case_dir / "malfind.csv")
    pslist, ps_fields = read_csv(case_dir / "pslist.csv")
    handles, h_fields = read_csv(case_dir / "handles.csv")
    filescan, fs_fields = read_csv(case_dir / "filescan.csv")

    mf_pid = find_column(mf_fields, "PID")
    mf_process = find_column(mf_fields, "Process", "ImageFileName", required=False)
    mf_protection = find_column(mf_fields, "Protection")

    ps_pid = find_column(ps_fields, "PID")
    ps_process = find_column(ps_fields, "ImageFileName", "Process")

    h_pid = find_column(h_fields, "PID")
    h_type = find_column(h_fields, "Type", "ObjectType")
    h_name = find_column(h_fields, "Name", "ObjectName")

    fs_name = find_column(fs_fields, "Name", "FileName", "Path")

    ps_by_pid: dict[str, str] = {}
    for row in pslist:
        pid = clean_pid(row.get(ps_pid))
        if pid:
            ps_by_pid[pid] = clean(row.get(ps_process))

    file_handles_by_pid: dict[str, list[str]] = defaultdict(list)
    for row in handles:
        pid = clean_pid(row.get(h_pid))
        object_type = clean(row.get(h_type)).lower()
        if pid and object_type == "file":
            file_handles_by_pid[pid].append(clean(row.get(h_name)))

    filescan_names = [clean(row.get(fs_name)) for row in filescan if clean(row.get(fs_name))]

    rwx_counts: Counter[str] = Counter()
    malfind_process: dict[str, str] = {}
    for row in malfind:
        pid = clean_pid(row.get(mf_pid))
        protection = clean(row.get(mf_protection)).upper()
        if pid and protection == RWX:
            rwx_counts[pid] += 1
            if mf_process:
                malfind_process[pid] = clean(row.get(mf_process))

    verification: list[dict[str, object]] = []
    discrepancies: list[dict[str, object]] = []

    for pid in sorted(rwx_counts, key=lambda x: int(x) if x.isdigit() else x):
        process = ps_by_pid.get(pid) or malfind_process.get(pid, "")
        pslist_match = pid in ps_by_pid
        pid_file_handles = file_handles_by_pid.get(pid, [])
        matching_handle_paths = [
            path for path in pid_file_handles if path_mentions_process(path, process)
        ]
        matching_filescan_paths = [
            path for path in filescan_names if path_mentions_process(path, process)
        ]

        if not process:
            classification = "UNRESOLVED_PROCESS_NAME"
            discrepancy = False
            explanation = "RWX PID found, but its process name could not be resolved."
        elif matching_handle_paths or matching_filescan_paths:
            classification = "CORROBORATED_FILE_EVIDENCE"
            discrepancy = False
            explanation = (
                "RWX region present, but corresponding executable evidence was found "
                "in handles and/or filescan."
            )
        else:
            classification = "CANDIDATE_DISCREPANCY"
            discrepancy = True
            explanation = (
                "RWX region present with no matching executable handle for the PID "
                "and no matching executable file object in filescan."
            )

        record: dict[str, object] = {
            "case": case_dir.name,
            "pid": pid,
            "process": process,
            "rwx_region_count": rwx_counts[pid],
            "pslist_pid_match": pslist_match,
            "pid_file_handle_count": len(pid_file_handles),
            "matching_executable_handle_found": bool(matching_handle_paths),
            "matching_handle_paths": " | ".join(matching_handle_paths[:10]),
            "matching_filescan_object_found": bool(matching_filescan_paths),
            "matching_filescan_paths": " | ".join(matching_filescan_paths[:10]),
            "classification": classification,
            "qualifying_discrepancy": discrepancy,
            "explanation": explanation,
        }
        verification.append(record)
        if discrepancy:
            discrepancies.append(record)

    fields = [
        "case",
        "pid",
        "process",
        "rwx_region_count",
        "pslist_pid_match",
        "pid_file_handle_count",
        "matching_executable_handle_found",
        "matching_handle_paths",
        "matching_filescan_object_found",
        "matching_filescan_paths",
        "classification",
        "qualifying_discrepancy",
        "explanation",
    ]
    write_csv(case_dir / "memlink_rwx_verification.csv", verification, fields)
    write_csv(case_dir / "memlink_discrepancies.csv", discrepancies, fields)

    summary: dict[str, object] = {
        "case": case_dir.name,
        "status": "analysed",
        "malfind_rows": len(malfind),
        "malfind_unique_pids": len({clean_pid(r.get(mf_pid)) for r in malfind if clean_pid(r.get(mf_pid))}),
        "rwx_regions": sum(rwx_counts.values()),
        "rwx_unique_pids": len(rwx_counts),
        "candidate_discrepancies": len(discrepancies),
        "method_note": (
            "PID ownership is derived from handles.csv. filescan.csv is used only "
            "as independent filename/path evidence because filescan has no PID field."
        ),
    }
    with (case_dir / "memlink_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyse Volatility case folders for preliminary MemLink RWX discrepancies."
    )
    parser.add_argument(
        "--outputs",
        type=Path,
        default=Path(r"D:\cfreds team b\outputs"),
        help="Root directory containing one subfolder per memory-image case.",
    )
    args = parser.parse_args()
    output_root: Path = args.outputs

    if not output_root.is_dir():
        print(f"ERROR: Output directory not found: {output_root}", file=sys.stderr)
        return 1

    case_dirs = sorted(path for path in output_root.iterdir() if path.is_dir())
    results: list[dict[str, object]] = []

    for case_dir in case_dirs:
        try:
            result = analyse_case(case_dir)
        except Exception as exc:  # keep other cases running and preserve the reason
            result = {"case": case_dir.name, "status": "error", "error": str(exc)}
        results.append(result)

    aggregate_fields = [
        "case",
        "status",
        "malfind_rows",
        "malfind_unique_pids",
        "rwx_regions",
        "rwx_unique_pids",
        "candidate_discrepancies",
        "missing_files",
        "error",
    ]
    aggregate_rows: list[dict[str, object]] = []
    for result in results:
        row = dict(result)
        if isinstance(row.get("missing_files"), list):
            row["missing_files"] = " | ".join(row["missing_files"])
        aggregate_rows.append(row)
    write_csv(output_root / "memlink_all_cases_summary.csv", aggregate_rows, aggregate_fields)

    print("\nMemLink discrepancy analysis")
    print("=" * 70)
    for result in results:
        case = result.get("case", "unknown")
        status = result.get("status")
        if status == "analysed":
            print(
                f"{case}: malfind={result['malfind_rows']}, "
                f"RWX regions={result['rwx_regions']}, "
                f"RWX PIDs={result['rwx_unique_pids']}, "
                f"candidate discrepancies={result['candidate_discrepancies']}"
            )
        elif status == "skipped_missing_files":
            print(f"{case}: SKIPPED (missing {', '.join(result['missing_files'])})")
        else:
            print(f"{case}: ERROR ({result.get('error', 'unknown error')})")
    print("=" * 70)
    print(f"Aggregate summary: {output_root / 'memlink_all_cases_summary.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
