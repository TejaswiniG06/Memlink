# MemLink

MemLink is a forensic analysis pipeline for detecting suspicious discrepancies across volatile-memory and disk evidence using public NIST CFReDS forensic images.

The current implementation automates memory-image processing with Volatility 3 and verifies suspicious `PAGE_EXECUTE_READWRITE` (RWX) memory regions against process and file evidence.

## Workflow

1. Extract process, command-line, module, handle and file-object evidence.
2. Identify processes containing RWX memory regions.
3. Resolve each PID using `pslist`.
4. Compare PID-owned handles with executable objects recovered through `filescan`.
5. Generate verification, discrepancy and summary reports.

> `filescan` does not contain PID information. It provides independent file-object evidence but cannot directly prove process ownership.

## Current Results

| Memory image | Malfind rows | RWX regions | RWX PIDs | Candidate discrepancies |
|---|---:|---:|---:|---:|
| `xp-laptop-2005-06-25` | 20 | 7 | 3 | 0 |
| `xp-laptop-2005-07-04` | 17 | 8 | 3 | 0 |

The RWX processes were `csrss.exe`, `svchost.exe` and `explorer.exe` in both images. Corresponding executable objects were present in `filescan`, so no missing-file-object discrepancy was detected under the current rule.

RWX memory is an investigation indicator and does not independently prove malicious activity.

## Usage

Place the CFReDS images inside `memory-images/`, then run:

```bat
run_all_memory_images.bat
py memlink_discrepancy_check.py
```

Memory images are excluded from this repository because of their size.

## Planned Work

- Add stronger discrepancy rules using process, module and parent-child evidence.
- Normalize memory and disk artifacts into a shared schema.
- Automate memory-disk correlation.
- Produce explainable risk scores and ranked forensic alerts.

## Disclaimer

This project is intended only for authorized forensic investigation, cybersecurity education and research.
