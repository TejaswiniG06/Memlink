# MemLink

**Memory–Disk Correlation for Attacker TTP Reconstruction**

MemLink is a forensic analysis project developed by Team Forite. It normalizes
memory and disk artifacts, identifies discrepancies and correlates related
evidence to support investigation of attacker behavior.

## Workflow

Evidence → extraction → normalization → assessment → correlation → reporting

## Current implementation

- Configurable Volatility 3 extraction with hashes, logs and run manifests.
- Selected Autopsy filesystem, extracted-artifact and registry-service ingestion.
- Shared artifact schema retaining original fields and source references.
- Initial process and memory-region assessment.
- Hash and normalized-path correlation with explicit strengths and limitations.
- JSON, CSV and HTML outputs for supported stages.

Comprehensive maliciousness assessment, evidence-backed ATT&CK reconstruction and
real-case evaluation remain under development.

## Case study and evaluation

The current case study uses the DC01 host from
[The Stolen Szechuan Sauce](https://dfirmadness.com/the-stolen-szechuan-sauce/),
a community training scenario published by DFIR Madness. Case-study evidence is
not distributed with the new pipeline; obtain it from the publisher.

Evaluation is retrospective because parts of the published solution were reviewed
before rules were frozen. Results are not presented as blind detection results.
Engineering tests and structural validation do not establish detection accuracy.

## Requirements

Tested with Python **3.13.9**, Volatility 3 Framework **2.28.1** and Autopsy
**4.22.1** on Windows. These are tested versions, not minimum requirements.
The Python pipeline uses the standard library. Install Volatility separately
with its own dependencies; disk collection requires compatible Autopsy outputs.

## Configuration and usage

To reproduce the DC01 Phase 1 dashboard from saved evidence exports without the
original drive, follow the [Phase 1 handover](PHASE1_HANDOVER.md). The code is
versioned here; the required input pack is shared privately.

Copy `configs/example.json` to a local configuration and replace all placeholder
paths and identifiers. Paths are interpreted relative to the working directory
unless absolute. Configure only mappings supported by evidence; record memory
and disk snapshots separately.

```powershell
python memlink_pipeline.py configs/local.json
python memlink_assess.py <run-directory> --output <new-assessment-directory>
python memlink_collection.py configs/local.json --runs <run-directory> --database <autopsy.db> --output <new-collection-directory>
python memlink_validate_collection.py <collection-directory>
python memlink_core.py configs/local.json <artifacts.jsonl> --output <new-report-directory>
```

Use each script's `--help` for additional arguments. Preserve originals and use
new output directories for reproducible runs.

## Shared schema

[schemas/artifact.schema.json](schemas/artifact.schema.json) defines artifact
identity, host, source layer/tool, type, path, process identifiers, available
hashes, timestamps, size, allocation state, tamper score, ATT&CK identifiers and
raw source fields. Case, snapshot and source-record references preserve provenance.
Unavailable values remain null.

## Engineering tests

```powershell
python -B -m unittest discover -s tests -v
```

Tests exercise software behavior using constructed examples, including host
isolation, PID reuse, path handling, hash conflicts and missing inputs.

## Interpretation and limitations

- Correlation strength is separate from maliciousness.
- PID alone cannot establish a cross-layer match; basename-only matches are weak.
- Executable memory alone does not prove injection.
- Memory file objects do not prove disk presence or process ownership.
- Missing disk matches require coverage, path-mapping and capture-gap checks.
- Repeated observations are not necessarily independent supporting evidence.
- Detailed event logs, scheduled tasks and separate NTFS timestamp pairs need
  additional extraction before comprehensive reconstruction.

## Repository and evidence handling

The root Python scripts implement extraction, adapters, normalization, collection,
assessment, correlation and reporting. `schemas/` contains the shared schema and
`tests/` contains engineering checks. Legacy CFReDS scripts and previously
committed outputs remain in repository history.

New evidence images, recovered files, case databases, generated investigation
outputs, local configurations and backups are excluded from commits. A sample
configuration is provided without evidence or local machine details.

## Intended use

For authorized forensic investigation, cybersecurity education and research.
