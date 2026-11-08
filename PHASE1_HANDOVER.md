# MemLink Phase 1 handover

DC01, The Stolen Szechuan Sauce. This is a development demonstration on a known case. The rules are not frozen and the draft conclusions are pending team review.

## View the demo

Get `dashboard.html` from your teammate by private transfer and open it in a browser. The standalone dashboard does not need E:, Python, or a server. It contains case excerpts and should stay out of Git.

In **Traces**, show the thread start, executable memory region and YARA hits for `spoolsv.exe`, then the service-install event and disk file for `coreupdater`. The endpoint and timing support investigating both leads; they do not establish process migration. Tier is review priority, not a verdict.

## Rebuild the demo from the saved inputs

Your laptop does not need the original E: drive, original memory and disk images, Volatility, Autopsy, or YARA. It needs Python 3.13 (tested with 3.13.9), the feature-branch code, and the private input ZIP. No extra Python packages are needed for this replay.

1. After the handover changes have been published, clone the feature branch:

   ```powershell
   git clone --branch feature/correlation-engine https://github.com/TejaswiniG06/Memlink.git
   Set-Location Memlink
   ```

2. Get `memlink_phase1_input_pack.zip` and `PACK_MANIFEST.json` from your teammate privately. Extract the ZIP into the clone root so `outputs/`, `backups/`, and `evidence_exports/` are siblings of `memlink_run.py`. Keep the manifest with the bundle. The evidence paths and the manifest are Git-ignored.

3. In PowerShell, from the clone root:

   ```powershell
   python -B -m unittest discover -s tests -q
   python -B memlink_run.py --run-config outputs/DC01/rules_engine_v1_20261105/phase1_run.json --path-map 'E:\cfreds capstone\MemLink\outputs\DC01=evidence_exports' --output outputs/phase1_reproduced
   ```

   The E: path is the original path prefix stored in the records. The option redirects it to the unpacked exports; it does not read or mount a drive named E:. Use a new output folder for each run.

4. Open `outputs/phase1_reproduced/dashboard.html`. With the unchanged demo inputs, expect 16 passing run checks and 64 ranked findings (3 Tier 2, 61 Tier 3). The saved YARA metadata contains 14 hits for PID 3724. The draft review records describe 5 malicious-supported, 46 benign-supported, and 7 indeterminate unique conclusions; some findings share a conclusion.

Replay checks the saved exports and rebuilds the results. It does not repeat the raw-image extraction or YARA scan. Of 15 completed process scans, one had hits and 14 had no match. Three timed out and two gave no result. No match is not proof of absence.

## Make the private input pack

On the source laptop, with E: connected, run from the existing repository:

```powershell
python -B phase1_make_pack.py --list-only --output outputs/phase1_handover_pack
python -B phase1_make_pack.py --output outputs/phase1_handover_pack
```

Use a new output folder. The ZIP contains the configured text exports and all files cited by the traces and adjudications. It excludes old dashboards, original images and binary dumps. The companion manifest lists the SHA-256 and size of each archived file. Share both privately; do not publish the pack or dashboard to GitHub.

## After the demo

Review the draft conclusions, document any spec revisions, and freeze inputs and rules before a separate retrospective evaluation. Independent-case validation is still pending. A04 and A06–A08 are not evaluable from these inputs.
