"""Build the private Phase 1 input pack (a zip) for rebuilding the DC01 demo on another machine.

    python -B phase1_make_pack.py --output <new folder>

Run from the workspace root with the E: drive connected. Reads (never changes) the inputs listed in
outputs/DC01/rules_engine_v1_20261105/phase1_run.json and writes <output>/memlink_phase1_input_pack.zip
plus PACK_MANIFEST.json (sha256 and size of every file). The pack holds case data and record excerpts:
share it privately, never through Git. Memory-run folders are stored under evidence_exports/memory_runs/.
"""
import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

RUN_CONFIG = Path('outputs/DC01/rules_engine_v1_20261105/phase1_run.json')
INPUT_KEYS = ('config', 'service_events', 'threads_run_manifest', 'threads',
              'disk_evidence_manifest', 'disk_evidence', 'adjudications', 'reviews',
              'traces', 'yara_matches')
DATA_SUFFIXES = {'.json', '.jsonl', '.csv', '.txt'}


def load_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def cited_files(document):
    if isinstance(document, dict):
        if isinstance(document.get('file'), str):
            yield document['file']
        for value in document.values():
            yield from cited_files(value)
    elif isinstance(document, list):
        for value in document:
            yield from cited_files(value)


def collect(config, workspace=None, run_config=RUN_CONFIG):
    """Resolve declared inputs and record references, never whole output trees."""
    root = Path(workspace or Path.cwd()).resolve()
    memory_roots = [(root / run).resolve() for run in config['memory_runs']]
    selected = {}

    def add(value):
        source = (root / value).resolve()
        if source.suffix.lower() not in DATA_SUFFIXES:
            raise ValueError(f'Not an allowed text evidence export: {value}')
        for folder in memory_roots:
            if source.is_relative_to(folder):
                name = f'evidence_exports/memory_runs/{folder.name}/{source.relative_to(folder).as_posix()}'
                break
        else:
            if not source.is_relative_to(root):
                raise ValueError(f'Input outside workspace and declared memory runs: {value}')
            relative = source.relative_to(root)
            if relative.parts[0] not in ('outputs', 'backups'):
                raise ValueError(f'Input outside the case-export folders: {value}')
            name = relative.as_posix()
        if not source.is_file():
            raise FileNotFoundError(f'Required input missing (check E: if applicable): {source}')
        if name in selected and selected[name] != source:
            raise ValueError(f'Two inputs resolve to the same archive path: {name}')
        selected[name] = source
        return source

    add(run_config)
    for key in INPUT_KEYS:
        if config.get(key):
            source = add(config[key])
            if key in ('traces', 'adjudications'):
                for reference in cited_files(load_json(source)):
                    add(reference)
    for folder in memory_roots:
        manifest = load_json(add(folder / 'manifest.json'))
        for plugin in manifest['plugins'].values():
            if plugin['status'] in ('success', 'success_empty'):
                add(plugin['source_file'])
    return [(source, name) for name, source in sorted(selected.items())]


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, help='new folder to create')
    parser.add_argument('--list-only', action='store_true', help='print what would be packed, write nothing')
    args = parser.parse_args(argv)
    try:
        items = collect(load_json(RUN_CONFIG))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f'Cannot build input pack: {error}\n')
    total = sum(s.stat().st_size for s, _ in items)
    print(f'{len(items)} files, {total / 1e6:.1f} MB uncompressed')
    if args.list_only:
        for _, name in items:
            print(' ', name)
        return 0
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=False)
    manifest = {}
    with zipfile.ZipFile(out / 'memlink_phase1_input_pack.zip', 'w', zipfile.ZIP_DEFLATED) as pack:
        for source, name in items:
            digest, size = hashlib.sha256(), 0
            with source.open('rb') as incoming, pack.open(name, 'w') as archived:
                for block in iter(lambda: incoming.read(1 << 20), b''):
                    archived.write(block)
                    digest.update(block)
                    size += len(block)
            manifest[name] = {'bytes': size, 'sha256': digest.hexdigest()}
    (out / 'PACK_MANIFEST.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(f'wrote {out / "memlink_phase1_input_pack.zip"} and PACK_MANIFEST.json')
    return 0


if __name__ == '__main__':
    sys.exit(main())
