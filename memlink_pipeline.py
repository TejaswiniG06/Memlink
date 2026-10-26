"""Configurable, provenance-aware memory extraction. Source images are read-only."""
import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def extract(config, only=None):
    image = Path(config['memory_image'])
    if not image.is_file():
        raise ValueError(f'Memory image unavailable: {image}')
    actual = sha256(image)
    if config.get('memory_sha256') and actual != config['memory_sha256']:
        raise ValueError('Memory image SHA-256 mismatch')
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    root = Path(config['output_root']) / 'memory_runs' / run_id
    root.mkdir(parents=True, exist_ok=False)
    version = subprocess.run([config['python'], '-B', '-c',
                             'import sys; sys.path.insert(0, sys.argv[1]); from volatility3.framework.constants import PACKAGE_VERSION; print(PACKAGE_VERSION)',
                             str(Path(config['volatility']).parent)],
                             capture_output=True, text=True)
    manifest = {'case_id': config['case_id'], 'host_id': config['host_id'],
                'snapshot_id': config['snapshot_id'], 'started_utc': run_id,
                'image': str(image), 'image_sha256': actual,
                'tool_version_response': (version.stdout + version.stderr).strip(),
                'configuration': config, 'plugins': {}}
    plugins = only or config['plugins']
    for plugin in plugins:
        if plugin not in config['plugins']:
            raise ValueError(f'Plugin not configured: {plugin}')
        command = [config['python'], '-B', config['volatility'], '-q',
                   '-f', str(image), '-r', 'json', plugin]
        record = {'command': command, 'started_utc': datetime.now(timezone.utc).isoformat()}
        target = root / (plugin + '.json')
        with target.open('wb') as stdout, (root / (plugin + '.stderr.txt')).open('wb') as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
        record['exit_code'] = result.returncode
        record['finished_utc'] = datetime.now(timezone.utc).isoformat()
        record['source_file'] = str(target)
        record['sha256'] = sha256(target)
        try:
            data = json.loads(target.read_text(encoding='utf-8-sig'))
            if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                raise ValueError('Expected Volatility JSON row list')
            record['rows'] = len(data)
            record['status'] = ('success' if data else 'success_empty') if result.returncode == 0 else 'failed'
        except (ValueError, UnicodeError) as error:
            record['status'] = 'failed' if result.returncode else 'invalid_output'
            record['reason'] = str(error)
        manifest['plugins'][plugin] = record
        (root / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        print(f"{plugin}: {record['status']} ({record.get('rows', '?')} rows)", flush=True)
    print(f'Manifest: {root / "manifest.json"}', flush=True)
    return 0 if all(r['status'] in ('success', 'success_empty') for r in manifest['plugins'].values()) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('--only', nargs='+')
    args = parser.parse_args()
    return extract(json.loads(args.config.read_text(encoding='utf-8')), args.only)


if __name__ == '__main__':
    sys.exit(main())
