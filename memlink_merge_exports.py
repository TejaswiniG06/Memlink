"""Merge common-schema CSV exports while retaining every source field."""
import argparse
import csv
from pathlib import Path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', type=Path, nargs='+')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fields = []
    for source in args.inputs:
        with source.open(encoding='utf-8-sig', newline='') as stream:
            for field in csv.DictReader(stream).fieldnames or []:
                if field not in fields:
                    fields.append(field)
    with args.output.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for source in args.inputs:
            with source.open(encoding='utf-8-sig', newline='') as incoming:
                writer.writerows(csv.DictReader(incoming))
