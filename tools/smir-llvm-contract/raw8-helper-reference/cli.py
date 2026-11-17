"""Run a fresh actual generic Machine versus native physical helper witness."""
import argparse
import json
from pathlib import Path
from oracle import actual_witness

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(actual_witness(args.profile, args.binary.resolve(), args.receipt.resolve()), sort_keys=True))
