"""Run the selected 20%-cap development preset without changing old experiments."""
import argparse
from pathlib import Path
from scripts.run_rasp_diverse import run


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ledger','reference','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    run(args.ledger, args.reference, args.output, Path('configs/rasp_selected.json'), args.cache)
