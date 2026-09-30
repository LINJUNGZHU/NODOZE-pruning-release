"""Render the four documentation diagrams with Graphviz (no experiment inputs)."""
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'docs/project-architecture/sources'
OUTPUT = ROOT / 'webapp/frontend/project-architecture'


def main():
    dot = shutil.which('dot')
    if dot is None:
        raise SystemExit('Graphviz dot is required. Chinese labels use WenQuanYi Zen Hei.')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for source in sorted(SOURCES.glob('*.dot')):
        for extension in ('svg', 'png', 'pdf'):
            target = OUTPUT / f'{source.stem}.{extension}'
            # DPI is for raster output. Graphviz 2.43 scales SVG contents twice
            # at non-default DPI, leaving the viewBox too small and clipping it.
            raster_options = ['-Gdpi=144'] if extension == 'png' else []
            subprocess.run([dot, *raster_options, f'-T{extension}', str(source), '-o', str(target)], check=True)
            print(target.relative_to(ROOT))


if __name__ == '__main__':
    main()
