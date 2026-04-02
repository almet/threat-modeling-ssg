import json
import re
import shutil
import tomllib
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from . import views
from .models import SiteConfig, ThreatModel
from .utils import render_views

TEMPLATES_DIR = Path(__file__).parent / "templates"


def load_config(filename="config.toml"):
    config_path = Path(filename)
    if config_path.exists():
        print("Loading config.toml...")
        with open(config_path, "rb") as f:
            return SiteConfig.model_validate(tomllib.load(f))
    return SiteConfig()


def copy_assets(assets_dst):
    assets_src = TEMPLATES_DIR / "assets"
    if assets_dst.exists():
        shutil.rmtree(assets_dst)
    shutil.copytree(assets_src, assets_dst)


def main():
    config = load_config()

    model = ThreatModel.load_report("report.json")

    # Setup Jinja2 and its filters
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    env.filters["basename"] = lambda p: Path(p).name
    env.filters["slugify"] = lambda s: re.sub(r"[^\w]", "_", s)

    # FIXME: These are a bit hackish, but work.
    env.filters["sort_by_class"] = lambda d: sorted(
        d.items(), key=lambda x: x[1].component_class
    )
    env.filters["implemented"] = lambda d: sorted(
        ((k, v) for k, v in d.items() if v is not False),
        key=lambda item: 0 if not isinstance(item[1], bool) else 1,
    )

    # Create output directory
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    model.prepare_scenarios(config)

    copy_assets(output_dir / "assets")

    render_views(
        env,
        output_dir,
        {
            "config": config,
            "model": model,
        },
    )

    print(f"\nDone! Generated files in {output_dir}/")
