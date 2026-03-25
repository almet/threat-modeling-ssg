import re
import shutil
import tomllib
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .graphs import generate_dataflow, generate_highlighted_dataflow, generate_sequence
from .models import SiteConfig, ThreatModel, analyze_data

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

    with open("data.json") as f:
        model = ThreatModel.model_validate_json(f.read())

    analysis = analyze_data(model)

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

    for scenario in model.scenarios:
        if config.github_repo and scenario.file:
            scenario.url = f"{config.github_repo}/blob/main/{scenario.file}"
        if not scenario.dfd and scenario.components:
            scenario.dfd = generate_dataflow(scenario)
        scenario.mermaid = generate_sequence(scenario)

    copy_assets(output_dir / "assets")

    # Compute all unique properties across all threat mappings
    all_threat_props = sorted(
        {
            prop
            for threat in model.threats.values()
            for prop in threat.mapping.requirements + threat.mapping.mitigations
        }
    )

    # Compute all properties present on components for property pages
    component_props = sorted(
        {
            prop
            for component in model.components.values()
            for prop in component.properties
        }
    )
    all_property_keys = sorted(set(all_threat_props) | set(component_props))

    # Build per-property detail data (based on current findings)
    active_threat_ids = [
        tid for tid in analysis["threat_counter"] if tid in model.threats
    ]
    props_detail = {}
    for prop in all_property_keys:
        label = prop.replace("_", " ").replace("!", "not ").title()
        prop_slug = re.sub(r"[^\w]", "_", prop)

        mitigated_threats = []
        would_be_mitigated_threats = []
        benefit_components = {}

        for tid in active_threat_ids:
            threat = model.threats[tid]
            if prop not in threat.mapping.mitigations:
                continue

            affected_components = analysis["threats_to_components"].get(tid, set())
            if not affected_components:
                mitigated_threats.append((tid, threat))
                continue

            missing_components = []
            for comp_name in affected_components:
                comp = model.components.get(comp_name)
                if not comp:
                    continue
                if comp.properties.get(prop) is not True:
                    missing_components.append(comp_name)

            if missing_components:
                would_be_mitigated_threats.append((tid, threat))
                for comp_name in missing_components:
                    comp = model.components.get(comp_name)
                    if not comp:
                        continue
                    entry = benefit_components.setdefault(
                        comp_name,
                        {
                            "name": comp_name,
                            "comp": comp,
                            "current_value": comp.properties.get(prop),
                            "threats": [],
                        },
                    )
                    entry["threats"].append((tid, threat))
            else:
                mitigated_threats.append((tid, threat))

        mitigated_threats.sort(key=lambda item: item[0])
        would_be_mitigated_threats.sort(key=lambda item: item[0])

        benefit_components_list = list(benefit_components.values())
        benefit_components_list.sort(
            key=lambda item: (
                0 if item["current_value"] is False else 1,
                item["name"].lower(),
            )
        )

        props_detail[prop] = {
            "label": label,
            "slug": prop_slug,
            "mitigated_threats": mitigated_threats,
            "would_be_mitigated_threats": would_be_mitigated_threats,
            "benefit_components": benefit_components_list,
        }

    # Generate index page
    print("Generating index.html...")
    template = env.get_template("summary.html")
    html = template.render(
        config=config,
        model=model,
        analysis=analysis,
        total_capec_threats=559,
        all_threat_props=all_threat_props,
    )
    (output_dir / "index.html").write_text(html)

    # Generate all-threats page
    print("Generating threats.html...")
    template = env.get_template("threats.html")
    html = template.render(
        config=config,
        model=model,
        analysis=analysis,
        all_threat_props=all_threat_props,
    )
    (output_dir / "threats.html").write_text(html)

    # Build scenario lookup
    scenario_by_name = {s.name: s for s in model.scenarios}

    # Generate threat pages
    print(f"Generating {len(model.threats)} threat pages...")
    template = env.get_template("threat.html")
    for threat_id, threat in model.threats.items():
        scenario_names = analysis["threats_to_scenarios"].get(threat_id, [])
        threat_scenario_data = []
        for scenario_name in scenario_names:
            scenario = scenario_by_name.get(scenario_name)
            if scenario:
                linked = scenario.linked_component_names
                affected_in_scenario = [
                    f.target
                    for f in scenario.findings
                    if f.threat_id == threat_id and f.target in linked
                ]
                if not affected_in_scenario:
                    continue
                highlighted_dfd = (
                    generate_highlighted_dataflow(
                        scenario.dfd, set(affected_in_scenario)
                    )
                    if scenario.dfd
                    else None
                )
                threat_scenario_data.append(
                    {
                        "scenario": scenario,
                        "affected_components": affected_in_scenario,
                        "highlighted_dfd": highlighted_dfd,
                    }
                )
        html = template.render(
            config=config,
            threat_id=threat_id,
            threat=threat,
            components=analysis["threats_to_components"].get(threat_id, set()),
            scenarios=scenario_names,
            frequency=analysis["threat_counter"].get(threat_id, 0),
            model=model,
            threat_scenario_data=threat_scenario_data,
        )
        (output_dir / f"threat_{threat_id}.html").write_text(html)

    # Generate component pages
    print(f"Generating {len(model.components)} component pages...")
    template = env.get_template("component.html")
    for name, component in model.components.items():
        threat_ids = analysis["components_to_threats"].get(name, set())
        unimplemented_mitigations = sorted(
            {
                prop
                for threat_id in threat_ids
                for prop in model.threats[threat_id].mapping.mitigations
                if component.properties.get(prop) is False
            }
        )
        html = template.render(
            config=config,
            comp_name=name,
            component=component,
            threats=threat_ids,
            scenarios=analysis["components_to_scenarios"].get(name, []),
            unimplemented_mitigations=unimplemented_mitigations,
            model=model,
        )
        safe_name = re.sub(r"[^\w]", "_", name)
        (output_dir / f"component_{safe_name}.html").write_text(html)

    # Generate components list page
    print("Generating components.html...")
    template = env.get_template("components.html")
    html = template.render(config=config, model=model, analysis=analysis)
    (output_dir / "components.html").write_text(html)

    # Generate individual property pages
    print(f"Generating {len(props_detail)} property pages...")
    prop_template = env.get_template("property.html")
    for prop, data in props_detail.items():
        html = prop_template.render(config=config, prop=prop, data=data)
        (output_dir / f"property_{data['slug']}.html").write_text(html)

    # Generate scenario pages
    print(f"Generating {len(model.scenarios)} scenario pages...")
    template = env.get_template("scenario.html")
    for scenario in model.scenarios:
        html = template.render(
            config=config,
            scenario=scenario,
            model=model,
        )
        (output_dir / f"scenario_{scenario.name.replace(' ', '_')}.html").write_text(
            html
        )

    print(f"\nDone! Generated files in {output_dir}/")
