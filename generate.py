"""
Generate threat model HTML reports from data.json

Usage: uv run --with jinja2 --with pydantic generate.py
"""

import shutil
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter

from pydantic import BaseModel
from jinja2 import Environment, FileSystemLoader


# Pydantic Models
class Threat(BaseModel):
    name: str
    description: str


class ComponentProperties(BaseModel):
    OS: str
    reads_input: bool
    sanitizes_input: bool
    loads_external_resources: bool
    writes_logs: bool
    executes_system_scripts: bool


class Component(BaseModel):
    description: str
    inBoundary: str
    properties: ComponentProperties


class Finding(BaseModel):
    target: str
    threat_id: str


class Flow(BaseModel):
    id: str
    name: str
    source: str
    sink: str
    isResponse: Optional[bool] = None
    responseTo: Optional[str] = None


class Scenario(BaseModel):
    name: str
    description: str
    findings: List[Finding]
    flows: List[Flow]


class ThreatModel(BaseModel):
    threats: Dict[str, Threat]
    components: Dict[str, Component]
    scenarios: List[Scenario]



def analyze_data(model: ThreatModel):
    """Analyze the threat model and return useful statistics"""

    # Count threat frequency
    threat_counter = Counter()
    for scenario in model.scenarios:
        for finding in scenario.findings:
            threat_counter[finding.threat_id] += 1

    # Get threats by frequency
    threats_by_frequency = threat_counter.most_common()

    # Map threats to components
    threats_to_components = {}
    for scenario in model.scenarios:
        for finding in scenario.findings:
            if finding.threat_id not in threats_to_components:
                threats_to_components[finding.threat_id] = set()
            threats_to_components[finding.threat_id].add(finding.target)

    # Map threats to scenarios
    threats_to_scenarios = {}
    for scenario in model.scenarios:
        for finding in scenario.findings:
            if finding.threat_id not in threats_to_scenarios:
                threats_to_scenarios[finding.threat_id] = []
            threats_to_scenarios[finding.threat_id].append(scenario.name)

    # Map components to threats
    components_to_threats = {}
    for scenario in model.scenarios:
        for finding in scenario.findings:
            if finding.target not in components_to_threats:
                components_to_threats[finding.target] = set()
            components_to_threats[finding.target].add(finding.threat_id)

    # Map components to scenarios
    components_to_scenarios = {}
    for scenario in model.scenarios:
        for finding in scenario.findings:
            if finding.target not in components_to_scenarios:
                components_to_scenarios[finding.target] = []
            if scenario.name not in components_to_scenarios[finding.target]:
                components_to_scenarios[finding.target].append(scenario.name)

    return {
        "threat_counter": threat_counter,
        "threats_by_frequency": threats_by_frequency,
        "threats_to_components": threats_to_components,
        "threats_to_scenarios": threats_to_scenarios,
        "components_to_threats": components_to_threats,
        "components_to_scenarios": components_to_scenarios,
    }


def main():
    # Load data
    print("Loading data.json...")
    with open("data.json") as f:
        model = ThreatModel.model_validate_json(f.read())

    # Analyze data
    print("Analyzing threat model...")
    analysis = analyze_data(model)

    # Setup Jinja2
    env = Environment(loader=FileSystemLoader("templates"))

    # Create output directory
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # Copy assets folder
    print("Copying assets...")
    assets_src = Path("templates/assets")
    assets_dst = output_dir / "assets"
    if assets_dst.exists():
        shutil.rmtree(assets_dst)
    shutil.copytree(assets_src, assets_dst)

    # Generate summary page
    print("Generating summary.html...")
    template = env.get_template("summary.html")
    html = template.render(
        model=model,
        analysis=analysis,
        total_capec_threats=1000,  # Placeholder - adjust as needed
    )
    (output_dir / "summary.html").write_text(html)

    # Generate threat pages
    print(f"Generating {len(model.threats)} threat pages...")
    template = env.get_template("threat.html")
    for threat_id, threat in model.threats.items():
        html = template.render(
            threat_id=threat_id,
            threat=threat,
            components=analysis["threats_to_components"].get(threat_id, set()),
            scenarios=analysis["threats_to_scenarios"].get(threat_id, []),
            frequency=analysis["threat_counter"].get(threat_id, 0),
            model=model,
        )
        (output_dir / f"threat_{threat_id}.html").write_text(html)

    # Generate component pages
    print(f"Generating {len(model.components)} component pages...")
    template = env.get_template("component.html")
    for comp_name, component in model.components.items():
        html = template.render(
            comp_name=comp_name,
            component=component,
            threats=analysis["components_to_threats"].get(comp_name, set()),
            scenarios=analysis["components_to_scenarios"].get(comp_name, []),
            model=model,
        )
        (output_dir / f"component_{comp_name.replace('.', '_')}.html").write_text(html)

    # Generate components list page
    print("Generating components.html...")
    template = env.get_template("components.html")
    html = template.render(model=model, analysis=analysis)
    (output_dir / "components.html").write_text(html)

    # Generate scenario pages
    print(f"Generating {len(model.scenarios)} scenario pages...")
    template = env.get_template("scenario.html")
    for scenario in model.scenarios:
        html = template.render(
            scenario=scenario,
            model=model,
        )
        (output_dir / f"scenario_{scenario.name.replace(' ', '_')}.html").write_text(html)

    print(f"\nDone! Generated files in {output_dir}/")


if __name__ == "__main__":
    main()
