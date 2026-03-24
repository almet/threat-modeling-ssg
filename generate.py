"""
Generate threat model HTML reports from data.json

Usage: uv run --with jinja2 --with pydantic generate.py
"""

import re
import shutil
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field, model_validator
from jinja2 import Environment, FileSystemLoader


class SiteConfig(BaseModel):
    title: str = "Threat Model Report"
    logo: Optional[str] = None
    github_repo: Optional[str] = None


class ThreatMapping(BaseModel):
    requirements: List[str] = []
    mitigations: List[str] = []


class Threat(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    SID: str
    name: str = Field(alias="description")
    description: str = Field(alias="details", default="")
    severity: str = ""
    likelihood_of_attack: str = Field(alias="Likelihood Of Attack", default="")
    mapping: ThreatMapping = Field(default_factory=ThreatMapping)
    target: List[str] = []


class Component(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str = ""
    component_class: str = Field(alias="class", default="")
    description: str = ""
    inBoundary: Optional[str] = Field(alias="in_boundary", default=None)
    properties: Dict[str, Any] = {}



class Finding(BaseModel):
    target: str
    threat_id: str


class Flow(BaseModel):
    id: str
    description: str = ""
    source: str
    sink: str
    is_response: bool = False
    response_to: Optional[str] = None


class Scenario(BaseModel):
    name: str
    description: str = ""
    findings: List[Finding] = []
    flows: List[Flow] = []
    components: List[Component] = []
    dfd: Optional[str] = None
    file: Optional[str] = None
    seq: Optional[Any] = None
    url: Optional[str] = None
    mermaid: Optional[str] = None


class ThreatModel(BaseModel):
    threats: Dict[str, Threat]
    components: Dict[str, Component]
    scenarios: List[Scenario]

    @model_validator(mode="before")
    @classmethod
    def threats_list_to_dict(cls, data: Any) -> Any:
        if isinstance(data.get("threats"), list):
            data["threats"] = {t["SID"]: t for t in data["threats"]}
        return data


def analyze_data(model: ThreatModel):
    """Analyze the threat model and return useful statistics"""

    # Count threat frequency
    threat_counter = Counter()
    for scenario in model.scenarios:
        for finding in scenario.findings:
            threat_counter[finding.threat_id] += 1

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
            if scenario.name not in threats_to_scenarios[finding.threat_id]:
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

def generate_mermaid(scenario: Scenario) -> str:
    if not scenario.flows:
        return ""

    def alias(name: str) -> str:
        return re.sub(r"[^\w]", "_", name)

    seen: set = set()
    participants: List[str] = []
    for flow in scenario.flows:
        for name in (flow.source, flow.sink):
            if name not in seen:
                participants.append(name)
                seen.add(name)

    lines = ["sequenceDiagram"]
    for name in participants:
        lines.append(f"    participant {alias(name)} as {name}")
    lines.append("")
    for flow in scenario.flows:
        arrow = "-->>" if flow.is_response else "->>"
        lines.append(f"    {alias(flow.source)}{arrow}{alias(flow.sink)}: {flow.id}")

    return "\n".join(lines)


def load_config(filename="config.toml"):
    config_path = Path(filename)
    if config_path.exists():
        print("Loading config.toml...")
        with open(config_path, "rb") as f:
            return SiteConfig.model_validate(tomllib.load(f))
    return SiteConfig()


def copy_assets(assets_src, assets_dst, config):
    if assets_dst.exists():
        shutil.rmtree(assets_dst)
    shutil.copytree(assets_src, assets_dst)



def main():
    config = load_config()

    with open("data.json") as f:
        model = ThreatModel.model_validate_json(f.read())

    analysis = analyze_data(model)

    # Setup Jinja2
    env = Environment(loader=FileSystemLoader("templates"))
    env.filters["basename"] = lambda p: Path(p).name
    env.filters["slugify"] = lambda s: re.sub(r"[^\w]", "_", s)
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
        scenario.mermaid = generate_mermaid(scenario)

    copy_assets(Path("templates/assets"), output_dir / "assets", config)

    # Generate index page
    print("Generating index.html...")
    template = env.get_template("summary.html")
    html = template.render(
        config=config,
        model=model,
        analysis=analysis,
        total_capec_threats=559,
    )

    (output_dir / "index.html").write_text(html)

    # Generate threat pages
    print(f"Generating {len(model.threats)} threat pages...")
    template = env.get_template("threat.html")
    for threat_id, threat in model.threats.items():
        html = template.render(
            config=config,
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
    for name, component in model.components.items():
        threat_ids = analysis["components_to_threats"].get(name, set())
        unimplemented_mitigations = sorted({
            prop
            for threat_id in threat_ids
            for prop in model.threats[threat_id].mapping.mitigations
            if component.properties.get(prop) is False
        })
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


if __name__ == "__main__":
    main()
