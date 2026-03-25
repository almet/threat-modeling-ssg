"""
Generate threat model HTML reports from data.json

Usage: uv run --with jinja2 --with pydantic generate.py
"""

import re
import shutil
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter, defaultdict

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

    # Severity distribution — only threats that actually appear in findings
    severity_order = ["Very High", "High", "Medium", "Low", "Unknown"]
    severity_counter = Counter(
        model.threats[tid].severity or "Unknown"
        for tid in threat_counter
        if tid in model.threats
    )
    severity_distribution = {
        s: severity_counter[s] for s in severity_order if severity_counter[s]
    }
    for s, c in severity_counter.items():
        if s not in severity_distribution and c:
            severity_distribution[s] = c

    return {
        "threat_counter": threat_counter,
        "threats_by_frequency": threats_by_frequency,
        "threats_to_components": threats_to_components,
        "threats_to_scenarios": threats_to_scenarios,
        "components_to_threats": components_to_threats,
        "components_to_scenarios": components_to_scenarios,
        "severity_distribution": severity_distribution,
    }

def generate_highlighted_dfd(dfd: str, highlight_components: set) -> str:
    """Modify a DOT graph string to highlight specific components by label."""
    if not highlight_components or not dfd:
        return dfd

    def highlighter(match):
        node_id = match.group(1)
        attrs = match.group(2)
        label_match = re.search(r'label\s*=\s*"([^"]*)"', attrs)
        if label_match and label_match.group(1) in highlight_components:
            # Detect indentation from existing attribute lines
            indent_match = re.search(r'^(\s+)\S', attrs, re.MULTILINE)
            indent = indent_match.group(1) if indent_match else "        "
            stripped = attrs.rstrip()
            trailing = attrs[len(stripped):]
            attrs = (
                f'{stripped}\n{indent}style = "filled";\n'
                f'{indent}fillcolor = "#c0392b";\n{indent}fontcolor = "white";\n'
                f'{indent}class = "highlighted";{trailing}'
            )
        return f"{node_id} [{attrs}]"

    pattern = re.compile(
        r"\b((?:process|actor|datastore|externalentity|boundary)_\w+)\s*\[([^\[\]]+)\]",
        re.DOTALL,
    )
    return pattern.sub(highlighter, dfd)


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


def generate_dfd(scenario: Scenario) -> str:
    """Generate a Graphviz DOT diagram from scenario components and flows."""

    NODE_SHAPES = {
        "Actor":          "square",
        "Process":        "circle",
        "ExternalEntity": "square",
        "Datastore":      "cylinder",
        "Server":         "box",
    }

    def slug(name: str) -> str:
        return re.sub(r"[^\w]", "_", name)

    def node_id(comp: Component) -> str:
        return f"{comp.component_class.lower()}_{slug(comp.name)}_{slug(comp.inBoundary or '')}"

    def wrap_label(text: str, width: int = 16) -> str:
        words, lines, current = text.split(), [], []
        for w in words:
            if current and sum(len(x) for x in current) + len(current) + len(w) > width:
                lines.append(" ".join(current))
                current = [w]
            else:
                current.append(w)
        if current:
            lines.append(" ".join(current))
        return "\\n".join(lines)

    boundaries = {c.name: c for c in scenario.components if c.component_class == "Boundary"}
    nodes      = [c for c in scenario.components if c.component_class != "Boundary"]

    # Build boundary nesting tree
    boundary_children: dict = defaultdict(list)
    root_boundaries: list = []
    for name, b in boundaries.items():
        if b.inBoundary and b.inBoundary in boundaries:
            boundary_children[b.inBoundary].append(name)
        else:
            root_boundaries.append(name)

    nodes_by_boundary: dict = defaultdict(list)
    for n in nodes:
        nodes_by_boundary[n.inBoundary or ""].append(n)

    lines: list = []

    def emit_node(comp: Component, indent: str) -> None:
        nid   = node_id(comp)
        shape = NODE_SHAPES.get(comp.component_class, "circle")
        label = wrap_label(comp.name)
        lines.extend([
            f"{indent}{nid} [",
            f"{indent}    shape = {shape};",
            f"{indent}    color = black;",
            f"{indent}    fontcolor = black;",
            f'{indent}    label = "{label}";',
            f"{indent}    margin = 0.02;",
            f"{indent}]",
            "",
        ])

    def emit_boundary(name: str, indent: str = "    ") -> None:
        lines.extend([
            f"{indent}subgraph cluster_boundary_{slug(name)} {{",
            f"{indent}    graph [",
            f"{indent}        fontsize = 10;",
            f"{indent}        fontcolor = black;",
            f"{indent}        style = dashed;",
            f"{indent}        color = firebrick2;",
            f"{indent}        label = <<i>{name}</i>>;",
            f"{indent}    ]",
            "",
        ])
        for child in boundary_children.get(name, []):
            emit_boundary(child, indent + "    ")
        for comp in nodes_by_boundary.get(name, []):
            emit_node(comp, indent + "    ")
        lines.extend([f"{indent}}}", ""])

    lines.extend([
        "digraph tm {",
        "    graph [",
        "        fontname = Arial;",
        "        fontsize = 14;",
        "    ]",
        "    node [",
        "        fontname = Arial;",
        "        fontsize = 14;",
        "    ]",
        "    edge [",
        "        fontname = Arial;",
        "        fontsize = 12;",
        "    ]",
        "    nodesep = 1;",
        "",
    ])

    for b_name in root_boundaries:
        emit_boundary(b_name)
    for comp in nodes_by_boundary.get("", []):
        emit_node(comp, "    ")

    # Map component name → node id (first occurrence wins for duplicate names)
    name_to_id: dict = {}
    for comp in nodes:
        name_to_id.setdefault(comp.name, node_id(comp))

    for flow in scenario.flows:
        src = name_to_id.get(flow.source)
        snk = name_to_id.get(flow.sink)
        if src and snk:
            label = wrap_label(flow.id, width=20).replace('"', '\\"')
            lines.extend([
                f"    {src} -> {snk} [",
                f"        color = black;",
                f"        fontcolor = black;",
                f"        dir = forward;",
                f'        label = "{label}";',
                f"    ]",
                "",
            ])

    lines.append("}")
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
    env.filters["sort_by_class"] = lambda d: sorted(d.items(), key=lambda x: x[1].component_class)
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
            scenario.dfd = generate_dfd(scenario)
        scenario.mermaid = generate_mermaid(scenario)

    copy_assets(Path("templates/assets"), output_dir / "assets", config)

    # Compute all unique properties across all threat mappings
    all_threat_props = sorted({
        prop
        for threat in model.threats.values()
        for prop in threat.mapping.requirements + threat.mapping.mitigations
    })

    # Compute all properties present on components for property pages
    component_props = sorted({
        prop
        for component in model.components.values()
        for prop in component.properties.keys()
    })
    all_property_keys = sorted(set(all_threat_props) | set(component_props))

    # Build per-property detail data (based on current findings)
    active_threat_ids = [
        tid for tid in analysis["threat_counter"].keys() if tid in model.threats
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
                affected_in_scenario = [
                    f.target for f in scenario.findings if f.threat_id == threat_id
                ]
                highlighted_dfd = (
                    generate_highlighted_dfd(scenario.dfd, set(affected_in_scenario))
                    if scenario.dfd
                    else None
                )
                threat_scenario_data.append({
                    "scenario": scenario,
                    "affected_components": affected_in_scenario,
                    "highlighted_dfd": highlighted_dfd,
                })
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


if __name__ == "__main__":
    main()
