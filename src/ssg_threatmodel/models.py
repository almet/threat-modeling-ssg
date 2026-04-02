from collections import Counter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SiteConfig(BaseModel):
    title: str = "Threat Model Report"
    logo: str | None = None
    github_repo: str | None = None
    hide_components_with_category: list[str] = []


class ThreatMapping(BaseModel):
    requirements: list[str] = []
    mitigations: list[str] = []


class Threat(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    SID: str
    comment: str = ""
    description: str = ""
    details: str = ""
    example: str = ""
    severity: str = ""
    likelihood: str = ""
    mapping: ThreatMapping = Field(default_factory=ThreatMapping)


class Component(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str = ""
    component_class: str = Field(alias="class", default="")
    description: str | None = ""
    inBoundary: str | None = Field(alias="in_boundary", default=None)
    properties: dict[str, Any] = {}

    def get_property(self, name):
        return self.properties.get(name, False)


class Finding(BaseModel):
    target: str
    threat_id: str


class Flow(BaseModel):
    id: str
    name: str
    is_response: bool = False
    response_to: str | None = None
    sink: str
    source: str


class Scenario(BaseModel):
    description: str = ""
    name: str
    file: str
    findings: list[Finding] = []
    flows: list[Flow] = []
    components: list[str] = []
    dfd: str = ""
    mermaid: str = ""
    url: str | None = None

    @property
    def linked_component_names(self) -> set:
        """Component names that appear in at least one flow (source or sink)."""
        return {flow.source for flow in self.flows} | {flow.sink for flow in self.flows}


class Property(BaseModel):
    description: str = ""
    name: str
    type: str


class ThreatModel(BaseModel):
    threats: dict[str, Threat]
    components: dict[str, Component]
    scenarios: list[Scenario]
    properties: dict[str, Property]

    @model_validator(mode="before")
    @classmethod
    def threats_list_to_dict(cls, data: Any) -> Any:
        if isinstance(data.get("threats"), list):
            data["threats"] = {t["SID"]: t for t in data["threats"]}
        return data


def analyze_data(model: ThreatModel):
    """Analyze the threat model and return useful statistics."""

    # Count threat frequency (only findings against linked components)
    threat_counter = Counter()
    for scenario in model.scenarios:
        linked = scenario.linked_component_names
        for finding in scenario.findings:
            if finding.target in linked:
                threat_counter[finding.threat_id] += 1

    threats_by_frequency = threat_counter.most_common()

    # Map threats to components (only linked ones)
    threats_to_components = {}
    for scenario in model.scenarios:
        linked = scenario.linked_component_names
        for finding in scenario.findings:
            if finding.target not in linked:
                continue
            if finding.threat_id not in threats_to_components:
                threats_to_components[finding.threat_id] = set()
            threats_to_components[finding.threat_id].add(finding.target)

    # Map threats to scenarios (only those with at least one linked affected component)
    threats_to_scenarios = {}
    for scenario in model.scenarios:
        linked = scenario.linked_component_names
        for finding in scenario.findings:
            if finding.target not in linked:
                continue
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
