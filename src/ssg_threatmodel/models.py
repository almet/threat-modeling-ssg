from collections import Counter
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SiteConfig(BaseModel):
    title: str = "Threat Model Report"
    logo: Optional[str] = None
    github_repo: Optional[str] = None
    hide_components_with_category: List[str] = []


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

    @property
    def linked_component_names(self) -> set:
        """Component names that appear in at least one flow (source or sink)."""
        return {flow.source for flow in self.flows} | {flow.sink for flow in self.flows}


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
