import re
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator


class SiteConfig(BaseModel):
    title: str = "Threat Model Report"
    logo: str | None = None
    github_repo: str | None = None
    hide_components_with_category: list[str] = []


class ThreatMapping(BaseModel):
    requirements: list[str] = []
    mitigations: list[str] = []

    @property
    def requirement_props(self) -> set[str]:
        return {k.split(".", 1)[0] for k in self.requirements}

    @property
    def mitigation_props(self) -> set[str]:
        return {k.split(".", 1)[0] for k in self.mitigations}

    def requirements_for_prop(self, base_prop: str) -> list[str]:
        """All requirement tokens whose base prop matches base_prop."""
        return [k for k in self.requirements if k.split(".", 1)[0] == base_prop]

    def mitigations_for_prop(self, base_prop: str) -> list[str]:
        """All mitigation tokens whose base prop matches base_prop."""
        return [k for k in self.mitigations if k.split(".", 1)[0] == base_prop]


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
    _key: str | None = PrivateAttr(default=None)

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
    file: str = ""
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
    _key: str | None = PrivateAttr(default=None)


class ThreatModel(BaseModel):
    threats: dict[str, Threat]
    components: dict[str, Component]
    scenarios: list[Scenario]
    properties: dict[str, Property]
    _analysis: dict[str, Any] | None = PrivateAttr(default=None)
    _scenario_by_name: dict[str, Scenario] | None = PrivateAttr(default=None)
    _threats_sorted: list[tuple[str, Threat]] | None = PrivateAttr(default=None)
    _threats_data: dict[str, dict[str, str]] | None = PrivateAttr(default=None)

    @model_validator(mode="before")
    @classmethod
    def threats_list_to_dict(cls, data: Any) -> Any:
        if isinstance(data.get("threats"), list):
            data["threats"] = {t["SID"]: t for t in data["threats"]}
        return data

    @model_validator(mode="after")
    def assign_keys(self) -> "ThreatModel":
        for key, component in self.components.items():
            component._key = key
            if not component.name:
                component.name = key
        for key, prop in self.properties.items():
            prop._key = key
        return self

    @classmethod
    def load_report(cls, filename: str = "report.json") -> "ThreatModel":
        return cls.model_validate_json(Path(filename).read_text())

    def prepare_scenarios(self, config: SiteConfig) -> None:
        from .graphs import generate_dataflow, generate_sequence

        for scenario in self.scenarios:
            if config.github_repo and scenario.file:
                scenario.url = f"{config.github_repo}/blob/main/{scenario.file}"
            scenario.dfd = generate_dataflow(scenario, self.components)
            scenario.mermaid = generate_sequence(scenario)

    def scenario_by_name(self) -> dict[str, Scenario]:
        if self._scenario_by_name is None:
            self._scenario_by_name = {s.name: s for s in self.scenarios}
        return self._scenario_by_name

    def threats_sorted(self) -> list[tuple[str, Threat]]:
        if self._threats_sorted is None:

            def sort_key(item: tuple[str, Threat]) -> int:
                match = re.search(r"\d+", item[0])
                return int(match.group()) if match else 0

            self._threats_sorted = sorted(self.threats.items(), key=sort_key)
        return self._threats_sorted

    def threats_data(self) -> dict[str, dict[str, str]]:
        if self._threats_data is None:
            self._threats_data = {
                tid: {"name": t.description, "description": t.details}
                for tid, t in self.threats.items()
            }
        return self._threats_data

    def analyze(self) -> dict[str, Any]:
        """Analyze the threat model and return useful statistics."""
        if self._analysis is not None:
            return self._analysis

        # Count threat frequency (only findings against linked components)
        threat_counter = Counter()
        for scenario in self.scenarios:
            linked = scenario.linked_component_names
            for finding in scenario.findings:
                if finding.target in linked:
                    threat_counter[finding.threat_id] += 1

        threats_by_frequency = threat_counter.most_common()

        # Map threats to components (only linked ones)
        threats_to_components = {}
        for scenario in self.scenarios:
            linked = scenario.linked_component_names
            for finding in scenario.findings:
                if finding.target not in linked:
                    continue
                if finding.threat_id not in threats_to_components:
                    threats_to_components[finding.threat_id] = set()
                threats_to_components[finding.threat_id].add(finding.target)

        # Map threats to scenarios (only those with at least one linked affected component)
        threats_to_scenarios = {}
        for scenario in self.scenarios:
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
        for scenario in self.scenarios:
            for finding in scenario.findings:
                if finding.target not in components_to_threats:
                    components_to_threats[finding.target] = set()
                components_to_threats[finding.target].add(finding.threat_id)

        # Map components to scenarios
        components_to_scenarios = {}
        for scenario in self.scenarios:
            for finding in scenario.findings:
                if finding.target not in components_to_scenarios:
                    components_to_scenarios[finding.target] = []
                if scenario.name not in components_to_scenarios[finding.target]:
                    components_to_scenarios[finding.target].append(scenario.name)

        # Severity distribution — only threats that actually appear in findings
        severity_order = ["Very High", "High", "Medium", "Low", "Unknown"]
        severity_counter = Counter(
            self.threats[tid].severity or "Unknown"
            for tid in threat_counter
            if tid in self.threats
        )
        severity_distribution = {
            s: severity_counter[s] for s in severity_order if severity_counter[s]
        }
        for s, c in severity_counter.items():
            if s not in severity_distribution and c:
                severity_distribution[s] = c

        self._analysis = {
            "threat_counter": threat_counter,
            "threats_by_frequency": threats_by_frequency,
            "threats_to_components": threats_to_components,
            "threats_to_scenarios": threats_to_scenarios,
            "components_to_threats": components_to_threats,
            "components_to_scenarios": components_to_scenarios,
            "severity_distribution": severity_distribution,
        }
        return self._analysis

    def _mitigation_applies(
        self, component: Component, prop_key: str, threat: Threat
    ) -> bool:
        def split_token(token: str) -> tuple[str, str | None]:
            if "." in token:
                base, item = token.split(".", 1)
                return base, item
            return token, None

        required_items = set()
        for req_key in threat.mapping.requirements:
            req_prop, req_item = split_token(req_key)
            if req_item:
                required_items.add(req_item)
                continue
            req_value = component.properties.get(req_prop)
            if isinstance(req_value, list):
                required_items.update(req_value)

        mitigation_items = set()
        for mit_key in threat.mapping.mitigations:
            mit_prop, mit_item = split_token(mit_key)
            if mit_prop != prop_key:
                continue
            if mit_item:
                mitigation_items.add(mit_item)

        value = component.properties.get(prop_key)
        if isinstance(value, list):
            required = set(required_items)
            required.update(mitigation_items)
            if required:
                return required.issubset(set(value))
            return bool(value)
        if isinstance(value, bool):
            return value is True
        if value is None:
            return False
        return bool(value)

    def threat_unimplemented_mitigations(
        self, component: Component, threat: Threat
    ) -> list[str]:
        """Mitigation tokens from threat.mapping.mitigations not yet implemented by component."""
        return [
            mit_token
            for mit_token in threat.mapping.mitigations
            if not self._mitigation_applies(component, mit_token.split(".", 1)[0], threat)
        ]

    def component_unimplemented_mitigations(
        self, component: Component, threat_ids: set[str]
    ) -> list[str]:
        missing = set()
        for tid in threat_ids:
            threat = self.threats.get(tid)
            if not threat:
                continue
            for prop_key in threat.mapping.mitigations:
                base_prop = prop_key.split(".", 1)[0]
                if not self._mitigation_applies(component, base_prop, threat):
                    missing.add(base_prop)
        return sorted(missing)

    def property_mitigation_state(
        self, prop_key: str
    ) -> tuple[list[tuple[str, Threat]], list[tuple[str, Threat]], list[dict[str, Any]]]:
        analysis = self.analyze()
        active_threat_ids = [
            tid for tid in analysis["threat_counter"] if tid in self.threats
        ]

        mitigated_threats: list[tuple[str, Threat]] = []
        would_be_mitigated_threats: list[tuple[str, Threat]] = []
        benefit_components: dict[str, dict[str, Any]] = {}

        for tid in active_threat_ids:
            threat = self.threats[tid]
            if not any(
                mit_key.split(".", 1)[0] == prop_key
                for mit_key in threat.mapping.mitigations
            ):
                continue

            affected_components = analysis["threats_to_components"].get(tid, set())
            if not affected_components:
                mitigated_threats.append((tid, threat))
                continue

            missing_components = []
            for comp_name in affected_components:
                comp = self.components.get(comp_name)
                if not comp:
                    continue
                if not self._mitigation_applies(comp, prop_key, threat):
                    missing_components.append(comp_name)

            if missing_components:
                would_be_mitigated_threats.append((tid, threat))
                for comp_name in missing_components:
                    comp = self.components.get(comp_name)
                    if not comp:
                        continue
                    entry = benefit_components.setdefault(
                        comp_name,
                        {
                            "name": comp_name,
                            "comp": comp,
                            "current_value": comp.properties.get(prop_key),
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

        return mitigated_threats, would_be_mitigated_threats, benefit_components_list
