from .components import Component, Property, Scenario, Threat


class Report:
    def __init__(
        self,
        scenarios: list[Scenario],
        components: list[Component] | None = None,
        threats: list[Threat] | None = None,
        properties: list[Property] | None = None,
    ):
        self.scenarios = scenarios
        self.threats = threats
        self.properties = properties
        self.components = components or self.populate_components(scenarios)

    def populate_components(self, scenarios: list[Scenario]):
        """Iterate all scenarios and retrieve their components."""
        components = {}
        for scenario in scenarios:
            for component in scenario.iter_components():
                components[component.name] = component
        return components.values()

    def components_to_dict(self):
        return {comp.name: comp.to_dict() for comp in self.components}

    def properties_to_dict(self):
        return {prop.name: prop.to_dict() for prop in self.properties}

    def scenarios_to_dict(self):
        return [scenario.to_dict() for scenario in self.scenarios]

    def threats_to_dict(self):
        return [threat.to_dict() for threat in self.threats]

    def generate(self):
        for scenario in self.scenarios:
            scenario.populate_findings(self.threats)

        report = {}
        report["properties"] = self.properties_to_dict()
        report["components"] = self.components_to_dict()
        report["scenarios"] = self.scenarios_to_dict()
        report["threats"] = self.threats_to_dict()
        return report
