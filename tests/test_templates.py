"""Tests for template rendering with fake data."""

import re
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

from ssg_threatmodel import views
from ssg_threatmodel.models import (
    Component,
    Finding,
    Flow,
    Property,
    Scenario,
    SiteConfig,
    Threat,
    ThreatMapping,
    ThreatModel,
)
from ssg_threatmodel.utils import VIEWS, _call_view, _normalize_items

TEMPLATES_DIR = Path(__file__).parent.parent / "src" / "ssg_threatmodel" / "templates"


@pytest.fixture
def jinja_env():
    """Create Jinja2 environment with all required filters."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    env.filters["basename"] = lambda p: Path(p).name
    env.filters["slugify"] = lambda s: re.sub(r"[^\w]", "_", s)
    env.filters["sort_by_class"] = lambda d: sorted(
        d.items(), key=lambda x: x[1].component_class
    )
    env.filters["implemented"] = lambda d: sorted(
        ((k, v) for k, v in d.items() if v is not False),
        key=lambda item: 0 if not isinstance(item[1], bool) else 1,
    )
    return env


@pytest.fixture
def sample_config():
    """Create a sample site configuration."""
    return SiteConfig(
        title="Test Threat Model",
        logo="logo.png",
        github_repo="https://github.com/test/repo",
        hide_components_with_category=[],
    )


@pytest.fixture
def sample_model():
    """Create a comprehensive sample threat model with realistic data."""
    threats = {
        "CAPEC-1": Threat(
            SID="CAPEC-1",
            description="Buffer Overflow",
            details="An adversary exploits buffer overflow vulnerabilities.",
            example="Stack smashing attack",
            severity="High",
            likelihood="Medium",
            mapping=ThreatMapping(
                requirements=["reads_input", "handles_binary_data"],
                mitigations=["validates_input", "uses_safe_functions"],
            ),
        ),
        "CAPEC-2": Threat(
            SID="CAPEC-2",
            description="SQL Injection",
            details="An adversary injects SQL commands into queries.",
            example="' OR '1'='1",
            severity="Very High",
            likelihood="High",
            mapping=ThreatMapping(
                requirements=["uses_database"],
                mitigations=["uses_parameterized_queries", "validates_input"],
            ),
        ),
        "CAPEC-3": Threat(
            SID="CAPEC-3",
            description="Cross-Site Scripting",
            details="An adversary injects malicious scripts into web pages.",
            severity="Medium",
            mapping=ThreatMapping(
                requirements=["renders_html"],
                mitigations=["escapes_output"],
            ),
        ),
    }

    components = {
        "WebServer": Component(
            name="WebServer",
            component_class="External",
            description="Frontend web server handling HTTP requests",
            inBoundary="DMZ",
            properties={
                "reads_input": True,
                "renders_html": True,
                "validates_input": True,
                "escapes_output": False,
            },
        ),
        "APIBackend": Component(
            name="APIBackend",
            component_class="Process",
            description="Backend API service processing business logic",
            inBoundary="Internal",
            properties={
                "reads_input": True,
                "uses_database": True,
                "validates_input": True,
                "uses_parameterized_queries": True,
            },
        ),
        "Database": Component(
            name="Database",
            component_class="Datastore",
            description="PostgreSQL database storing application data",
            inBoundary="Internal",
            properties={
                "stores_sensitive_data": True,
                "encrypted_at_rest": True,
            },
        ),
    }

    flows = [
        Flow(id="1", name="HTTP Request", source="WebServer", sink="APIBackend"),
        Flow(
            id="2",
            name="HTTP Response",
            source="APIBackend",
            sink="WebServer",
            is_response=True,
            response_to="1",
        ),
        Flow(id="3", name="SQL Query", source="APIBackend", sink="Database"),
        Flow(
            id="4",
            name="Query Result",
            source="Database",
            sink="APIBackend",
            is_response=True,
            response_to="3",
        ),
    ]

    scenarios = [
        Scenario(
            name="User Login",
            description="User authenticates via web form",
            file="scenarios/login.yaml",
            findings=[
                Finding(target="WebServer", threat_id="CAPEC-1"),
                Finding(target="WebServer", threat_id="CAPEC-3"),
                Finding(target="APIBackend", threat_id="CAPEC-2"),
            ],
            flows=flows,
            components=["WebServer", "APIBackend", "Database"],
        ),
        Scenario(
            name="Data Export",
            description="User exports data as CSV",
            file="scenarios/export.yaml",
            findings=[
                Finding(target="APIBackend", threat_id="CAPEC-2"),
            ],
            flows=[flows[2], flows[3]],
            components=["APIBackend", "Database"],
        ),
    ]

    properties = {
        "reads_input": Property(name="Reads Input", type="bool"),
        "validates_input": Property(name="Validates Input", type="bool"),
        "uses_database": Property(name="Uses Database", type="bool"),
        "uses_parameterized_queries": Property(
            name="Uses Parameterized Queries", type="bool"
        ),
        "renders_html": Property(name="Renders HTML", type="bool"),
        "escapes_output": Property(name="Escapes Output", type="bool"),
        "handles_binary_data": Property(name="Handles Binary Data", type="bool"),
        "uses_safe_functions": Property(name="Uses Safe Functions", type="bool"),
        "stores_sensitive_data": Property(name="Stores Sensitive Data", type="bool"),
        "encrypted_at_rest": Property(name="Encrypted at Rest", type="bool"),
    }

    model = ThreatModel(
        threats=threats,
        components=components,
        scenarios=scenarios,
        properties=properties,
    )
    # Prepare scenarios without graph generation (skip for tests)
    for scenario in model.scenarios:
        scenario.dfd = ""
        scenario.mermaid = ""
    return model


def render_template(env, template_name, context):
    """Helper to render a template and return the HTML."""
    template = env.get_template(template_name)
    return template.render(**context)


class TestIndexTemplate:
    def test_renders_without_error(self, jinja_env, sample_config, sample_model):
        """Index template renders with sample data."""
        html = render_template(
            jinja_env,
            "index.html",
            {
                "config": sample_config,
                "model": sample_model,
                "analysis": sample_model.analyze(),
            },
        )
        assert html
        assert "Test Threat Model" in html

    def test_shows_threat_count(self, jinja_env, sample_config, sample_model):
        """Index shows correct threat count."""
        analysis = sample_model.analyze()
        html = render_template(
            jinja_env,
            "index.html",
            {"config": sample_config, "model": sample_model, "analysis": analysis},
        )
        # Should show threats affecting us
        assert "Threats affecting us" in html

    def test_shows_scenarios(self, jinja_env, sample_config, sample_model):
        """Index lists all scenarios."""
        html = render_template(
            jinja_env,
            "index.html",
            {
                "config": sample_config,
                "model": sample_model,
                "analysis": sample_model.analyze(),
            },
        )
        assert "User Login" in html
        assert "Data Export" in html


class TestThreatsTemplate:
    def test_renders_without_error(self, jinja_env, sample_config, sample_model):
        """Threats template renders with sample data."""
        html = render_template(
            jinja_env,
            "threats.html",
            {
                "config": sample_config,
                "model": sample_model,
                "analysis": sample_model.analyze(),
                "all_threat_props": list(sample_model.properties),
            },
        )
        assert html
        assert "All Threats" in html

    def test_shows_severity_distribution(self, jinja_env, sample_config, sample_model):
        """Threats page shows severity distribution."""
        html = render_template(
            jinja_env,
            "threats.html",
            {
                "config": sample_config,
                "model": sample_model,
                "analysis": sample_model.analyze(),
                "all_threat_props": list(sample_model.properties),
            },
        )
        assert "Threats by Severity" in html


class TestThreatTemplate:
    def test_renders_for_each_threat(self, jinja_env, sample_config, sample_model):
        """Individual threat pages render correctly."""
        analysis = sample_model.analyze()
        scenario_by_name = sample_model.scenario_by_name()

        for threat_id, threat in sample_model.threats.items():
            html = render_template(
                jinja_env,
                "threat.html",
                {
                    "config": sample_config,
                    "model": sample_model,
                    "threat_id": threat_id,
                    "threat": threat,
                    "components": analysis["threats_to_components"].get(
                        threat_id, set()
                    ),
                    "scenarios": analysis["threats_to_scenarios"].get(threat_id, []),
                    "frequency": analysis["threat_counter"].get(threat_id, 0),
                    "threat_scenario_data": [],
                },
            )
            assert html
            assert threat_id in html
            assert threat.description in html


class TestComponentTemplate:
    def test_renders_for_each_component(self, jinja_env, sample_config, sample_model):
        """Individual component pages render correctly."""
        analysis = sample_model.analyze()

        for name, component in sample_model.components.items():
            threat_ids = analysis["components_to_threats"].get(name, set())
            html = render_template(
                jinja_env,
                "component.html",
                {
                    "config": sample_config,
                    "model": sample_model,
                    "comp_name": name,
                    "component": component,
                    "threats": threat_ids,
                    "scenarios": [],
                    "unimplemented_mitigations": sample_model.component_unimplemented_mitigations(
                        component, threat_ids
                    ),
                    "threat_unimplemented": {
                        tid: sample_model.threat_unimplemented_mitigations(
                            component, sample_model.threats[tid]
                        )
                        for tid in threat_ids
                        if tid in sample_model.threats
                    },
                    "component_name": re.sub(r"[^\w]", "_", name),
                },
            )
            assert html
            assert name in html
            if component.description:
                assert component.description in html


class TestComponentsTemplate:
    def test_renders_without_error(self, jinja_env, sample_config, sample_model):
        """Components list template renders."""
        html = render_template(
            jinja_env,
            "components.html",
            {"config": sample_config, "model": sample_model},
        )
        assert html


class TestPropertyTemplate:
    def test_renders_for_each_property(self, jinja_env, sample_config, sample_model):
        """Individual property pages render correctly."""
        for prop_key, prop in sample_model.properties.items():
            mitigated, would_mitigate, benefit = sample_model.property_mitigation_state(
                prop_key
            )
            slug = re.sub(r"[^\w]", "_", prop_key)
            html = render_template(
                jinja_env,
                "property.html",
                {
                    "config": sample_config,
                    "prop": prop_key,
                    "prop_slug": slug,
                    "data": {
                        "label": prop.name,
                        "display_label": prop_key.replace("_", " ")
                        .replace("!", "not ")
                        .title(),
                        "slug": slug,
                        "mitigated_threats": mitigated,
                        "would_be_mitigated_threats": would_mitigate,
                        "benefit_components": benefit,
                        "requiring_threats": [],
                    },
                },
            )
            assert html
            assert "Property:" in html


class TestScenarioTemplate:
    def test_renders_for_each_scenario(self, jinja_env, sample_config, sample_model):
        """Individual scenario pages render correctly."""
        for scenario in sample_model.scenarios:
            html = render_template(
                jinja_env,
                "scenario.html",
                {
                    "config": sample_config,
                    "model": sample_model,
                    "scenario": scenario,
                    "scenario_name": scenario.name.replace(" ", "_"),
                },
            )
            assert html
            assert scenario.name in html
            if scenario.description:
                assert scenario.description in html


class TestGeneratorTemplate:
    def test_renders_without_error(self, jinja_env, sample_config, sample_model):
        """Generator template renders with sample data."""
        html = render_template(
            jinja_env,
            "generator.html",
            {
                "config": sample_config,
                "all_threat_props": list(sample_model.properties),
                "threats_data": sample_model.threats_data(),
                "threats_sorted": sample_model.threats_sorted(),
            },
        )
        assert html
        assert "Threat Mapping Generator" in html


class TestIncludeTemplates:
    def test_components_table_renders(self, jinja_env, sample_config, sample_model):
        """Components table include renders via index."""
        html = render_template(
            jinja_env,
            "index.html",
            {
                "config": sample_config,
                "model": sample_model,
                "analysis": sample_model.analyze(),
            },
        )
        # Components table should show component names
        assert "WebServer" in html
        assert "APIBackend" in html
        assert "Database" in html

    def test_threats_table_renders(self, jinja_env, sample_config, sample_model):
        """Threats table include renders via threats page."""
        html = render_template(
            jinja_env,
            "threats.html",
            {
                "config": sample_config,
                "model": sample_model,
                "analysis": sample_model.analyze(),
                "all_threat_props": list(sample_model.properties),
            },
        )
        # Should show threat IDs
        assert "CAPEC-1" in html
        assert "CAPEC-2" in html
        assert "CAPEC-3" in html

    def test_findings_table_renders(self, jinja_env, sample_config, sample_model):
        """Findings table include renders via scenario page."""
        scenario = sample_model.scenarios[0]
        html = render_template(
            jinja_env,
            "scenario.html",
            {
                "config": sample_config,
                "model": sample_model,
                "scenario": scenario,
                "scenario_name": scenario.name.replace(" ", "_"),
            },
        )
        # Should show findings
        assert "CAPEC-1" in html
        assert "WebServer" in html


class TestViewFunctions:
    """Test that view functions work with sample data."""

    def test_all_views_callable(self, sample_config, sample_model):
        """All registered views can be called with sample data."""
        data = {"config": sample_config, "model": sample_model}

        for spec in VIEWS:
            result = _call_view(spec.func, data)
            items = _normalize_items(result)
            assert len(items) > 0, f"View {spec.func.__name__} returned no items"

            # Each item should have required template variables
            for item in items:
                assert "config" in item, (
                    f"View {spec.func.__name__} missing 'config'"
                )
