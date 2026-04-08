import pytest

from ssg_threatmodel.models import (
    Component,
    Finding,
    Flow,
    Property,
    Scenario,
    Threat,
    ThreatMapping,
    ThreatModel,
)


@pytest.fixture()
def model_factory():
    def _make(threats, components, scenarios, properties=None):
        return ThreatModel(
            threats=threats,
            components=components,
            scenarios=scenarios,
            properties=properties or {},
        )

    return _make


FLOW_A_B = Flow(id="1", name="A to B", source="A", sink="B")


def test_component_threats(model_factory) -> None:
    model = model_factory(
        threats={"T1": Threat(SID="T1"), "T2": Threat(SID="T2")},
        components={
            "A": Component(name="A", component_class="Process"),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[Finding(target="A", threat_id="T1"), Finding(target="B", threat_id="T2")],
                flows=[FLOW_A_B],
            )
        ],
    )
    analysis = model.analyze()
    assert analysis["components_to_threats"].get("A", set()) == {"T1"}
    assert analysis["components_to_threats"].get("B", set()) == {"T2"}


def test_threat_affected_components(model_factory) -> None:
    model = model_factory(
        threats={"T1": Threat(SID="T1"), "T2": Threat(SID="T2")},
        components={
            "A": Component(name="A", component_class="Process"),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[Finding(target="A", threat_id="T1"), Finding(target="B", threat_id="T1")],
                flows=[FLOW_A_B],
            )
        ],
    )
    analysis = model.analyze()
    assert analysis["threats_to_components"].get("T1", set()) == {"A", "B"}
    assert analysis["threats_to_components"].get("T2", set()) == set()


def test_threat_linked_scenarios(model_factory) -> None:
    model = model_factory(
        threats={"T1": Threat(SID="T1"), "T2": Threat(SID="T2")},
        components={
            "A": Component(name="A", component_class="Process"),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[Finding(target="A", threat_id="T1")],
                flows=[FLOW_A_B],
            ),
            Scenario(
                name="S2",
                findings=[Finding(target="B", threat_id="T2")],
                flows=[Flow(id="1", name="B to A", source="B", sink="A")],
            ),
        ],
    )
    analysis = model.analyze()
    assert analysis["threats_to_scenarios"].get("T1", []) == ["S1"]
    assert analysis["threats_to_scenarios"].get("T2", []) == ["S2"]


def test_threat_mapping_base_props() -> None:
    mapping = ThreatMapping(
        requirements=["loads_resources.images", "reads_input"],
        mitigations=["verifies_resources.images", "is_trusted"],
    )
    assert mapping.requirement_props == {"loads_resources", "reads_input"}
    assert mapping.mitigation_props == {"verifies_resources", "is_trusted"}


def test_threat_mapping_for_prop() -> None:
    mapping = ThreatMapping(
        requirements=["loads_resources.images", "loads_resources.deps", "reads_input"],
        mitigations=["verifies_resources.images", "is_trusted"],
    )
    assert mapping.requirements_for_prop("loads_resources") == [
        "loads_resources.images", "loads_resources.deps"
    ]
    assert mapping.requirements_for_prop("reads_input") == ["reads_input"]
    assert mapping.requirements_for_prop("other") == []
    assert mapping.mitigations_for_prop("verifies_resources") == ["verifies_resources.images"]
    assert mapping.mitigations_for_prop("is_trusted") == ["is_trusted"]
    assert mapping.mitigations_for_prop("other") == []


def test_property_mitigates_threats(model_factory) -> None:
    model = model_factory(
        threats={
            "T1": Threat(SID="T1", mapping=ThreatMapping(
                requirements=["reads_input"], mitigations=["sanitizes_input"]
            )),
        },
        components={
            "A": Component(name="A", component_class="Process",
                           properties={"reads_input": True, "sanitizes_input": True}),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[Finding(target="A", threat_id="T1")],
                flows=[FLOW_A_B],
            )
        ],
        properties={
            "reads_input": Property(name="Reads input", type="bool"),
            "sanitizes_input": Property(name="Sanitizes input", type="bool"),
        },
    )
    mitigated, would_mitigate, _ = model.property_mitigation_state("sanitizes_input")
    assert [tid for tid, _ in mitigated] == ["T1"]
    assert [tid for tid, _ in would_mitigate] == []


def test_property_would_mitigate_threats(model_factory) -> None:
    model = model_factory(
        threats={
            "T1": Threat(SID="T1", mapping=ThreatMapping(
                requirements=["reads_input"], mitigations=["sanitizes_input"]
            )),
        },
        components={
            "A": Component(name="A", component_class="Process",
                           properties={"reads_input": True, "sanitizes_input": False}),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[Finding(target="A", threat_id="T1")],
                flows=[FLOW_A_B],
            )
        ],
        properties={
            "reads_input": Property(name="Reads input", type="bool"),
            "sanitizes_input": Property(name="Sanitizes input", type="bool"),
        },
    )
    mitigated, would_mitigate, _ = model.property_mitigation_state("sanitizes_input")
    assert [tid for tid, _ in mitigated] == []
    assert [tid for tid, _ in would_mitigate] == ["T1"]


def test_property_mitigation_state_dotted(model_factory) -> None:
    """Dotted mitigations: component with correct sub-item is mitigated, wrong sub-item is not."""
    model = model_factory(
        threats={
            "T-dotted-ok": Threat(SID="T-dotted-ok", mapping=ThreatMapping(
                requirements=["loads_resources.system"],
                mitigations=["verifies_resources.system"],
            )),
            "T-dotted-miss": Threat(SID="T-dotted-miss", mapping=ThreatMapping(
                requirements=["loads_resources.images"],
                mitigations=["verifies_resources.images"],
            )),
        },
        components={
            "Covered": Component(name="Covered", component_class="Process",
                                 properties={"loads_resources": ["system"],
                                             "verifies_resources": ["system"]}),
            "Affected": Component(name="Affected", component_class="Process",
                                  properties={"loads_resources": ["images"],
                                              "verifies_resources": ["updates"]}),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[
                    Finding(target="Covered", threat_id="T-dotted-ok"),
                    Finding(target="Affected", threat_id="T-dotted-miss"),
                ],
                flows=[Flow(id="1", name="Covered to Affected",
                            source="Covered", sink="Affected")],
            )
        ],
        properties={
            "loads_resources": Property(name="Loads resources", type="list"),
            "verifies_resources": Property(name="Verifies resources", type="list"),
        },
    )
    mitigated, would_mitigate, _ = model.property_mitigation_state("verifies_resources")
    assert [tid for tid, _ in mitigated] == ["T-dotted-ok"]
    assert [tid for tid, _ in would_mitigate] == ["T-dotted-miss"]


def test_property_requiring_threats(model_factory) -> None:
    """Active threats that have the property in their requirements show up for the property page."""
    model = model_factory(
        threats={
            "T-active": Threat(SID="T-active", mapping=ThreatMapping(
                requirements=["loads_resources.system"],
                mitigations=["verifies_resources.system"],
            )),
            "T-inactive": Threat(SID="T-inactive", mapping=ThreatMapping(
                requirements=["loads_resources.images"],
                mitigations=["verifies_resources.images"],
            )),
        },
        components={
            "A": Component(name="A", component_class="Process",
                           properties={"loads_resources": ["system"]}),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[Finding(target="A", threat_id="T-active")],
                flows=[FLOW_A_B],
            )
        ],
        properties={
            "loads_resources": Property(name="Loads resources", type="list"),
        },
    )
    analysis = model.analyze()
    requiring = [
        tid for tid, t in model.threats.items()
        if tid in analysis["threat_counter"]
        and "loads_resources" in t.mapping.requirement_props
    ]
    assert requiring == ["T-active"]


def test_is_mitigated_no_mitigations() -> None:
    """A threat with no mitigations defined is never considered mitigated."""
    threat = Threat(SID="T1", mapping=ThreatMapping(mitigations=[]))
    comp = Component(name="X", properties={"anything": True})
    assert threat.is_mitigated(comp) is False


def test_is_mitigated_boolean() -> None:
    """Boolean mitigation: True = mitigated, False or missing = not mitigated."""
    threat = Threat(SID="T1", mapping=ThreatMapping(mitigations=["is_sandboxed"]))
    assert threat.is_mitigated(Component(name="X", properties={"is_sandboxed": True})) is True
    assert threat.is_mitigated(Component(name="X", properties={"is_sandboxed": False})) is False
    assert threat.is_mitigated(Component(name="X", properties={})) is False


def test_is_mitigated_dotted() -> None:
    """Dotted mitigation: correct sub-item = mitigated, wrong or missing sub-item = not mitigated."""
    threat = Threat(SID="T1", mapping=ThreatMapping(
        requirements=["loads_resources.images"],
        mitigations=["verifies_resources.images"],
    ))
    assert threat.is_mitigated(
        Component(name="X", properties={"verifies_resources": ["images"]})
    ) is True
    assert threat.is_mitigated(
        Component(name="X", properties={"verifies_resources": ["updates"]})
    ) is False
    assert threat.is_mitigated(
        Component(name="X", properties={"verifies_resources": None})
    ) is False
    assert threat.is_mitigated(Component(name="X", properties={})) is False


def test_is_mitigated_any_one_is_enough() -> None:
    """Any single satisfied mitigation is enough; not all are required."""
    threat = Threat(SID="T1", mapping=ThreatMapping(
        requirements=["loads_resources.system"],
        mitigations=["is_trusted", "verifies_resources.system"],
    ))
    # Neither satisfied
    assert threat.is_mitigated(Component(name="X", properties={})) is False
    # Only the boolean one satisfied
    assert threat.is_mitigated(
        Component(name="X", properties={"is_trusted": True})
    ) is True
    # Only the dotted one satisfied
    assert threat.is_mitigated(
        Component(name="X", properties={"verifies_resources": ["system"]})
    ) is True
    # Both satisfied
    assert threat.is_mitigated(
        Component(name="X", properties={"is_trusted": True, "verifies_resources": ["system"]})
    ) is True


def test_threat_unimplemented_boolean(model_factory) -> None:
    """Boolean mitigation: True = implemented, False or missing = unimplemented."""
    threat = Threat(SID="T1", mapping=ThreatMapping(mitigations=["is_sandboxed"]))
    model = model_factory(
        threats={"T1": threat},
        components={},
        scenarios=[],
    )
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={"is_sandboxed": True}), threat
    ) == []
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={"is_sandboxed": False}), threat
    ) == ["is_sandboxed"]
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={}), threat
    ) == ["is_sandboxed"]


def test_threat_unimplemented_dotted(model_factory) -> None:
    """Dotted mitigation: correct sub-item = implemented, wrong or missing = unimplemented."""
    threat = Threat(SID="T1", mapping=ThreatMapping(
        requirements=["loads_resources.images"],
        mitigations=["verifies_resources.images"],
    ))
    model = model_factory(
        threats={"T1": threat},
        components={},
        scenarios=[],
    )
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={"verifies_resources": ["images"]}), threat
    ) == []
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={"verifies_resources": ["updates"]}), threat
    ) == ["verifies_resources.images"]
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={"verifies_resources": None}), threat
    ) == ["verifies_resources.images"]
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={}), threat
    ) == ["verifies_resources.images"]


def test_threat_unimplemented_multiple(model_factory) -> None:
    """Multiple mitigations: returns only the unimplemented ones."""
    threat = Threat(SID="T1", mapping=ThreatMapping(
        requirements=["loads_resources.system"],
        mitigations=["is_trusted", "verifies_resources.system"],
    ))
    model = model_factory(
        threats={"T1": threat},
        components={},
        scenarios=[],
    )
    # Neither mitigation implemented
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={}), threat
    ) == ["is_trusted", "verifies_resources.system"]

    # Only is_trusted implemented
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={"is_trusted": True}), threat
    ) == ["verifies_resources.system"]

    # Only verifies_resources.system implemented
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={"verifies_resources": ["system"]}), threat
    ) == ["is_trusted"]

    # Both implemented
    assert model.threat_unimplemented_mitigations(
        Component(name="X", properties={"is_trusted": True, "verifies_resources": ["system"]}),
        threat,
    ) == []
