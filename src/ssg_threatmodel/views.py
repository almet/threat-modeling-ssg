import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from .graphs import generate_highlighted_dataflow
from .models import SiteConfig, ThreatModel, _token_satisfied
from .utils import slugify, view


@view("/index.html", log="Generating index.html...")
def summary_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    return {"config": config, "model": model, "analysis": model.analyze()}


@view("/threats.html", log="Generating threats.html...")
def threats_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    return {
        "config": config,
        "model": model,
        "analysis": model.analyze(),
        "all_threat_props": list(model.properties),
    }


@view(
    "/threat_{threat_id}.html",
    template="threat.html",
    log=lambda count: f"Generating {count} threat pages...",
)
def threat_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    analysis = model.analyze()
    scenario_by_name = model.scenario_by_name()
    for threat_id, threat in model.threats.items():
        scenario_names = analysis["threats_to_scenarios"].get(threat_id, [])
        affected_components = analysis["threats_to_components"].get(threat_id, set())
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
        yield {
            "config": config,
            "model": model,
            "threat_id": threat_id,
            "threat": threat,
            "components": affected_components,
            "scenarios": scenario_names,
            "frequency": analysis["threat_counter"].get(threat_id, 0),
            "threat_scenario_data": threat_scenario_data,
        }


@view(
    "/component_{component_name}.html",
    template="component.html",
    log=lambda count: f"Generating {count} component pages...",
)
def component_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    analysis = model.analyze()
    for name, component in model.components.items():
        threat_ids = analysis["components_to_threats"].get(name, set())
        scenario_names = list(
            dict.fromkeys(
                s.name
                for s in model.scenarios
                if name in s.linked_component_names or name in s.components
            )
        )
        yield {
            "config": config,
            "model": model,
            "comp_name": name,
            "component": component,
            "threats": threat_ids,
            "scenarios": scenario_names,
            "unimplemented_mitigations": model.component_unimplemented_mitigations(
                component, threat_ids
            ),
            "threat_unimplemented": {
                tid: model.threat_unimplemented_mitigations(
                    component, model.threats[tid]
                )
                for tid in threat_ids
                if tid in model.threats
            },
            "component_name": slugify(name),
        }


@view("/components.html", log="Generating components.html...")
def components_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    return {"config": config, "model": model}


@view(
    "/property_{prop_slug}.html",
    template="property.html",
    log=lambda count: f"Generating {count} property pages...",
)
def property_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    analysis = model.analyze()
    for prop_key, prop in model.properties.items():
        mitigated_threats, would_be_mitigated_threats, benefit_components = (
            model.property_mitigation_state(prop_key)
        )
        requiring_threats = sorted(
            (
                (tid, t)
                for tid, t in model.threats.items()
                if tid in analysis["threat_counter"]
                and prop_key in t.mapping.requirement_props
            ),
            key=lambda x: x[0],
        )
        slug = slugify(prop_key)
        yield {
            "config": config,
            "prop": prop_key,
            "prop_slug": slug,
            "data": {
                "label": prop.name,
                "display_label": (
                    prop_key.replace("_", " ").replace("!", "not ").title()
                ),
                "slug": slug,
                "mitigated_threats": mitigated_threats,
                "would_be_mitigated_threats": would_be_mitigated_threats,
                "benefit_components": benefit_components,
                "requiring_threats": requiring_threats,
            },
        }


@view(
    "/scenario_{scenario_name}.html",
    template="scenario.html",
    log=lambda count: f"Generating {count} scenario pages...",
)
def scenario_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    for scenario in model.scenarios:
        yield {
            "config": config,
            "model": model,
            "scenario": scenario,
            "scenario_name": scenario.name.replace(" ", "_"),
        }


@view("/threats_components.html", log="Generating threats_components.html...")
def threats_components_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    analysis = model.analyze()

    severity_order = {"Very High": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}

    def sort_key(item: tuple[str, Any]) -> tuple[int, int]:
        tid, threat = item
        sev = severity_order.get(threat.severity or "Unknown", 4)
        match = re.search(r"\d+", tid)
        return (sev, int(match.group()) if match else 0)

    active_threats = sorted(
        [
            (tid, t)
            for tid, t in model.threats.items()
            if tid in analysis["threat_counter"]
        ],
        key=sort_key,
    )

    def _fmt(tok: str) -> str:
        return tok.replace("_", " ").replace(".", ": ")

    affected_comp_names: set[str] = set()
    status: dict[str, dict[str, dict]] = {}
    for tid, threat in active_threats:
        status[tid] = {}
        for comp_name, comp in model.components.items():
            if threat.applies_to(comp):
                affected_comp_names.add(comp_name)
                satisfied = [t for t in threat.mapping.mitigations if _token_satisfied(comp, t)]
                missing = [t for t in threat.mapping.mitigations if not _token_satisfied(comp, t)]
                status[tid][comp_name] = {
                    "mitigated": bool(satisfied),
                    "satisfied": ", ".join(_fmt(t) for t in satisfied),
                    "missing": ", ".join(_fmt(t) for t in missing),
                }

    sorted_components = sorted(
        [
            (name, comp)
            for name, comp in model.components.items()
            if name in affected_comp_names
        ],
        key=lambda x: (x[1].component_class, x[0]),
    )

    class_counter = Counter(
        comp.component_class or "Other" for _, comp in sorted_components
    )

    return {
        "config": config,
        "active_threats": active_threats,
        "sorted_components": sorted_components,
        "component_classes": class_counter,
        "status": status,
    }


@view("/stats.html", log="Generating stats.html...")
def stats_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    analysis = model.analyze()
    active_threat_ids = set(analysis["threat_counter"])

    # Mitigation coverage across all threat-component pairs
    mitigated = 0
    unmitigated = 0
    for tid in active_threat_ids:
        threat = model.threats.get(tid)
        if not threat:
            continue
        for comp in model.components.values():
            if threat.applies_to(comp):
                if threat.is_mitigated(comp):
                    mitigated += 1
                else:
                    unmitigated += 1

    # Most affected components (by number of distinct threats)
    comp_threat_counts = Counter(
        {name: len(tids) for name, tids in analysis["components_to_threats"].items()}
    )

    # Threats with no mitigations defined
    unmapped = sorted(
        tid
        for tid in active_threat_ids
        if tid in model.threats and not model.threats[tid].mapping.mitigations
    )

    return {
        "config": config,
        "model": model,
        "analysis": analysis,
        "mitigated": mitigated,
        "unmitigated": unmitigated,
        "total_pairs": mitigated + unmitigated,
        "most_affected_components": comp_threat_counts.most_common(10),
        "unmapped_threats": unmapped,
    }


@view("/generator.html", log="Generating generator.html...")
def generator_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    return {
        "config": config,
        "all_threat_props": list(model.properties),
        "threats_data": model.threats_data(),
        "threats_sorted": model.threats_sorted(),
    }
