from collections.abc import Iterable
from typing import Any

from .graphs import generate_highlighted_dataflow
from .models import SiteConfig, ThreatModel
from .utils import view, slugify


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
        scenario_names = list(dict.fromkeys(
            s.name for s in model.scenarios
            if name in s.linked_component_names or name in s.components
        ))
        yield {
            "config": config,
            "model": model,
            "comp_name": name,
            "component": component,
            "threats": threat_ids,
            "scenarios": scenario_names,
            "unimplemented_mitigations": model.component_unimplemented_mitigations(component, threat_ids),
            "threat_unimplemented": {
                tid: model.threat_unimplemented_mitigations(component, model.threats[tid])
                for tid in threat_ids if tid in model.threats
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
            ((tid, t) for tid, t in model.threats.items()
             if tid in analysis["threat_counter"] and prop_key in t.mapping.requirement_props),
            key=lambda x: x[0],
        )
        slug = slugify(prop_key)
        yield {
            "config": config,
            "prop": prop_key,
            "prop_slug": slug,
            "data": {
                "label": prop.name,
                "display_label": prop_key.replace("_", " ").replace("!", "not ").title(),
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
