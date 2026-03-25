import re

from .models import Scenario


def generate_mermaid(scenario: Scenario) -> str:
    if not scenario.flows:
        return ""

    def alias(name: str) -> str:
        return re.sub(r"[^\w]", "_", name)

    seen: set = set()
    participants: list = []
    for flow in scenario.flows:
        for name in (flow.source, flow.sink):
            if name not in seen:
                participants.append(name)
                seen.add(name)

    lines = ["sequenceDiagram"]
    for name in participants:
        lines.append(f"    participant {alias(name)} as {name}")
    lines.append("")
    for i, flow in enumerate(scenario.flows, 1):
        arrow = "-->>" if flow.is_response else "->>"
        lines.append(f"    {alias(flow.source)}{arrow}{alias(flow.sink)}: {i}. {flow.id}")

    return "\n".join(lines)
