import re
from collections import defaultdict

from .models import Component, Scenario

FONT_NAME = "Arial"
FONT_SIZE_GRAPH = 14
FONT_SIZE_NODE = 14
FONT_SIZE_EDGE = 12
FONT_SIZE_BOUNDARY = 10

NODE_SHAPES = {
    "Actor":          "square",
    "Process":        "circle",
    "ExternalEntity": "square",
    "Datastore":      "cylinder",
    "Server":         "box",
}


def generate_dfd(scenario: Scenario) -> str:
    """Generate a Graphviz DOT diagram from scenario components and flows."""

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
    all_nodes  = [c for c in scenario.components if c.component_class != "Boundary"]

    # Filter out components not linked to any flow
    linked_names = scenario.linked_component_names
    nodes = [c for c in all_nodes if c.name in linked_names]

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

    def boundary_has_content(name: str) -> bool:
        if nodes_by_boundary.get(name):
            return True
        return any(boundary_has_content(child) for child in boundary_children.get(name, []))

    def emit_boundary(name: str, indent: str = "    ") -> None:
        if not boundary_has_content(name):
            return
        lines.extend([
            f"{indent}subgraph cluster_boundary_{slug(name)} {{",
            f"{indent}    graph [",
            f"{indent}        fontsize = {FONT_SIZE_BOUNDARY};",
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
        f"        fontname = {FONT_NAME};",
        f"        fontsize = {FONT_SIZE_GRAPH};",
        "    ]",
        "    node [",
        f"        fontname = {FONT_NAME};",
        f"        fontsize = {FONT_SIZE_NODE};",
        "    ]",
        "    edge [",
        f"        fontname = {FONT_NAME};",
        f"        fontsize = {FONT_SIZE_EDGE};",
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

    for i, flow in enumerate(scenario.flows, 1):
        src = name_to_id.get(flow.source)
        snk = name_to_id.get(flow.sink)
        if src and snk:
            label = wrap_label(f"{i}. {flow.id}", width=20).replace('"', '\\"')
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


def generate_highlighted_dfd(dfd: str, highlight_components: set) -> str:
    """Modify a DOT graph string to highlight specific components by label."""
    if not highlight_components or not dfd:
        return dfd

    def highlighter(match):
        node_id = match.group(1)
        attrs = match.group(2)
        label_match = re.search(r'label\s*=\s*"([^"]*)"', attrs)
        label = label_match.group(1).replace("\\n", " ") if label_match else None
        if label and label in highlight_components:
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
