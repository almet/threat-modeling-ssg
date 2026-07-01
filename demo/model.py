from ratm import Ratm
from ratm.components import Scenario

# [ Demo threat model ]
# ------------------------------------------------------------
# Exemple usage of ratm, describing its very own threat model.
# This is a simplistic example to showcase how the tool works
# and what can be accomplished with it.
#
# RATM is a tool that:
#
# - Let developers use python to define their threat model
# - Compiles the threat model and publishes it on a static site generator
# ------------------------------------------------------------

# create a threat model object that will be used afterwards
tm = Ratm(load_capec_info=False)

# A list of properties: (name, description, default, type)
tm.define_properties(
    ("loads_resources", "Loads resources external to the program.", tuple(), tuple),
    ("verifies_resources", "Verifies the resources before use.", tuple(), tuple),
    ("uses_network", "The component uses the network stack"),
    ("is_exposed", "The component is considered exposed to the attacker"),
    ("is_physical", "The component is a physical one"),
    ("requires_credentials", "The component requires credentials to connect"),
    (
        "uses_strong_credentials",
        "The credentials are strong (2FA with OTP, certificates)",
    ),
    ("publishes_code", "The component publishes code"),
)


# You can define your own threats, naming them and providing:
#
# - a list of requirements, that need to be true for this threat to apply
# - a list of mitigations. If any of these are true, the threat is considered mitigated.
#

# In this example, we use sub-resources, using the dot separator.
tm.Threat(
    "RATM-1-DEPS",
    requirements=["loads_resources.deps"],
    mitigations=["verifies_resources.deps"],
    comment="Check that every component that explicitly loads packages verify them",
)
tm.Threat(
    "RATM-1-DEPS",
    requirements=["loads_resources.deps"],
    mitigations=["verifies_resources.deps"],
    comment="Check that every component that explicitly loads packages verify them",
)


# -- Boundaries

THE_INTERNET = tm.Boundary(
    name="Internet",
    # Define your own properties here
    uses_network=True,
    is_exposed=True,
)

DEV_HOST = tm.Boundary(
    name="Dev host",
    uses_network=True,
    is_physical=True,
)

USER_HOST = tm.Boundary(
    name="User host",
    # You can define an array of resources loaded by a boundary
    loads_resources=["system", "files"],
)

# -- Actors

USER = tm.Actor(name="User", boundary=USER_HOST)
DEV = tm.Actor(name="Developer", boundary=THE_INTERNET)

# -- Components

DEV_MACHINE = tm.Component(name="Dev machine", is_physical=True, boundary=DEV_HOST)

BROWSER = tm.Component(
    name="Browser of the visitor of the threat model",
    boundary=USER_HOST,
    uses_network=True,
)

PYPI = tm.Component(
    name="PyPI servers",
    boundary=THE_INTERNET,
    requires_credentials=True,
    uses_strong_credentials=True,
    publishes_code=True,
)

NPM = tm.Component(
    name="NPM servers",
    boundary=THE_INTERNET,
    requires_credentials=True,
    uses_strong_credentials=True,
    publishes_code=True,
)

PYTHON_PACKAGE = tm.Component(
    name="pytm python package",
    loads_resources=["deps"],
)
# -- Scenarios
# 1. Publishing to PyPI servers (building npm packages)
# 2. Running the pipeline

release = Scenario(name="Release", description="Build and release the ratm package")

release.Dataflow(
    name="Kick off release build",
    description="A dev decides to build and release",
    source=DEV,
    sink=DEV_MACHINE,
)

release.Dataflow(
    name="Gather JS deps",
    description="Get JavaScript dependencies from NPM",
    source=DEV_MACHINE,
    sink=NPM,
)

release.Dataflow(
    name="Gather python deps",
    description="Get python dependencies from PyPI",
    source=DEV_MACHINE,
    sink=PYPI,
)
release.Dataflow(
    name="Vendorize JS deps",
    description="Vendorize the JS dependencies in the python package",
    source=DEV_MACHINE,
    sink=PYTHON_PACKAGE,
)

release.Dataflow(
    name="Publish on PyPI",
    description="Publish the local package on PyPI",
    source=PYTHON_PACKAGE,
    sink=PYTHON_PACKAGE,
)

# And finally, your scenarios

if __name__ == "__main__":
    report = tm.Report(
        [
            release,
        ]
    )
    out = report.generate()
    import json

    print(json.dumps(out, indent=4, sort_keys=True))
