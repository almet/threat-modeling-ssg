build: src/ratm/ssg/templates/assets/viz-global.js src/ratm/ssg/templates/assets/mermaid.min.js
	uv run demo/model.py | uv run ratm

src/ratm/ssg/templates/assets/viz-global.js src/ratm/ssg/templates/assets/mermaid.min.js: package.json
	npm install && npm run install-assets

regenerate:
	find . -type f -not -path './output/*' -not -path './.git/*' -not -path './node_modules/*' | entr -c make build

serve:
	python -m http.server -d output

test:
	PYTHONPATH=src uv run pytest

lint:
	uvx ruff check
	uvx ruff format --check

fix:
	uvx ruff check --fix
	uvx ruff format
