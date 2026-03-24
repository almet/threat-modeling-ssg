build: templates/assets/viz-global.js templates/assets/mermaid.min.js
	uv run --with pydantic --with jinja2 generate.py

templates/assets/viz-global.js templates/assets/mermaid.min.js: package.json
	npm install && npm run install-assets

regenerate:
	find . -type f -not -path './output/*' -not -path './.git/*' -not -path './node_modules/*' | entr -c make build

serve:
	python -m http.server -d output
