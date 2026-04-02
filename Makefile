build: src/ssg_threatmodel/templates/assets/viz-global.js src/ssg_threatmodel/templates/assets/mermaid.min.js
	uv run ssg-threatmodel

src/ssg_threatmodel/templates/assets/viz-global.js src/ssg_threatmodel/templates/assets/mermaid.min.js: package.json
	npm install && npm run install-assets

regenerate:
	find . -type f -not -path './output/*' -not -path './.git/*' -not -path './node_modules/*' | entr -c make build

serve:
	python -m http.server -d output

test:
	PYTHONPATH=src uv run pytest
