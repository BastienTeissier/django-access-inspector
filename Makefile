format:
	uv run ruff check --select I --fix && uv run ruff format

lint:
	uv run ruff check

lint-fix:
	uv run ruff check . --fix

typecheck:
	uv run mypy django_access_inspector/

test:
	uv run coverage run -m pytest --cov-fail-under=80

validate: lint typecheck test
	@echo "✅ All validation checks passed!"

coverage:
	uv run coverage report -m

check:
	uv run manage.py inspect_access_control

build:
	uv run -m build --sdist
	uv run -m build --wheel

deploy:
	uv run -m twine upload dist/*

inspector:
	npx @modelcontextprotocol/inspector

start_mcp:
	uv run manage.py start_mcp_server