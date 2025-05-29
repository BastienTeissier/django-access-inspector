format:
	uv run ruff format

lint:
	uv run ruff check

lint-fix:
	uv run ruff check . --fix

typecheck:
	uv run mypy django_access_inspector/

test:
	uv run pytest

validate: lint typecheck test
	@echo "✅ All validation checks passed!"

check:
	uv run manage.py inspect_access_control

build:
	uv run -m build --sdist
	uv run -m build --wheel

deploy:
	uv run -m twine upload dist/*
