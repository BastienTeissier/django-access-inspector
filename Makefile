format:
	uv run ruff format

lint:
	uv run ruff check

lint-fix:
	uv run ruff check . --fix

check:
	uv run manage.py inspect_access_control

build:
	uv run -m build --sdist
	uv run -m build --wheel

deploy:
	uv run -m twine upload dist/*

sca:
	uv run safety scan
