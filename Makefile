format:
	poetry run python -m black .

lint:
	poetry run ruff check .

lint-fix:
	poetry run ruff check . --fix

check:
	poetry run python manage.py inspect_access_control