---
name: django-access-audit
description: Audit Django endpoint security using django-access-inspector CLI.
---

# Django Access Audit

Analyze Django endpoint authentication and permission configurations, classify risk per endpoint, and generate a structured security report.

## Workflow

1. **Run the CLI** to collect endpoint data
2. **Analyze** the JSON output
3. **Generate** a structured security report

## Step 1: Run the CLI

Execute the management command to get JSON output:

```bash
python manage.py inspect_access_control --output json
```

For CI mode with snapshot comparison:

```bash
python manage.py inspect_access_control --ci --snapshot <snapshot.json> --output json
```

### Error handling

- If the command is not found: tell the user to install with `pip install django-access-inspector` and add `"django_access_inspector"` to `INSTALLED_APPS`
- If no endpoints are found (empty JSON): report "No endpoints found" and stop

## Step 2: Analyze Results

Parse the JSON output and for each unauthenticated or unchecked endpoint:

1. Identify the file containing the view function
2. Read the file to understand the endpoint's logic
3. Access other relevant files (models, serializers, etc.) as needed
4. Classify the endpoint's risk: **critical**, **high**, **medium**, **low**
5. Identify missing or weak authentication / permission classes
6. Spot dangerous HTTP methods (e.g., unauthenticated POST/PUT/DELETE)

If all endpoints are properly secured, report "No insecure endpoints found" and stop.

## Step 3: Generate Report

Respond in concise, technical language. Output in this structure:

### Security Assessment
One-sentence overall assessment.

### Critical Issues
Bullet list of endpoints needing immediate attention, or "None".

### Recommendations
Bullet list of specific code or config changes:
- Recommend concrete DRF/Django fixes (decorators, mixins, settings)
- Prioritize from highest to lowest severity

### Code Examples
Concise, runnable fix snippets — only what is necessary.

### Best Practices
Bullet list of broader security advice for the project.
