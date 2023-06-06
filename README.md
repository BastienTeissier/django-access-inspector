# Django Access Inspector

Django Access Inspector is a comprehensive access control app for Django that helps you enforce fine-grained access control on your views. It provides a flexible and easy-to-use interface to check and analyze authentication and permission classes for each view in your Django project.

## Installation

Run one of the following command:

```
pip install django-access-inspector
```

```
poetry add django-access-inspector
```

Add "django_access_inspector" to your INSTALLED_APPS setting like this:

    INSTALLED_APPS = [
        ...,
        "django_access_inspector",
    ]

## Run

```
python manage.py inspect_access_control
```
