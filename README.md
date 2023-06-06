# Django Scan Access inspector

Django Access inspector is a Django app to scan access on an application views.

## Build

Run the following command:

    python setup.py sdist

## Installation

Run one of the following command:

    pip install django-access-inspector

    poetry add PATH_TO_THIS_REPO/dist/django_access_inspector-0.1.tar.gz

Add "django_access_inspector" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...,
        "django_access_inspector",
    ]
