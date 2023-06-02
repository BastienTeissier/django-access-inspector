import json
import re

from django.conf import settings
from django.core.exceptions import ViewDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.urls import URLPattern, URLResolver  # type: ignore
from django.utils import translation
from rich.console import Console
from rich.table import Table
from rich.text import Text


class RegexURLPattern:  # type: ignore
    pass


class RegexURLResolver:  # type: ignore
    pass


class LocaleRegexURLResolver:  # type: ignore
    pass


def describe_pattern(p):
    return str(p.pattern)


class Command(BaseCommand):
    help = "Displays all of the url matching routes for the project."

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--output",
            dest="output",
            default="cli",
            help="Set the settings URL conf variable to use",
        )

    def handle(self, *args, **options):
        urlconf = "ROOT_URLCONF"

        views = {}
        unchecked_views = []
        if not hasattr(settings, urlconf):
            raise CommandError(
                "Settings module {} does not have the attribute {}.".format(
                    settings, urlconf
                )
            )

        try:
            urlconf = __import__(getattr(settings, urlconf), {}, {}, [""])
        except Exception as e:
            raise CommandError(
                "Error occurred while trying to load %s: %s"
                % (getattr(settings, urlconf), str(e))
            )

        view_functions = self.extract_views_from_urlpatterns(urlconf.urlpatterns)

        for func, _, url_name in view_functions:
            permissions = []
            authentications = []
            if url_name is not None and hasattr(views, url_name):
                permissions = views[url_name].get("permission_classes", [])

            if hasattr(func, "view_class"):
                permissions.extend(
                    [
                        permission_class.__name__
                        for permission_class in getattr(
                            func.view_class, "permission_classes", []
                        )
                    ]
                )
                authentications.extend(
                    [
                        authentication_class.__name__
                        for authentication_class in getattr(
                            func.view_class, "authentication_classes", []
                        )
                    ]
                )
            elif hasattr(func, "cls"):
                permissions.extend(
                    [
                        permission_class.__name__
                        for permission_class in getattr(
                            func.cls, "permission_classes", []
                        )
                    ]
                )
                authentications.extend(
                    [
                        authentication_class.__name__
                        for authentication_class in getattr(
                            func.cls, "authentication_classes", []
                        )
                    ]
                )
            elif hasattr(func, "initkwargs"):
                permissions.extend(
                    [
                        permission_class.__name__
                        for permission_class in getattr(
                            func.initkwargs, "permission_classes", []
                        )
                    ]
                )
                authentications.extend(
                    [
                        authentication_class.__name__
                        for authentication_class in getattr(
                            func.initkwargs, "authentication_classes", []
                        )
                    ]
                )
            else:
                func_name = func
                if hasattr(func, "__name__"):
                    func_name = func.__name__
                elif hasattr(func, "__class__"):
                    func_name = "%s()" % func.__class__.__name__
                else:
                    func_name = re.sub(r" at 0x[0-9a-f]+", "", repr(func))

                unchecked_views.append(f"{url_name} / {func_name}")

            views[url_name] = {
                "permissions_classes": list(set(permissions)),
                "authentication_classes": list(set(authentications)),
            }

        split_views = self.split_views(views)

        if options["output"] == "json":
            print(
                json.dumps({"views": split_views, "unchecked_views": unchecked_views})
            )
        else:
            self.print_views_in_terminal(views, unchecked_views)
            console = Console()
            console.print(
                Text(
                    f"Authenticated views: {len(split_views['authenticated'])}",
                    style="bold green",
                )
            )
            console.print(
                Text(
                    f"Unauthenticated views: {len(split_views['unauthenticated'])}",
                    style="bold red",
                )
            )
            console.print(
                Text(f"Unchecked views: {len(unchecked_views)}", style="bold red")
            )

    def print_views_in_terminal(self, views, unchecked_views):
        console = Console()

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("View")
        table.add_column("Permission Classes")
        table.add_column("Authentication Classes")
        for url, perm in views.items():
            if url is not None:
                permissions = Text("None", style="bold red")
                if len(perm.get("permissions_classes", 0)) > 0:
                    permissions = Text(", ".join(perm["permissions_classes"]))
                authentications = Text("None", style="bold red")
                if len(perm.get("authentication_classes", 0)) > 0:
                    authentications = Text(", ".join(perm["authentication_classes"]))
                table.add_row(
                    Text(url, style="bold blue"), permissions, authentications
                )

        console.print(table)

    def split_views(self, views):
        authenticated = {}
        unauthenticated = {}
        for url, perm in views.items():
            if (
                len(perm.get("authentication_classes", 0)) > 0
                or len(perm.get("permissions_classes", 0)) > 0
            ):
                authenticated[url] = perm
            else:
                unauthenticated[url] = perm
        return {"authenticated": authenticated, "unauthenticated": unauthenticated}

    def extract_views_from_urlpatterns(self, urlpatterns, base="", namespace=None):
        """
        Return a list of views from a list of urlpatterns.
        Each object in the returned list is a three-tuple: (view_func, regex, name)
        """
        views = []
        for p in urlpatterns:
            if isinstance(p, (URLPattern, RegexURLPattern)):
                try:
                    if not p.name:
                        name = p.name
                    elif namespace:
                        name = "{0}:{1}".format(namespace, p.name)
                    else:
                        name = p.name
                    pattern = describe_pattern(p)
                    views.append((p.callback, base + pattern, name))
                except ViewDoesNotExist:
                    continue
            elif isinstance(p, (URLResolver, RegexURLResolver)):
                try:
                    patterns = p.url_patterns
                except ImportError:
                    continue
                if namespace and p.namespace:
                    _namespace = "{0}:{1}".format(namespace, p.namespace)
                else:
                    _namespace = p.namespace or namespace
                pattern = describe_pattern(p)
                if isinstance(p, LocaleRegexURLResolver):
                    for language in self.LANGUAGES:
                        with translation.override(language[0]):
                            views.extend(
                                self.extract_views_from_urlpatterns(
                                    patterns, base + pattern, namespace=_namespace
                                )
                            )
                else:
                    views.extend(
                        self.extract_views_from_urlpatterns(
                            patterns, base + pattern, namespace=_namespace
                        )
                    )
            elif hasattr(p, "_get_callback"):
                try:
                    views.append(
                        (p._get_callback(), base + describe_pattern(p), p.name)
                    )
                except ViewDoesNotExist:
                    continue
            elif hasattr(p, "url_patterns") or hasattr(p, "_get_url_patterns"):
                try:
                    patterns = p.url_patterns
                except ImportError:
                    continue
                views.extend(
                    self.extract_views_from_urlpatterns(
                        patterns, base + describe_pattern(p), namespace=namespace
                    )
                )
            else:
                raise TypeError("%s does not appear to be a urlpattern object" % p)
        return views
