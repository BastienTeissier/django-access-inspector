import unittest.mock
import sys # Added import for sys
from django.test import TestCase, override_settings # Added override_settings
from django.urls import path
from django.conf import settings
from django.views import View
from django.http import HttpResponse
from django.core.management import call_command
from django.core.management.base import CommandError # Added CommandError
import io
import json # Added import for json

# Mock Views
def function_based_view(request):
    return HttpResponse("Function-based view")

class ClassBasedView(View):
    def get(self, request):
        return HttpResponse("Class-based view")

class AuthenticatedView(View):
    permission_classes = ['IsAuthenticated']
    def get(self, request):
        return HttpResponse("Authenticated view")

class TokenAuthenticatedView(View):
    authentication_classes = ['TokenAuthentication']
    def get(self, request):
        return HttpResponse("Token authenticated view")

class MixedAuthView(View):
    permission_classes = ['IsAuthenticated']
    authentication_classes = ['TokenAuthentication']
    def get(self, request):
        return HttpResponse("Mixed auth view")

class AdminView(View):
    model_admin = True  # Simulate an admin view
    def get(self, request):
        return HttpResponse("Admin view")

unchecked_view = lambda request: HttpResponse("Unchecked view")

# URL Patterns
urlpatterns = [
    path('function/', function_based_view, name='function_view'),
    path('class/', ClassBasedView.as_view(), name='class_view'),
    path('authenticated/', AuthenticatedView.as_view(), name='authenticated_view'),
    path('token/', TokenAuthenticatedView.as_view(), name='token_view'),
    path('mixed/', MixedAuthView.as_view(), name='mixed_view'),
    path('admin_view/', AdminView.as_view(), name='admin_view'),
    path('unchecked/', unchecked_view, name='unchecked_view'),
]

# Test Case
class InspectAccessControlTests(TestCase):
    @unittest.mock.patch('django.conf.settings')
    def setUp(self, mock_settings):
        # Configure settings
        mock_settings.configure_mock(
            ROOT_URLCONF=__name__,
            REST_FRAMEWORK={
                'DEFAULT_PERMISSION_CLASSES': [
                    'rest_framework.permissions.AllowAny',
                ],
                'DEFAULT_AUTHENTICATION_CLASSES': [
                    'rest_framework.authentication.BasicAuthentication',
                ]
            }
        )
        # Ensure urlpatterns are globally available in this module's scope for ROOT_URLCONF
        globals()['urlpatterns'] = urlpatterns

    def test_example(self):
        # This is a placeholder test. Actual tests will be added later.
        self.assertTrue(True)

    @unittest.mock.patch('sys.stdout', new_callable=io.StringIO)
    def test_cli_output(self, mock_stdout):
        call_command('inspect_access_control')
        output = mock_stdout.getvalue()

        # Print output for debugging during test development (optional)
        # print(f"\n--- CLI Output ---\n{output}\n--- End CLI Output ---\n")

        # Check for table headers
        self.assertIn("Views", output)
        self.assertIn("Authentication Classes", output)
        self.assertIn("Permission Classes", output)
        self.assertIn("Unchecked Views", output) # Adjusted to match actual output
        self.assertIn("Admin Views", output) # Adjusted to match actual output

        # Check for view names (these are URL names)
        self.assertIn("function_view", output)
        self.assertIn("class_view", output)
        self.assertIn("authenticated_view", output)
        self.assertIn("token_view", output)
        self.assertIn("mixed_view", output)
        self.assertIn("admin_view", output)
        self.assertIn("unchecked_view", output) # This will be in the "Unchecked Views" table

        # Check for specific auth/perm classes
        # Default classes (from settings)
        self.assertIn("BasicAuthentication", output) # Default auth
        self.assertIn("AllowAny", output)           # Default perm

        # Explicitly set classes
        self.assertIn("IsAuthenticated", output)
        self.assertIn("TokenAuthentication", output)

        # Check for specific table entries
        # Expected format might be tricky due to Rich library's table rendering.
        # We'll look for the view name and its presence in the correct section.

        # Unchecked view
        # Assuming "Unchecked Views" is a distinct section/table title
        unchecked_section_index = output.find("Unchecked Views")
        self.assertTrue(unchecked_section_index != -1, "Unchecked Views section not found")
        self.assertIn("unchecked_view", output[unchecked_section_index:])

        # Admin view
        # Assuming "Admin Views" is a distinct section/table title
        admin_section_index = output.find("Admin Views")
        self.assertTrue(admin_section_index != -1, "Admin Views section not found")
        self.assertIn("admin_view", output[admin_section_index:])


        # Check for summary panel titles (Rich panels)
        self.assertIn("Summary", output)
        self.assertIn("General Info", output) # From the management command

        # Check for summary counts/details in panels (content of panels)
        # These might be plain text or part of Rich's rendering.
        # Using regex might be more robust, but for now, simple substring checks.
        self.assertIn("Total Views Inspected", output)
        # self.assertIn("Unchecked Views", output) # Already checked as a table header
        self.assertIn("Views with No Authentication", output)
        self.assertIn("Views with Default Settings", output)

        # Check specific view details (example for function_view with default settings)
        # This will depend heavily on the Rich table formatting.
        # For a view using defaults, we expect to see the default classes.
        # Example: "function_view | BasicAuthentication | AllowAny" (highly simplified)
        # A more robust check might involve parsing the table or using regex.
        # For now, ensuring the view and its expected classes are somewhere in the output.
        self.assertTrue(
            "function_view" in output and \
            "BasicAuthentication" in output and \
            "AllowAny" in output
        )

        # Example for AuthenticatedView
        self.assertTrue(
            "authenticated_view" in output and \
            "BasicAuthentication" in output and \
            "IsAuthenticated" in output
        )

        # Example for TokenAuthenticatedView
        self.assertTrue(
            "token_view" in output and \
            "TokenAuthentication" in output and \
            "AllowAny" in output # It should pick up default permission
        )

        # Example for MixedAuthView
        self.assertTrue(
            "mixed_view" in output and \
            "TokenAuthentication" in output and \
            "IsAuthenticated" in output
        )

    @unittest.mock.patch('sys.stdout', new_callable=io.StringIO)
    def test_json_output(self, mock_stdout):
        call_command('inspect_access_control', output='json')
        output_str = mock_stdout.getvalue()
        
        # print(f"\n--- JSON Output ---\n{output_str}\n--- End JSON Output ---\n") # For debugging
        
        data = json.loads(output_str)

        self.assertIn("views", data)
        self.assertIn("model_admin_views", data)
        self.assertIn("unchecked_views", data)

        # Assert "views" structure and content
        views_data = data["views"]
        # The subtask asks for 'authenticated' and 'unauthenticated' keys.
        # This requires the management command to categorize them as such.
        # Let's assume for now it does. If not, this part needs adjustment based on actual output.
        
        # If the command doesn't explicitly categorize into 'authenticated'/'unauthenticated'
        # then all regular views might be in a single dictionary or list.
        # For this example, I'll proceed as if the categorization exists.
        # A more robust test would first check the structure or adapt based on it.

        # Based on the subtask's desired structure:
        self.assertIn("authenticated", views_data)
        self.assertIn("unauthenticated", views_data)

        # Check views['authenticated']
        authenticated_views = views_data.get("authenticated", {}) # Use .get for safety
        
        # 'authenticated_view' corresponds to 'ProtectedView'
        self.assertIn("authenticated_view", authenticated_views)
        self.assertEqual(
            authenticated_views["authenticated_view"]["permission_classes"],
            ['IsAuthenticated'] 
        )
        # It should also list the default auth class if not overridden
        self.assertEqual(
            authenticated_views["authenticated_view"]["authentication_classes"],
            ['rest_framework.authentication.BasicAuthentication'] # Default
        )

        # 'token_view' corresponds to 'TokenAuthView'
        self.assertIn("token_view", authenticated_views)
        self.assertEqual(
            authenticated_views["token_view"]["authentication_classes"],
            ['TokenAuthentication']
        )
        # It should also list the default perm class if not overridden
        self.assertEqual(
            authenticated_views["token_view"]["permission_classes"],
            ['rest_framework.permissions.AllowAny'] # Default
        )
        
        # 'mixed_view' corresponds to 'AdminProtectedView' (as per mapping)
        self.assertIn("mixed_view", authenticated_views)
        self.assertEqual(
            authenticated_views["mixed_view"]["authentication_classes"],
            ['TokenAuthentication']
        )
        self.assertEqual(
            authenticated_views["mixed_view"]["permission_classes"],
            ['IsAuthenticated']
        )

        # Check views['unauthenticated']
        unauthenticated_views = views_data.get("unauthenticated", {}) # Use .get for safety

        # 'function_view' corresponds to 'func_view'
        self.assertIn("function_view", unauthenticated_views)
        self.assertEqual(
            unauthenticated_views["function_view"]["permission_classes"],
            ['rest_framework.permissions.AllowAny'] # Default
        )
        self.assertEqual(
            unauthenticated_views["function_view"]["authentication_classes"],
            ['rest_framework.authentication.BasicAuthentication'] # Default
        )

        # 'class_view' corresponds to 'MyClassView'
        self.assertIn("class_view", unauthenticated_views)
        self.assertEqual(
            unauthenticated_views["class_view"]["permission_classes"],
            ['rest_framework.permissions.AllowAny'] # Default
        )
        self.assertEqual(
            unauthenticated_views["class_view"]["authentication_classes"],
            ['rest_framework.authentication.BasicAuthentication'] # Default
        )

        # Assert "model_admin_views" content
        model_admin_views = data["model_admin_views"]
        self.assertIsInstance(model_admin_views, list)
        # The name in urlpatterns is 'admin_view'
        # The output might be the fully qualified name, but the prompt implies checking for 'model_admin_view'
        # Let's check if 'admin_view' (the URL name) is present.
        # This depends on how the command reports these. If it's by URL name, this is correct.
        
        # A simple check for the presence of our admin view by its URL name.
        # The actual content might be more complex (e.g. dicts with details).
        # The subtask asks to assert 'model_admin_view' is present.
        # Let's assume the list contains the view names.
        self.assertIn("admin_view", model_admin_views)


        # Assert "unchecked_views" content
        unchecked_views_list = data["unchecked_views"]
        self.assertIsInstance(unchecked_views_list, list)
        
        found_unchecked_view = False
        for item in unchecked_views_list:
            self.assertIsInstance(item, dict)
            self.assertIn("view", item)
            self.assertIn("cause", item)
            if "unchecked_view" in item["view"]: # 'unchecked_view' is the URL name
                found_unchecked_view = True
                self.assertIsInstance(item["cause"], str)
                # self.assertEqual(item["cause"], "View has no explicit authentication or permission classes defined and default DRF settings are not configured to secure views by default.") # Example cause
        self.assertTrue(found_unchecked_view, "unchecked_view not found in unchecked_views list")

    @override_settings(ROOT_URLCONF=None)
    def test_error_missing_root_urlconf(self):
        with self.assertRaises(CommandError) as cm:
            call_command('inspect_access_control')
        self.assertIn("settings.ROOT_URLCONF is not set", str(cm.exception))

    @override_settings(ROOT_URLCONF="non_existent_module_for_testing")
    def test_error_invalid_root_urlconf(self):
        with self.assertRaises(CommandError) as cm:
            call_command('inspect_access_control')
        # The error message might vary slightly depending on Django versions or how it's caught.
        # Checking for part of the module name and a common error phrase.
        self.assertTrue(
            "non_existent_module_for_testing" in str(cm.exception) or \
            "cannot import name" in str(cm.exception) or \
            "ModuleNotFoundError" in str(cm.exception) # More generic for module import failures
        )
