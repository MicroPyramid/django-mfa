from django.core.urlresolvers import reverse
from django.shortcuts import resolve_url
from django.contrib.auth import REDIRECT_FIELD_NAME as redirect_field_name
from .models import is_mfa_enabled

try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:  # Django < 1.10
    # Works perfectly for everyone using MIDDLEWARE_CLASSES
    MiddlewareMixin = object


class MfaMiddleware(MiddlewareMixin):

    def process_request(self, request):
        if request.user.is_authenticated() and is_mfa_enabled(request.user):
            if not request.session.get('verfied_otp'):
                current_path = request.path
                if current_path != reverse("mfa:verify_otp"):
                    path = request.get_full_path()
                    resolved_login_url = resolve_url(reverse("mfa:verify_otp"))
                    from django.contrib.auth.views import redirect_to_login
                    return redirect_to_login(path, resolved_login_url, redirect_field_name)
        return None
