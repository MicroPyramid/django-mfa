from django.urls import reverse
from django.shortcuts import resolve_url
from django.contrib.auth import REDIRECT_FIELD_NAME as redirect_field_name
from .models import is_mfa_enabled, is_u2f_enabled
from .views import verify_rmb_cookie

try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:  # Django < 1.10
    # Works perfectly for everyone using MIDDLEWARE_CLASSES
    MiddlewareMixin = object


class MfaMiddleware(MiddlewareMixin):

    def process_request(self, request):
        if request.user.is_authenticated and ((not verify_rmb_cookie(request) and is_mfa_enabled(request.user)) or (is_u2f_enabled(request.user))):
            if not request.session.get('verfied_otp') and not request.session.get('verfied_u2f'):
                current_path = request.path
                paths = [reverse("mfa:verify_second_factor"), reverse(
                    "mfa:verify_second_factor_u2f"), reverse("mfa:verify_second_factor_totp")]
                if current_path not in paths:
                    path = request.get_full_path()
                    resolved_login_url = resolve_url(
                        reverse("mfa:verify_second_factor"))
                    from django.contrib.auth.views import redirect_to_login
                    return redirect_to_login(path, resolved_login_url, redirect_field_name)
        return None
