# Views package: registry-driven MFA screens.
#
# Split by concern (picker / verify / enroll / manage) rather than the single
# flat views.py the legacy UserOTP-based flow used. `verify_rmb_cookie` (and
# its update/delete counterparts) are re-exported here because
# `django_mfa.middleware` imports `verify_rmb_cookie` directly from
# `django_mfa.views` -- splitting the module into a package must not change
# that import path.
from django_mfa.views.verify import (  # noqa: F401
    delete_rmb_cookie,
    update_rmb_cookie,
    verify_rmb_cookie,
)
