import datetime

from django.contrib.auth.models import Group, User
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from django.utils import timezone

from django_mfa import policy
from django_mfa.checks import check_mfa_required_predicate


def everyone(user):
    return True


def nobody(user):
    return False


not_callable = "this is a string, not a function"


class MfaRequiredForTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_default_requires_nobody(self):
        self.assertFalse(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED=True)
    def test_true_requires_every_authenticated_user(self):
        self.assertTrue(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED=True)
    def test_anonymous_is_never_required(self):
        from django.contrib.auth.models import AnonymousUser
        self.assertFalse(policy.mfa_required_for(AnonymousUser()))

    @override_settings(MFA_REQUIRED="django_mfa.tests.test_policy.everyone")
    def test_dotted_path_is_imported_and_called(self):
        self.assertTrue(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED="django_mfa.tests.test_policy.nobody")
    def test_dotted_path_returning_false(self):
        self.assertFalse(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED=everyone)
    def test_a_plain_callable_works_too(self):
        self.assertTrue(policy.mfa_required_for(self.user))


class SuppliedPredicateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    @override_settings(MFA_REQUIRED=policy.is_staff)
    def test_is_staff(self):
        self.assertFalse(policy.mfa_required_for(self.user))
        self.user.is_staff = True
        self.assertTrue(policy.mfa_required_for(self.user))

    def test_in_groups_matches_only_named_groups(self):
        predicate = policy.in_groups("admins", "finance")
        with override_settings(MFA_REQUIRED=predicate):
            self.assertFalse(policy.mfa_required_for(self.user))
            self.user.groups.add(Group.objects.create(name="marketing"))
            self.assertFalse(policy.mfa_required_for(self.user))
            self.user.groups.add(Group.objects.create(name="finance"))
            self.assertTrue(policy.mfa_required_for(self.user))

    def test_in_groups_costs_one_query(self):
        predicate = policy.in_groups("admins")
        with self.assertNumQueries(1):
            predicate(self.user)


class CheckE004Tests(TestCase):
    def test_default_passes(self):
        self.assertEqual(check_mfa_required_predicate(None), [])

    @override_settings(MFA_REQUIRED="django_mfa.tests.test_policy.everyone")
    def test_valid_dotted_path_passes(self):
        self.assertEqual(check_mfa_required_predicate(None), [])

    @override_settings(MFA_REQUIRED="django_mfa.nonexistent.predicate")
    def test_unimportable_path_is_an_error(self):
        errors = check_mfa_required_predicate(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E004"])

    @override_settings(MFA_REQUIRED="django_mfa.tests.test_policy.not_callable")
    def test_importable_but_not_callable_is_an_error(self):
        errors = check_mfa_required_predicate(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E004"])

    @override_settings(MFA_REQUIRED=42)
    def test_nonsense_value_is_an_error(self):
        errors = check_mfa_required_predicate(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E004"])

    @override_settings(MFA_REQUIRED="django_mfa.nonexistent.predicate")
    def test_the_check_is_not_gated_on_webauthn(self):
        """E001-E003 are WebAuthn-only and skip for a TOTP-only project.
        E004 is not WebAuthn-specific and must fire regardless."""
        with override_settings(MFA_QUICKLOGIN=False):
            errors = check_mfa_required_predicate(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E004"])


class ResolveTests(TestCase):
    @override_settings(MFA_REQUIRED=42)
    def test_resolve_raises_on_a_nonsense_value(self):
        with self.assertRaises(ImproperlyConfigured):
            policy.resolve()


JOINED = datetime.datetime(2026, 1, 10, 12, 0)


def _joined(dt):
    """A user whose date_joined is `dt`, timezone-matched to USE_TZ."""
    user = User.objects.create_user("grace", "grace@example.com", "pw")
    User.objects.filter(pk=user.pk).update(date_joined=policy._match_tz(dt))
    user.refresh_from_db()
    return user


class RequiredAtTests(TestCase):
    def test_no_settings_means_required_immediately(self):
        """The default install must behave exactly as it does today."""
        self.assertIsNone(policy.required_at(_joined(JOINED)))

    @override_settings(MFA_REQUIRED_FROM=datetime.date(2026, 9, 1))
    def test_cutover_only(self):
        self.assertEqual(
            policy.required_at(_joined(JOINED)),
            policy._match_tz(datetime.datetime(2026, 9, 1, 0, 0)))

    @override_settings(MFA_GRACE_PERIOD=14)
    def test_period_only_counts_from_date_joined(self):
        self.assertEqual(
            policy.required_at(_joined(JOINED)),
            policy._match_tz(JOINED + datetime.timedelta(days=14)))

    @override_settings(MFA_REQUIRED_FROM=datetime.date(2026, 9, 1),
                       MFA_GRACE_PERIOD=14)
    def test_cutover_wins_for_a_user_who_joined_long_ago(self):
        """max(), not min(): an old account is governed by the cutover."""
        self.assertEqual(
            policy.required_at(_joined(JOINED)),
            policy._match_tz(datetime.datetime(2026, 9, 1, 0, 0)))

    @override_settings(MFA_REQUIRED_FROM=datetime.date(2026, 9, 1),
                       MFA_GRACE_PERIOD=14)
    def test_personal_window_wins_for_a_user_who_joined_after_the_cutover(self):
        """The cutover having passed must not cost a new joiner their window."""
        late = datetime.datetime(2026, 10, 5, 9, 0)
        self.assertEqual(
            policy.required_at(_joined(late)),
            policy._match_tz(late + datetime.timedelta(days=14)))

    @override_settings(MFA_GRACE_PERIOD=datetime.timedelta(days=3))
    def test_period_accepts_a_timedelta(self):
        self.assertEqual(
            policy.required_at(_joined(JOINED)),
            policy._match_tz(JOINED + datetime.timedelta(days=3)))

    @override_settings(MFA_GRACE_PERIOD=14,
                       MFA_GRACE_ANCHOR="django_mfa.tests.test_policy.anchor_none")
    def test_anchor_returning_none_falls_back_to_cutover_only(self):
        self.assertIsNone(policy.required_at(_joined(JOINED)))

    @override_settings(MFA_GRACE_PERIOD=14,
                       MFA_GRACE_ANCHOR="django_mfa.tests.test_policy.anchor_fixed")
    def test_dotted_path_anchor_is_used_instead_of_date_joined(self):
        self.assertEqual(
            policy.required_at(_joined(JOINED)),
            policy._match_tz(
                datetime.datetime(2026, 6, 1, 0, 0) + datetime.timedelta(days=14)))

    @override_settings(MFA_GRACE_PERIOD=14)
    def test_user_model_without_date_joined_gets_no_personal_window(self):
        class Anon:
            is_authenticated = True

        self.assertIsNone(policy.required_at(Anon()))

    @override_settings(MFA_REQUIRED_FROM="2026-09-01")
    def test_cutover_of_the_wrong_type_raises(self):
        """A string is not a date or datetime -- _as_datetime must say so
        rather than fail confusingly on a later comparison against
        timezone.now()."""
        with self.assertRaises(ImproperlyConfigured):
            policy.required_at(_joined(JOINED))


def anchor_none(user):
    return None


def anchor_fixed(user):
    return datetime.datetime(2026, 6, 1, 0, 0)


@override_settings(MFA_REQUIRED=True)
class GraceStateTests(TestCase):
    def setUp(self):
        self.user = _joined(JOINED)

    def test_none_when_no_grace_is_configured(self):
        self.assertIsNone(policy.grace_state(self.user))

    @override_settings(MFA_REQUIRED_FROM=datetime.date(2020, 1, 1))
    def test_none_once_the_deadline_has_passed(self):
        self.assertIsNone(policy.grace_state(self.user))

    @override_settings(MFA_REQUIRED=False,
                       MFA_REQUIRED_FROM=datetime.date(2099, 1, 1))
    def test_none_for_a_user_the_policy_does_not_cover(self):
        """No banner for someone who would never be walled anyway."""
        self.assertIsNone(policy.grace_state(self.user))

    @override_settings(MFA_REQUIRED_FROM=datetime.date(2099, 1, 1))
    def test_reports_the_deadline_while_in_grace(self):
        state = policy.grace_state(self.user)
        self.assertEqual(
            state.required_at, policy._match_tz(datetime.datetime(2099, 1, 1, 0, 0)))
        self.assertGreater(state.days_remaining, 0)

    def test_days_remaining_rounds_up(self):
        """23 hours left must read '1 day', never '0' -- 0 reads as expired."""
        soon = timezone.now() + datetime.timedelta(hours=23)
        with override_settings(MFA_REQUIRED_FROM=soon):
            self.assertEqual(policy.grace_state(self.user).days_remaining, 1)


def anchor_aware(user):
    """An anchor resolver returning an aware datetime -- see
    MatchTzUseTzFalseTests for why this exists."""
    return datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)


class MatchTzUseTzFalseTests(TestCase):
    """_match_tz's `not USE_TZ and is_aware(value)` branch.

    test_runner.py pins USE_TZ=True globally, so nothing above this class
    ever hits that branch -- every value either starts naive already or is
    made aware. Mirrors MfaDisableUntilUseTzTests' pattern (test_exemptions.py):
    pin USE_TZ=False with override_settings and drive the real, public entry
    points (required_at/grace_state) end-to-end, rather than calling the
    private helper directly. TIME_ZONE is pinned to UTC alongside USE_TZ so
    the aware -> naive conversion is a plain tzinfo strip with no hour shift,
    keeping the expected values simple. Far-future dates (2099) keep
    grace_state() from reading as already-passed regardless of when the
    suite runs.
    """

    @override_settings(
        USE_TZ=False, TIME_ZONE="UTC",
        MFA_REQUIRED_FROM=datetime.datetime(
            2099, 1, 1, tzinfo=datetime.timezone.utc))
    def test_required_at_converts_an_aware_cutover_to_naive(self):
        due = policy.required_at(_joined(JOINED))
        self.assertTrue(timezone.is_naive(due))
        self.assertEqual(due, datetime.datetime(2099, 1, 1, 0, 0))

    @override_settings(
        USE_TZ=False, TIME_ZONE="UTC", MFA_REQUIRED=True,
        MFA_GRACE_PERIOD=1,
        MFA_GRACE_ANCHOR="django_mfa.tests.test_policy.anchor_aware")
    def test_grace_state_converts_an_aware_anchor_to_naive(self):
        state = policy.grace_state(_joined(JOINED))
        self.assertTrue(timezone.is_naive(state.required_at))
        self.assertEqual(state.required_at, datetime.datetime(2099, 1, 2, 0, 0))


class ProtectAdminUnionTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            "s", "s@example.com", "pw", is_staff=True)
        self.plain = User.objects.create_user("p", "p@example.com", "pw")

    def test_off_by_default(self):
        self.assertIsNone(policy.resolve())

    @override_settings(MFA_PROTECT_ADMIN=True)
    def test_staff_are_required_with_no_other_policy(self):
        self.assertTrue(policy.resolve()(self.staff))
        self.assertFalse(policy.resolve()(self.plain))

    @override_settings(MFA_PROTECT_ADMIN=True,
                       MFA_REQUIRED="django_mfa.tests.test_policy.only_p")
    def test_union_with_an_existing_predicate(self):
        self.assertTrue(policy.resolve()(self.staff))
        self.assertTrue(policy.resolve()(self.plain))

    @override_settings(MFA_PROTECT_ADMIN=True)
    def test_the_union_is_not_cached_across_settings_changes(self):
        """policy._import is @cache'd on the dotted path; the composed
        predicate must NOT ride along or override_settings gets pinned."""
        self.assertTrue(policy.resolve()(self.staff))
        with override_settings(MFA_PROTECT_ADMIN=False):
            self.assertIsNone(policy.resolve())


def only_p(user):
    return user.username == "p"
