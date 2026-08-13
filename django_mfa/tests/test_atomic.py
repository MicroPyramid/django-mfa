# django_mfa/tests/test_atomic.py
from django.contrib.auth.models import User
from django.test import TestCase

from django_mfa.atomic import update_data
from django_mfa.models import Authenticator


class UpdateDataTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.auth = Authenticator.objects.create(
            user=self.user, type="totp", data={"secret": "S", "counter": 1})

    def test_applies_the_change_and_reports_success(self):
        self.assertTrue(
            update_data(self.auth, lambda d: {**d, "counter": 2}))
        self.auth.refresh_from_db()
        self.assertEqual(self.auth.data["counter"], 2)

    def test_refreshes_the_in_memory_instance(self):
        update_data(self.auth, lambda d: {**d, "counter": 7})
        self.assertEqual(self.auth.data["counter"], 7)

    def test_declining_to_change_writes_nothing(self):
        self.assertFalse(update_data(self.auth, lambda d: None))
        self.auth.refresh_from_db()
        self.assertEqual(self.auth.data["counter"], 1)

    def test_a_deleted_row_is_reported_rather_than_raising(self):
        Authenticator.objects.filter(pk=self.auth.pk).delete()
        self.assertFalse(update_data(self.auth, lambda d: {**d, "counter": 2}))

    def test_apply_sees_the_committed_value_not_the_stale_instance(self):
        """The whole point of the helper: the caller's in-memory copy may be
        stale, so ``apply`` must be handed what is actually in the row.
        """
        Authenticator.objects.filter(pk=self.auth.pk).update(
            data={"secret": "S", "counter": 99})
        seen = []

        def apply(data):
            seen.append(data["counter"])
            return {**data, "counter": 100}

        update_data(self.auth, apply)
        self.assertEqual(seen, [99])

    def test_a_concurrent_write_between_read_and_update_is_retried(self):
        """Simulates losing the race: another writer commits in the window
        between this helper reading ``data`` and its conditional UPDATE. The
        first attempt must not clobber that write -- it must re-read and
        re-apply on top of it.
        """
        interference = [True]

        def apply(data):
            if interference:
                interference.pop()
                # Land a competing write *after* update_data() has read, so
                # its compare-and-set no longer matches.
                Authenticator.objects.filter(pk=self.auth.pk).update(
                    data={"secret": "S", "counter": 50, "other": "kept"})
            return {**data, "counter": data["counter"] + 1}

        self.assertTrue(update_data(self.auth, apply))
        self.auth.refresh_from_db()
        # 51, not 2: the retry re-read the competing write and built on it.
        self.assertEqual(self.auth.data["counter"], 51)
        # And the competing writer's own key survived.
        self.assertEqual(self.auth.data["other"], "kept")

    def test_gives_up_rather_than_looping_forever(self):
        """A writer that always loses must return False, not spin."""
        calls = []

        def apply(data):
            calls.append(1)
            Authenticator.objects.filter(pk=self.auth.pk).update(
                data={"secret": "S", "counter": len(calls) + 100})
            return {**data, "counter": 0}

        self.assertFalse(update_data(self.auth, apply))
        self.assertLess(len(calls), 20)
