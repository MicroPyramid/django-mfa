from django.test import RequestFactory, TestCase

from django_mfa import session


class SessionStateTests(TestCase):
    def setUp(self):
        self.request = RequestFactory().get("/")
        self.request.session = {}

    def test_absent_state_is_neither_verified_nor_pending(self):
        self.assertFalse(session.is_verified(self.request))
        self.assertFalse(session.is_pending(self.request))

    def test_start_pending_is_pending_not_verified(self):
        session.start_pending(self.request)
        self.assertTrue(session.is_pending(self.request))
        self.assertFalse(session.is_verified(self.request))

    def test_mark_verified_records_method_and_timestamp(self):
        session.mark_verified(self.request, "totp")
        state = self.request.session[session.SESSION_KEY]
        self.assertTrue(state["verified"])
        self.assertEqual(state["method"], "totp")
        self.assertIsInstance(state["at"], int)

    def test_verified_is_not_pending(self):
        session.start_pending(self.request)
        session.mark_verified(self.request, "totp")
        self.assertFalse(session.is_pending(self.request))

    def test_reset_clears_state(self):
        session.mark_verified(self.request, "totp")
        session.reset(self.request)
        self.assertNotIn(session.SESSION_KEY, self.request.session)

    def test_reset_on_empty_session_is_a_no_op(self):
        session.reset(self.request)  # must not raise
        self.assertEqual(self.request.session, {})
