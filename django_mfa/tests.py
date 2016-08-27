from django.test import TestCase
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django_mfa.models import *
from django.test import Client
from django_mfa import totp
from django.core.urlresolvers import reverse


class Views_test(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='micro', email='djangomfa@mp.com', password='djangomfa')
        user_login = self.client.login(username='micro', password="djangomfa")

    def test_security_settings_view(self):
        response = self.client.get(reverse('security_settings'))
        self.assertTemplateUsed(response, "security.html")

    def test_configure_mfa_view(self):
        response = self.client.get(reverse('configure_mfa'))
        self.assertTemplateUsed(response, "configure.html")

    # def test_configure_mfa_post_view(self):
    #     response = self.client.post(reverse('configure_mfa'))
    #     self.assertTemplateUsed(response, "configure.html")

    # def test_enable_mfa_view(self):
    #     response = self.client.get(reverse('enable_mfa'))
    #     self.assertTemplateUsed(response, "configure.html")


