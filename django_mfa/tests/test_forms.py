from django_mfa.models import *
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django_mfa.forms import *
from unittest import skip


class TestU2fForm(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='micro', email='djangomfa@mp.com', password='djangomfa')

    def test_key_response_form(self):
        self.assertTrue(issubclass(KeyResponseForm, forms.Form))
        form_data = {"response": "xyz"}
        form = KeyRegistrationForm(data=form_data, user=self.user,
                                   request="/settings/add-key/", appId="https://appId")
        self.assertTrue(form.is_valid())

    # @skip('Need to implement ')
    # def test_KeyResponseForm(self):
    #     session = self.client.session
    #     session['u2f_sign_request'] = {'appId': 'https://appId.com', 'registeredKeys': [{'publicKey': 'publicKey', 'keyHandle': 'keyHandle',
    #                                                                                      'appId': 'https://appId.com', 'version': 'U2F_V2'}], 'challenge': 'HaK4_Vn763JZGKVE5-pZu5hH1WcWuXVikoRYXGQlEXI'}
    #     session.save()
    #     # kwargs_data = {'initial': {}, 'prefix': None, 'data': < QueryDict: {'csrfmiddlewaretoken': ['stUhPxqfTbqPNGpGRVToXRCANWDaJsJ96Y7HTfzk6RmEpEqvZ74xYYb7OGKfTiHy'], 'response': ['31t23t32t23eeewg']} > , 'files': < MultiValueDict: {} > , 'user': < SimpleLazyObject: < User: super@gmail.com>>, 'request': < WSGIRequest: POST '/settings/add-key/' > , 'appId': 'http://127.0.0.1:8000'}
    #     # form = KeyResponseForm(data={"response": "xyz"}, user=self.user,
    #     #                        request="/settings/add-key/", appId="https://appId")
    #     req_response = self.client.post('/settings/add-key/')
    #     form = KeyResponseForm(data={"response": "xyz"}, user= self.user, request= req_response, appId= 'https://appId.com')
