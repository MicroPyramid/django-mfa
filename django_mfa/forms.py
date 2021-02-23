import json
from django import forms
from django.utils import timezone
from u2flib_server import u2f


class SecondFactorForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        self.request = kwargs.pop('request')
        self.appId = kwargs.pop('appId')
        return super(SecondFactorForm, self).__init__(*args, **kwargs)


class KeyResponseForm(SecondFactorForm):
    response = forms.CharField()

    def __init__(self, *args, **kwargs):
        super(KeyResponseForm, self).__init__(*args, **kwargs)
        if self.data:
            self.sign_request = self.request.session['u2f_sign_request']
        else:
            self.sign_request = u2f.begin_authentication(self.appId, [
                d.to_json() for d in self.user.u2f_keys.all()
            ])
            self.request.session['u2f_sign_request'] = self.sign_request

    def validate_second_factor(self):
        response = json.loads(self.cleaned_data['response'])
        try:
            device, login_counter, _ = u2f.complete_authentication(
                self.sign_request, response)
            # TODO: store login_counter and verify it's increasing
            device = self.user.u2f_keys.get(key_handle=device['keyHandle'])
            device.last_used_at = timezone.now()
            device.save()
            del self.request.session['u2f_sign_request']
            return True
        except ValueError:
            self.add_error(
                '__all__', 'U2F validation failed -- bad signature.')
        return False


class KeyRegistrationForm(SecondFactorForm):
    response = forms.CharField()
