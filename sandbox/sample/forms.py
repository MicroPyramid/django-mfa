from django import forms
from django.contrib.auth import authenticate


class RegistrationForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs = {'class': 'form-control'}

    def clean_confirm_password(self):
        password = self.cleaned_data.get("password")
        confirm_password = self.cleaned_data.get("confirm_password")
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords not matched")
        return confirm_password


class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs = {'class': 'form-control'}
        # The "webauthn" token is what makes passkey autofill (conditional
        # mediation) surface anything -- the browser offers the user's
        # passkeys in this field's own dropdown. Set after the loop above,
        # which replaces attrs wholesale rather than updating it. See
        # login.html's data-conditional form and docs/recipes.md.
        self.fields['email'].widget.attrs['autocomplete'] = 'username webauthn'

    def clean(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')
        self.user = authenticate(username=email, password=password)
        if not self.user:
            raise forms.ValidationError("Invalid Credentials")
        return self.cleaned_data
