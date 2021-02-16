Flow And Urls
======================

.. _templatetags-paginate:

Once we have done with the basic setup as given in installation and setup, we are ready to go.

Step1: Enabling MFA
~~~~~~~~~~~~~~~~~~~

Once your app is up and running with settings, just go to url ``/settings/security``. There we can see if the MFA is enabled or not. Lets say MFA is not enabled. When we click on ``'Enable MFA'``. Then user will be redirected to setup types url.

Step2: Setup with APP
~~~~~~~~~~~~~~~~~~~~~

When user completes step1 successfully, he/she will be redirected to url ``/settings/mfa/configure/``. Here user will have option to Setup using APP. This means we are going to use google authenticator for this. When user click on ``'Setup using APP'`` then will be redirected to page where we get a QR code which we have to scan in our google authenticator.


Step3: Scan QR code
~~~~~~~~~~~~~~~~~~~~~

In this step user will see a QR code generated with user's email. User have to scan this code with Google Authenticator app. Once user scanned this image, user will get a 6 digit code which expire for every 30 secs. User has to enter this six digit code in the text box. Once user successfully enters the six digit code, thats it from now onwards your MFA is enabled. You can check this by logging out of the system and login again. Even when user login with username and password the application will ask for 6 digit code to complete the login. After succesfull setup user will get a list of recovery codes, which user should save and can be used to authenticate/disable the two-factored-authentication when user lost the mobile or unable to get otp code from authenticator app.

Step4: Disabing the MFA
~~~~~~~~~~~~~~~~~~~~~~~

Disabling MFA is quite simple, we can do this by visiting the url ``/settings/security``. By clicking the ``'Disable MFA'`` the you will be asked to enter the 6 digit otp from authenticator app or one of your recovery code, if the code is correct your account will be free from MFA.
