function handleU2FError(resp) {
  if (resp.errorCode) {
    document.getElementById('u2f-status').textContent = 'Error with U2F';
    return true;
  } else {
    return false;
  }
}

if (typeof window.u2f === 'undefined')
  document.getElementById('u2f-not-defined-error').style.display = 'block';


var request;
var requestElem = document.getElementById('django_u2f_request');
if (requestElem) {
  request = JSON.parse(requestElem.textContent);
  u2f.sign(request.appId, request.challenge, request.registeredKeys, function(resp) {
    var form = document.getElementById('u2f-form');
    form.response.value = JSON.stringify(resp);
    if (!handleU2FError(resp)) {
      form.submit();
    }
  });
}


var registrationElem = document.getElementById('django_u2f_registration');
alert(registrationElem.textContent)
if (registrationElem) {
  request = JSON.parse(registrationElem.textContent);
  u2f.register(request.appId, request.registerRequests, request.registeredKeys, function(resp) {
    var form = document.getElementById('u2f-form');
    form.response.value = JSON.stringify(resp);
    if (!handleU2FError(resp)) {
      form.submit();
    }
  });
}
