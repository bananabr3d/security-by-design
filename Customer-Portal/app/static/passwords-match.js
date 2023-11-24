var checkPasswordMatch = function() {
    if (document.getElementById('password').value ==
      document.getElementById('password2').value) {
      document.getElementById('password-match').style.color = 'green';
      document.getElementById('password-match').innerHTML = '&#x2713; Passwords match';
    } else {
      document.getElementById('password-match').style.color = 'red';
      document.getElementById('password-match').innerHTML = '&#x2717; Passwords do not match';
    }
  }