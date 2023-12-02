var checkPasswordMatch = function() {
  // Check that the passwords match
    if (document.getElementById('password').value ==
    // If they do, change the text to green, display a checkmark and activate the submit button (id=form-button)
      document.getElementById('password2').value) {
      document.getElementById('password-match').style.color = 'green';
      document.getElementById('password-match').innerHTML = '&#x2713; Passwords match';
      document.getElementById('form-button').disabled = false;
    } else {
    // If they don't, change the text to red, display an X and deactivate the submit button
      document.getElementById('password-match').style.color = 'red';
      document.getElementById('password-match').innerHTML = '&#x2717; Passwords do not match';
      document.getElementById('form-button').disabled = true;
    }
  }