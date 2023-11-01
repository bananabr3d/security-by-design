document.addEventListener('DOMContentLoaded', function () {
    const cookieBanner = document.getElementById('cookie-banner');
    const acceptButton = document.getElementById('accept-cookies');

    // Check if the user has previously accepted cookies
    if (document.cookie.indexOf('cookieConsent=accepted') === -1) {
        cookieBanner.style.display = 'block';
    }

    acceptButton.addEventListener('click', function () {
        // Set a cookie to remember the user's consent
        document.cookie = 'cookieConsent=accepted; max-age=2592000'; // Cookie expires after 30 days

        // Hide the cookie banner
        cookieBanner.style.display = 'none';
    });
});