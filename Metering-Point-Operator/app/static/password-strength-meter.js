function checkPasswordStrength() {
    const password = document.getElementById('password').value;
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');

    // Calculate the score based on fulfilled criteria
    let score = calculateScore(password);

    // score_level goes from min 0 - 5
    // 0 - 19: Very Weak
    // 20 - 39: Weak
    // 40 - 59: Moderate
    // 60 - 79: Strong
    // 80 - 100: Very Strong
    score_level = Math.min(Math.floor(score / 20) + 1, 5);

    // Update the strength bar and text
    strengthBar.style.width = Math.min(score, 100) + "%"; // Max score (and width) is 100%
    strengthBar.style.backgroundColor = getStrengthColor(score_level);
    strengthText.innerHTML = getStrengthText(score_level);
}

function calculateScore(password) {
    // Score is based on a easier version of https://www.uic.edu/apps/strong-password/

    let score = 0;

    // Check if password chars meet criteria -> "Additions"
    for (let i = 0; i < password.length; i++) {
        score += checkCriteria_Chars(password[i]);
    }

    // Check if password meets criteria -> "Additions" and "Deductions"
    score += checkCriteria(password);

    return score;
}

function checkCriteria_Chars(char) {
    const criteria = [
        /[a-z]/, // Lowercase
        /[A-Z]/, // Uppercase
        /[0-9]/, // Digit
        /[^A-Za-z0-9]/ // Special character
    ];

    for (let i = 0; i < criteria.length; i++) {
        if (criteria[i].test(char)) {
            return 1;
        }
    }

    return 0;
}

function checkCriteria(password) {
    let result = 0;

    // Check length
    result += password.length * 4;

    // Check if numbers only or letters only, then reduce score by length
    if (/^[0-9]+$/.test(password) || /^[a-zA-Z]+$/.test(password)) {
        result -= password.length;
    }

    // Check for repeating characters
    const uniqueChars = new Set(password);
    result -= (password.length - uniqueChars.size);

    // Check for consecutive uppercase letters
    for (let i = 0; i < password.length - 1; i++) {
        if (/[A-Z]/.test(password[i]) && /[A-Z]/.test(password[i + 1])) {
            result -= 2;
        }
    }

    // Check for consecutive lowercase letters
    for (let i = 0; i < password.length - 1; i++) {
        if (/[a-z]/.test(password[i]) && /[a-z]/.test(password[i + 1])) {
            result -= 2;
        }
    }

    // Check for consecutive numbers
    for (let i = 0; i < password.length - 1; i++) {
        if (/[0-9]/.test(password[i]) && /[0-9]/.test(password[i + 1])) {
            result -= 2;
        }
    }

    return result;
}

function getStrengthColor(score) {
    const colors = ["#d9534f", "#f0ad4e", "#5bc0de", "#5cb85c", "#5cb85c"];
    return colors[score - 1];
}

function getStrengthText(score) {
    const strengthLevels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"];
    return strengthLevels[score - 1];
}
