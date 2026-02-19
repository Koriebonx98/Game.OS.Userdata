// Form Handling and Validation

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    
    // Login Form Handler
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Signup Form Handler
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', handleSignup);
    }
});

// Handle Login Form Submission
function handleLogin(event) {
    event.preventDefault();
    
    const messageDiv = document.getElementById('loginMessage');
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    
    // Clear previous messages
    messageDiv.className = 'message';
    messageDiv.textContent = '';
    
    // Basic validation
    if (!validateEmail(email)) {
        showMessage(messageDiv, 'Please enter a valid email address', 'error');
        return;
    }
    
    if (password.length < 6) {
        showMessage(messageDiv, 'Password must be at least 6 characters long', 'error');
        return;
    }
    
    // Simulate login (In production, this would be an API call)
    console.log('Login attempt:', { email, rememberMe });
    
    // Check if user exists in localStorage (for demo purposes)
    const users = JSON.parse(localStorage.getItem('users') || '[]');
    const user = users.find(u => u.email === email && u.password === password);
    
    if (user) {
        showMessage(messageDiv, 'Login successful! Redirecting...', 'success');
        
        // Store session
        if (rememberMe) {
            localStorage.setItem('currentUser', JSON.stringify(user));
        } else {
            sessionStorage.setItem('currentUser', JSON.stringify(user));
        }
        
        // Redirect after 1.5 seconds (in production, redirect to dashboard)
        setTimeout(() => {
            showMessage(messageDiv, 'Welcome back, ' + user.username + '!', 'success');
        }, 1500);
    } else {
        showMessage(messageDiv, 'Invalid email or password. Please try again.', 'error');
    }
}

// Handle Signup Form Submission
function handleSignup(event) {
    event.preventDefault();
    
    const messageDiv = document.getElementById('signupMessage');
    const username = document.getElementById('signupUsername').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    const agreeTerms = document.getElementById('agreeTerms').checked;
    
    // Clear previous messages
    messageDiv.className = 'message';
    messageDiv.textContent = '';
    
    // Validation
    if (username.length < 3) {
        showMessage(messageDiv, 'Username must be at least 3 characters long', 'error');
        return;
    }
    
    if (!validateEmail(email)) {
        showMessage(messageDiv, 'Please enter a valid email address', 'error');
        return;
    }
    
    if (password.length < 6) {
        showMessage(messageDiv, 'Password must be at least 6 characters long', 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showMessage(messageDiv, 'Passwords do not match', 'error');
        return;
    }
    
    if (!agreeTerms) {
        showMessage(messageDiv, 'Please agree to the Terms and Conditions', 'error');
        return;
    }
    
    // Check if user already exists
    const users = JSON.parse(localStorage.getItem('users') || '[]');
    const existingUser = users.find(u => u.email === email);
    
    if (existingUser) {
        showMessage(messageDiv, 'An account with this email already exists', 'error');
        return;
    }
    
    // Create new user (In production, this would be an API call)
    const newUser = {
        username,
        email,
        password, // In production, NEVER store plain passwords!
        createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    localStorage.setItem('users', JSON.stringify(users));
    
    console.log('Signup successful:', { username, email });
    
    showMessage(messageDiv, 'Account created successfully! Redirecting to login...', 'success');
    
    // Redirect to login page after 2 seconds
    setTimeout(() => {
        window.location.href = 'login.html';
    }, 2000);
}

// Email Validation Helper
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Show Message Helper
function showMessage(element, message, type) {
    element.textContent = message;
    element.className = 'message ' + type;
}

// Password Strength Indicator (Optional Enhancement)
function checkPasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    
    if (strength <= 2) return 'weak';
    if (strength <= 4) return 'medium';
    return 'strong';
}

// Clear form on successful submission
function clearForm(formId) {
    const form = document.getElementById(formId);
    if (form) {
        form.reset();
    }
}
