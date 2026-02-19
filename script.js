/**
 * Game.OS Userdata – Account Management Script
 *
 * Modes
 * ─────
 *   'github' – Real persistent accounts stored in a private GitHub repository.
 *              Free, GitHub-only, no external server required.
 *   'demo'   – Accounts stored in browser localStorage (local testing only).
 *
 * Enabling real accounts (GitHub mode)
 * ──────────────────────────────────────
 * 1. Create a private GitHub repository for data (e.g. Koriebonx98/Game.OS.Private.Data)
 * 2. Create a fine-grained Personal Access Token:
 *    https://github.com/settings/tokens → "Fine-grained tokens" → "Generate new token"
 *    • Repository access: Only select repositories → your private data repo
 *    • Permissions → Repository permissions → Contents: Read and write
 * 3. Add the token as a secret named DATA_REPO_TOKEN in THIS repo
 *    (Settings → Secrets and variables → Actions → New repository secret)
 * 4. In THIS repo's Pages settings, set Source to "GitHub Actions"
 * 5. Push to main — the deploy workflow (.github/workflows/deploy.yml) injects
 *    the token at build time so it is never committed to the public repository.
 */

// ============================================================
// CONFIGURATION
// ============================================================

// Fine-grained PAT injected by the deploy workflow (see .github/workflows/deploy.yml).
// Do NOT paste a real token here – it would be visible in the public repository.
//
// Security note: the deployed JS will contain the token and is readable by anyone
// who inspects the page source. Mitigate by using a fine-grained PAT scoped ONLY
// to your private data repository (contents: read+write). If the token is compromised
// you can revoke and regenerate it at https://github.com/settings/tokens.
const GITHUB_TOKEN = ''; // ← injected at deploy time by .github/workflows/deploy.yml

// Private repository that stores account JSON files.
// These values are injected at deploy time by .github/workflows/deploy.yml
// (DATA_REPO_OWNER from ${{ github.repository_owner }}, DATA_REPO_NAME from vars.DATA_REPO_NAME).
// The defaults below are used only when running locally.
const DATA_REPO_OWNER = 'Koriebonx98'; // ← injected at deploy time
const DATA_REPO_NAME  = 'Game.OS.Private.Data'; // ← injected at deploy time

// Mode is detected automatically – 'github' when a token is present, else 'demo'
let MODE = (GITHUB_TOKEN && GITHUB_TOKEN.length > 0) ? 'github' : 'demo';

// Promise that resolves when initializeMode() has finished detecting the active mode.
// Form handlers await this to avoid a race condition where MODE is still 'github'
// while initializeMode() is still checking whether GitHub is reachable.
let modeReady = null;

// ============================================================
// SECURITY - PASSWORD HASHING FOR DEMO MODE
// ============================================================

/**
 * Hash password using Web Crypto API (for demo mode only)
 * NOTE: This provides basic protection but is NOT suitable for production.
 */
async function hashPasswordDemo(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

/**
 * Hash a password for GitHub mode using PBKDF2 with 100,000 iterations.
 * Much more resistant to brute-force attacks than plain SHA-256.
 * The username acts as the PBKDF2 salt (per-user).
 */
async function hashPassword(password, username) {
    const encoder  = new TextEncoder();
    const keyMat   = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        {
            name:       'PBKDF2',
            salt:       encoder.encode(`${username.toLowerCase()}:gameos`),
            iterations: 100000,
            hash:       'SHA-256'
        },
        keyMat,
        256  // 256 bits = 32 bytes
    );
    return Array.from(new Uint8Array(bits))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// ============================================================
// INITIALIZATION
// ============================================================

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

    // Update Account Form Handler
    const updateForm = document.getElementById('updateForm');
    if (updateForm) {
        updateForm.addEventListener('submit', handleAccountUpdate);
    }
    
    // Detect and initialise the active mode.
    // Store the promise so form handlers can await it before proceeding.
    modeReady = initializeMode();
    
    // Update nav and display current user state
    displayCurrentUser();

    // If on account page, require login and populate details
    if (document.getElementById('updateForm')) {
        requireLogin();
        populateAccountDetails();
        loadFriendsList();
    }
});

// ============================================================
// MODE INITIALISATION
// ============================================================

async function initializeMode() {
    const statusEl = document.getElementById('connectionStatus');

    if (MODE === 'github') {
        try {
            // Verify the token and data repo are reachable
            const resp = await fetch(
                `https://api.github.com/repos/${DATA_REPO_OWNER}/${DATA_REPO_NAME}`,
                { headers: githubHeaders() }
            );
            if (resp.ok) {
                console.log('✅ GitHub mode active – real accounts enabled');
                if (statusEl) {
                    statusEl.textContent = '✅ Real accounts active';
                    statusEl.className = 'status connected';
                }
                return;
            }
            throw new Error(`GitHub API ${resp.status}`);
        } catch (err) {
            console.warn('⚠️ GitHub token invalid or data repo unreachable – falling back to demo mode');
            console.warn(err.message);
            MODE = 'demo';
        }
    }

    // Demo mode notice
    console.warn('🎮 Demo Mode – accounts stored in browser localStorage only');
    console.warn('To enable real accounts, follow the setup guide in README.md');
    if (statusEl) {
        statusEl.textContent = '🎮 Demo Mode – accounts stored locally only';
        statusEl.className = 'status disconnected';
    }
}

// ============================================================
// GITHUB API HELPERS
// ============================================================

function githubHeaders() {
    return {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json'
    };
}

/**
 * Read and parse a JSON file from the private data repository.
 * Returns { content, sha } or null when the file does not exist.
 */
async function githubRead(path) {
    const resp = await fetch(
        `https://api.github.com/repos/${DATA_REPO_OWNER}/${DATA_REPO_NAME}/contents/${path}`,
        { headers: githubHeaders() }
    );
    if (resp.status === 404) return null;
    if (!resp.ok) throw new Error(`GitHub API error ${resp.status}`);
    const file = await resp.json();
    const json = new TextDecoder().decode(
        Uint8Array.from(atob(file.content.replace(/\n/g, '')), c => c.charCodeAt(0))
    );
    return { content: JSON.parse(json), sha: file.sha };
}

/**
 * Create or update a JSON file in the private data repository.
 * Pass `sha` when overwriting an existing file.
 */
/**
 * Delete a file from the private data repository.
 */
async function githubDelete(path, sha, message) {
    const resp = await fetch(
        `https://api.github.com/repos/${DATA_REPO_OWNER}/${DATA_REPO_NAME}/contents/${path}`,
        {
            method: 'DELETE',
            headers: githubHeaders(),
            body: JSON.stringify({
                message,
                sha,
                committer: { name: 'Game.OS Bot', email: 'game-os-bot@users.noreply.github.com' }
            })
        }
    );
    if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.message || `GitHub API error ${resp.status}`);
    }
}

async function githubWrite(path, content, message, sha) {
    const json   = JSON.stringify(content, null, 2);
    const bytes  = new TextEncoder().encode(json);
    let binary   = '';
    bytes.forEach(b => (binary += String.fromCharCode(b)));
    const base64 = btoa(binary);

    const body = {
        message,
        content: base64,
        committer: { name: 'Game.OS Bot', email: 'game-os-bot@users.noreply.github.com' }
    };
    if (sha) body.sha = sha;

    const resp = await fetch(
        `https://api.github.com/repos/${DATA_REPO_OWNER}/${DATA_REPO_NAME}/contents/${path}`,
        { method: 'PUT', headers: githubHeaders(), body: JSON.stringify(body) }
    );
    if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.message || `GitHub API error ${resp.status}`);
    }
    return resp.json();
}

// ============================================================
// GITHUB MODE – ACCOUNT CREATION
// ============================================================

async function createAccountGitHub(username, email, password) {
    const usernameLower = username.toLowerCase();
    const emailLower    = email.toLowerCase();
    const passwordHash  = await hashPassword(password, username);

    // Check for duplicate username
    const existing = await githubRead(`accounts/${usernameLower}/profile.json`);
    if (existing) {
        return { success: false, message: 'Username already exists' };
    }

    // Check for duplicate email via index
    const indexFile = await githubRead('accounts/email-index.json');
    const emailMap  = indexFile ? indexFile.content : {};
    if (emailMap[emailLower]) {
        return { success: false, message: 'Email already registered' };
    }

    // Create account profile file (one folder per user)
    await githubWrite(
        `accounts/${usernameLower}/profile.json`,
        { username, email, password_hash: passwordHash, created_at: new Date().toISOString() },
        `Create account: ${username}`
    );

    // Update email index (up to 3 attempts to handle concurrent write conflicts)
    emailMap[emailLower] = usernameLower;
    let indexRef = indexFile;
    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            const map = indexRef ? { ...indexRef.content } : {};
            map[emailLower] = usernameLower;
            await githubWrite(
                'accounts/email-index.json',
                map,
                `Add email index for: ${username}`,
                indexRef ? indexRef.sha : undefined
            );
            break; // success – exit loop
        } catch (err) {
            if (attempt < 2) {
                // Re-read for updated SHA, then retry with brief backoff
                indexRef = await githubRead('accounts/email-index.json');
                await new Promise(r => setTimeout(r, 200 * (attempt + 1)));
            } else {
                throw err;
            }
        }
    }

    return { success: true, message: 'Account created successfully' };
}

// ============================================================
// GITHUB MODE – LOGIN VERIFICATION
// ============================================================

async function verifyAccountGitHub(identifier, password) {
    let accountKey;
    if (identifier.includes('@')) {
        // Email login: look up username via email index
        const indexFile = await githubRead('accounts/email-index.json');
        if (!indexFile) return { success: false, message: 'Account not found' };
        accountKey = indexFile.content[identifier.toLowerCase()];
        if (!accountKey) return { success: false, message: 'Account not found' };
    } else {
        accountKey = identifier.toLowerCase();
    }

    const accountFile = await githubRead(`accounts/${accountKey}/profile.json`);
    if (!accountFile) return { success: false, message: 'Account not found' };

    const account   = accountFile.content;
    const inputHash = await hashPassword(password, account.username);
    if (account.password_hash !== inputHash) {
        return { success: false, message: 'Invalid password' };
    }

    return {
        success: true,
        message: 'Login successful',
        user: { username: account.username, email: account.email }
    };
}

// ============================================================
// DEMO MODE FUNCTIONS (localStorage-based account system)
// ============================================================

/**
 * Get all accounts from localStorage
 */
function getDemoAccounts() {
    const accounts = localStorage.getItem('gameOS_accounts');
    return accounts ? JSON.parse(accounts) : [];
}

/**
 * Save accounts to localStorage
 */
function saveDemoAccounts(accounts) {
    localStorage.setItem('gameOS_accounts', JSON.stringify(accounts));
}

/**
 * Create account in demo mode
 */
async function createAccountDemo(username, email, password) {
    // Hash password first (outside Promise)
    const passwordHash = await hashPasswordDemo(password);
    
    return new Promise((resolve) => {
        setTimeout(() => {
            const accounts = getDemoAccounts();
            
            // Check if username already exists
            if (accounts.find(acc => acc.username.toLowerCase() === username.toLowerCase())) {
                resolve({
                    success: false,
                    message: 'Username already exists'
                });
                return;
            }
            
            // Check if email already exists
            if (accounts.find(acc => acc.email.toLowerCase() === email.toLowerCase())) {
                resolve({
                    success: false,
                    message: 'Email already registered'
                });
                return;
            }
            
            // Create new account
            const newAccount = {
                username: username,
                email: email,
                password_hash: passwordHash, // Hashed password
                createdAt: new Date().toISOString()
            };
            
            accounts.push(newAccount);
            saveDemoAccounts(accounts);
            
            console.log('✅ Demo account created:', { username, email });
            
            resolve({
                success: true,
                message: 'Account created successfully'
            });
        }, 500); // Simulate network delay
    });
}

/**
 * Verify account in demo mode
 */
async function verifyAccountDemo(identifier, password) {
    // Hash password first (outside Promise)
    const passwordHash = await hashPasswordDemo(password);
    
    return new Promise((resolve) => {
        setTimeout(() => {
            const accounts = getDemoAccounts();
            
            // Find account by email or username
            const account = accounts.find(acc => 
                acc.email.toLowerCase() === identifier.toLowerCase() || 
                acc.username.toLowerCase() === identifier.toLowerCase()
            );
            
            if (!account) {
                resolve({
                    success: false,
                    message: 'Account not found'
                });
                return;
            }
            
            // Compare hashed passwords
            if (account.password_hash !== passwordHash) {
                resolve({
                    success: false,
                    message: 'Invalid password'
                });
                return;
            }
            
            console.log('✅ Demo login successful:', account.username);
            
            resolve({
                success: true,
                message: 'Login successful',
                user: {
                    username: account.username,
                    email: account.email
                }
            });
        }, 500); // Simulate network delay
    });
}

// ============================================================
// SIGNUP HANDLER
// ============================================================

async function handleSignup(event) {
    event.preventDefault();
    
    const messageDiv = document.getElementById('signupMessage');
    const username = document.getElementById('signupUsername').value.trim();
    const email = document.getElementById('signupEmail').value.trim();
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    const agreeTerms = document.getElementById('agreeTerms').checked;
    
    // Clear previous messages
    clearMessage(messageDiv);
    
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
    
    // Show loading state
    showMessage(messageDiv, '⏳ Creating your account... Please wait.', 'info');
    disableForm('signupForm');
    
    try {
        // Wait for mode detection to complete before proceeding (fixes race condition)
        await modeReady;
        let data;
        
        if (MODE === 'demo') {
            // Use demo mode (localStorage)
            data = await createAccountDemo(username, email, password);
        } else {
            // GitHub mode – write directly to the private data repository
            data = await createAccountGitHub(username, email, password);
        }
        
        if (data.success) {
            // Success!
            showMessage(messageDiv, 
                '✅ Account created successfully! You can now login. Redirecting...', 
                'success'
            );
            
            // Store username/email for convenience
            localStorage.setItem('lastUsername', username);
            localStorage.setItem('lastEmail', email);
            
            // Clear form
            document.getElementById('signupForm').reset();
            
            // Redirect to login page after 3 seconds
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 3000);
        } else {
            // Handle error from backend
            const errorMessage = data.message || 'Failed to create account. Please try again.';
            showMessage(messageDiv, '❌ ' + errorMessage, 'error');
            enableForm('signupForm');
        }
    } catch (error) {
        // GitHub API failed – switch to demo mode and retry
        console.error('Signup error:', error);
        if (MODE === 'github') {
            MODE = 'demo';
            console.warn('GitHub unavailable – retrying in demo (localStorage) mode');
            try {
                const fallback = await createAccountDemo(username, email, password);
                if (fallback.success) {
                    showMessage(messageDiv,
                        '✅ Account created (GitHub unavailable – saved locally). You can now login. Redirecting...',
                        'success'
                    );
                    localStorage.setItem('lastUsername', username);
                    localStorage.setItem('lastEmail', email);
                    document.getElementById('signupForm').reset();
                    setTimeout(() => { window.location.href = 'login.html'; }, 3000);
                } else {
                    showMessage(messageDiv, '❌ ' + (fallback.message || 'Failed to create account. Please try again.'), 'error');
                    enableForm('signupForm');
                }
                return;
            } catch (demoErr) {
                console.error('Demo fallback error:', demoErr);
            }
        }
        showMessage(messageDiv, '❌ Failed to create account. Please check your details and try again.', 'error');
        enableForm('signupForm');
    }
}

// ============================================================
// LOGIN HANDLER
// ============================================================

async function handleLogin(event) {
    event.preventDefault();
    
    const messageDiv = document.getElementById('loginMessage');
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    
    // Clear previous messages
    clearMessage(messageDiv);
    
    // Basic validation
    if (!email) {
        showMessage(messageDiv, 'Please enter your email', 'error');
        return;
    }
    
    if (!password) {
        showMessage(messageDiv, 'Please enter your password', 'error');
        return;
    }
    
    // Send the email/username as-is; backend will handle the lookup
    const loginIdentifier = email;
    
    // Show loading state
    showMessage(messageDiv, '⏳ Verifying credentials... Please wait.', 'info');
    disableForm('loginForm');
    
    try {
        // Wait for mode detection to complete before proceeding (fixes race condition)
        await modeReady;
        let data;
        
        if (MODE === 'demo') {
            // Use demo mode (localStorage)
            data = await verifyAccountDemo(loginIdentifier, password);
        } else {
            // GitHub mode – read from the private data repository
            data = await verifyAccountGitHub(loginIdentifier, password);
        }
        
        if (data.success) {
            // Extract user info
            const username = data.user ? data.user.username : '';
            const email = data.user ? data.user.email : '';
            
            // Validate we have user data
            if (!username || !email) {
                console.warn('⚠️ Backend response missing user data');
                showMessage(messageDiv, 
                    '⚠️ Login successful but user data incomplete. Please try again.', 
                    'warning'
                );
                enableForm('loginForm');
                return;
            }
            
            // Success!
            showMessage(messageDiv, 
                `✅ Welcome back, ${username}! Login successful.`, 
                'success'
            );
            
            // Create user session
            const userSession = {
                username: username,
                email: email,
                loginTime: new Date().toISOString()
            };
            
            // Store session
            if (rememberMe) {
                localStorage.setItem('gameOSUser', JSON.stringify(userSession));
            } else {
                sessionStorage.setItem('gameOSUser', JSON.stringify(userSession));
            }
            
            // Redirect after 2 seconds
            setTimeout(() => {
                window.location.href = 'index.html';
            }, 2000);
        } else {
            // Handle error from backend
            showMessage(messageDiv, 
                '❌ Invalid email or password. Please try again.', 
                'error'
            );
            enableForm('loginForm');
        }
    } catch (error) {
        // GitHub API failed – switch to demo mode and retry
        console.error('Login error:', error);
        if (MODE === 'github') {
            MODE = 'demo';
            console.warn('GitHub unavailable – retrying in demo (localStorage) mode');
            try {
                const fallback = await verifyAccountDemo(loginIdentifier, password);
                if (fallback.success) {
                    const username = fallback.user ? fallback.user.username : '';
                    const userEmail = fallback.user ? fallback.user.email : '';
                    if (username && userEmail) {
                        showMessage(messageDiv, `✅ Welcome back, ${username}! Login successful.`, 'success');
                        const userSession = { username, email: userEmail, loginTime: new Date().toISOString() };
                        if (rememberMe) {
                            localStorage.setItem('gameOSUser', JSON.stringify(userSession));
                        } else {
                            sessionStorage.setItem('gameOSUser', JSON.stringify(userSession));
                        }
                        setTimeout(() => { window.location.href = 'index.html'; }, 2000);
                        return;
                    }
                } else {
                    showMessage(messageDiv, '❌ Invalid email or password. Please try again.', 'error');
                    enableForm('loginForm');
                    return;
                }
            } catch (demoErr) {
                console.error('Demo fallback error:', demoErr);
            }
        }
        showMessage(messageDiv, '❌ Failed to login. Please check your credentials and try again.', 'error');
        enableForm('loginForm');
    }
}

// ============================================================
// USER SESSION DISPLAY
// ============================================================

function displayCurrentUser() {
    const user = getCurrentUser();
    const userDisplayElement = document.getElementById('userDisplay');
    const guestNav = document.getElementById('guestNav');
    const userNav  = document.getElementById('userNav');

    if (user) {
        // Show user info banner (home page only)
        if (userDisplayElement) {
            userDisplayElement.innerHTML = `
                <div class="user-info">
                    <span class="welcome-text">Welcome, <strong>${user.username}</strong>!</span>
                    <a href="account.html" class="btn btn-secondary" style="text-decoration:none;">My Account</a>
                </div>
            `;
        }
        // Toggle nav: hide guest links, show user links
        if (guestNav) guestNav.classList.add('hidden');
        if (userNav)  userNav.classList.remove('hidden');
        // Toggle home-page CTA buttons
        const guestCta = document.getElementById('guestCta');
        const userCta  = document.getElementById('userCta');
        if (guestCta) guestCta.classList.add('hidden');
        if (userCta)  userCta.classList.remove('hidden');
    } else {
        // Ensure guest state is visible
        if (guestNav) guestNav.classList.remove('hidden');
        if (userNav)  userNav.classList.add('hidden');
    }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function showMessage(element, message, type) {
    if (element) {
        element.textContent = message;
        element.className = 'message ' + type;
        element.style.display = 'block';
    }
}

function clearMessage(element) {
    if (element) {
        element.textContent = '';
        element.className = 'message';
        element.style.display = 'none';
    }
}

function disableForm(formId) {
    const form = document.getElementById(formId);
    if (form) {
        const inputs = form.querySelectorAll('input, button');
        inputs.forEach(input => {
            input.disabled = true;
            input.style.opacity = '0.6';
        });
    }
}

function enableForm(formId) {
    const form = document.getElementById(formId);
    if (form) {
        const inputs = form.querySelectorAll('input, button');
        inputs.forEach(input => {
            input.disabled = false;
            input.style.opacity = '1';
        });
    }
}

// ============================================================
// SESSION MANAGEMENT
// ============================================================

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    const user = localStorage.getItem('gameOSUser') || sessionStorage.getItem('gameOSUser');
    return user !== null;
}

/**
 * Get current user information
 */
function getCurrentUser() {
    const userStr = localStorage.getItem('gameOSUser') || sessionStorage.getItem('gameOSUser');
    return userStr ? JSON.parse(userStr) : null;
}

/**
 * Logout user
 */
function logout() {
    localStorage.removeItem('gameOSUser');
    sessionStorage.removeItem('gameOSUser');
    window.location.href = 'login.html';
}

/**
 * Require login for protected pages
 * Call this at the top of pages that require authentication
 */
function requireLogin() {
    if (!isLoggedIn()) {
        window.location.href = 'login.html';
    }
}

// ============================================================
// MY ACCOUNT PAGE – DISPLAY & UPDATE
// ============================================================

/**
 * Populate account detail fields on the My Account page.
 */
function populateAccountDetails() {
    const user = getCurrentUser();
    if (!user) return;
    const usernameEl = document.getElementById('displayUsername');
    const emailEl    = document.getElementById('displayEmail');
    const joinedEl   = document.getElementById('displayJoined');
    if (usernameEl) usernameEl.textContent = user.username;
    if (emailEl)    emailEl.textContent    = user.email;
    if (joinedEl)   joinedEl.textContent   = user.loginTime
        ? new Date(user.loginTime).toLocaleDateString(undefined, { year:'numeric', month:'long', day:'numeric' })
        : '—';
}

/**
 * Handle the update account form submission.
 */
async function handleAccountUpdate(event) {
    event.preventDefault();
    const messageDiv       = document.getElementById('updateMessage');
    const newEmail         = document.getElementById('updateEmail').value.trim();
    const currentPassword  = document.getElementById('updateCurrentPassword').value;
    const newPassword      = document.getElementById('updateNewPassword').value;
    const confirmPassword  = document.getElementById('updateConfirmPassword').value;
    const user             = getCurrentUser();

    clearMessage(messageDiv);

    if (!currentPassword) {
        showMessage(messageDiv, 'Please enter your current password to make changes.', 'error');
        return;
    }
    if (newEmail && !validateEmail(newEmail)) {
        showMessage(messageDiv, 'Please enter a valid email address.', 'error');
        return;
    }
    if (newPassword && newPassword.length < 6) {
        showMessage(messageDiv, 'New password must be at least 6 characters.', 'error');
        return;
    }
    if (newPassword && newPassword !== confirmPassword) {
        showMessage(messageDiv, 'New passwords do not match.', 'error');
        return;
    }
    if (!newEmail && !newPassword) {
        showMessage(messageDiv, 'No changes to save – enter a new email or password.', 'info');
        return;
    }

    showMessage(messageDiv, '⏳ Saving changes… Please wait.', 'info');
    disableForm('updateForm');

    try {
        let result;
        if (MODE === 'demo') {
            result = await updateAccountDemo(user.username, currentPassword, newEmail || null, newPassword || null);
        } else {
            result = await updateAccountGitHub(user.username, currentPassword, newEmail || null, newPassword || null);
        }

        if (result.success) {
            // Refresh stored session with updated info
            const sessionKey = localStorage.getItem('gameOSUser') ? 'localStorage' : 'sessionStorage';
            const updatedUser = { ...user, email: result.email };
            if (sessionKey === 'localStorage') {
                localStorage.setItem('gameOSUser', JSON.stringify(updatedUser));
            } else {
                sessionStorage.setItem('gameOSUser', JSON.stringify(updatedUser));
            }
            populateAccountDetails();
            showMessage(messageDiv, '✅ Account updated successfully!', 'success');
            document.getElementById('updateForm').reset();
        } else {
            showMessage(messageDiv, '❌ ' + result.message, 'error');
        }
    } catch (err) {
        console.error('Update error:', err);
        showMessage(messageDiv, '❌ Failed to update account. Please try again.', 'error');
    }
    enableForm('updateForm');
}

// ============================================================
// DEMO MODE – ACCOUNT UPDATE
// ============================================================

async function updateAccountDemo(username, currentPassword, newEmail, newPassword) {
    const currentHash = await hashPasswordDemo(currentPassword);
    const accounts = getDemoAccounts();
    const idx = accounts.findIndex(a => a.username.toLowerCase() === username.toLowerCase());
    if (idx === -1) return { success: false, message: 'Account not found.' };
    if (accounts[idx].password_hash !== currentHash) {
        return { success: false, message: 'Current password is incorrect.' };
    }
    if (newEmail) {
        const emailTaken = accounts.some((a, i) => i !== idx && a.email.toLowerCase() === newEmail.toLowerCase());
        if (emailTaken) return { success: false, message: 'Email already in use by another account.' };
        accounts[idx].email = newEmail;
    }
    if (newPassword) {
        accounts[idx].password_hash = await hashPasswordDemo(newPassword);
    }
    saveDemoAccounts(accounts);
    return { success: true, message: 'Account updated.', email: accounts[idx].email };
}

// ============================================================
// GITHUB MODE – ACCOUNT UPDATE
// ============================================================

async function updateAccountGitHub(username, currentPassword, newEmail, newPassword) {
    const usernameLower = username.toLowerCase();
    const accountFile   = await githubRead(`accounts/${usernameLower}/profile.json`);
    if (!accountFile) return { success: false, message: 'Account not found.' };
    const account = accountFile.content;

    // Verify current password
    const currentHash = await hashPassword(currentPassword, account.username);
    if (account.password_hash !== currentHash) {
        return { success: false, message: 'Current password is incorrect.' };
    }

    let updated = { ...account };

    // Handle email change
    if (newEmail && newEmail.toLowerCase() !== account.email.toLowerCase()) {
        const emailLower   = newEmail.toLowerCase();
        const indexFile    = await githubRead('accounts/email-index.json');
        const emailMap     = indexFile ? { ...indexFile.content } : {};
        if (emailMap[emailLower] && emailMap[emailLower] !== usernameLower) {
            return { success: false, message: 'Email already in use by another account.' };
        }
        // Remove old email, add new
        delete emailMap[account.email.toLowerCase()];
        emailMap[emailLower] = usernameLower;
        await githubWrite(
            'accounts/email-index.json',
            emailMap,
            `Update email index for: ${username}`,
            indexFile ? indexFile.sha : undefined
        );
        updated.email = newEmail;
    }

    // Handle password change
    if (newPassword) {
        updated.password_hash = await hashPassword(newPassword, account.username);
    }

    await githubWrite(
        `accounts/${usernameLower}/profile.json`,
        updated,
        `Update account: ${username}`,
        accountFile.sha
    );

    return { success: true, message: 'Account updated.', email: updated.email };
}

// ============================================================
// GITHUB MODE – FRIENDS
// ============================================================

async function addFriendGitHub(username, friendUsername) {
    const usernameLower = username.toLowerCase();
    const friendLower   = friendUsername.toLowerCase();

    if (usernameLower === friendLower) {
        return { success: false, message: 'You cannot add yourself as a friend' };
    }

    // Check friend exists
    const friendFile = await githubRead(`accounts/${friendLower}/profile.json`);
    if (!friendFile) return { success: false, message: 'User not found' };

    const friendsPath = `accounts/${usernameLower}/friends.json`;
    const friendsFile = await githubRead(friendsPath);
    const friends     = friendsFile ? [...friendsFile.content] : [];

    if (friends.some(f => f.toLowerCase() === friendLower)) {
        return { success: false, message: 'Already friends with this user' };
    }

    friends.push(friendFile.content.username);
    await githubWrite(
        friendsPath,
        friends,
        `Add friend ${friendUsername} for: ${username}`,
        friendsFile ? friendsFile.sha : undefined
    );
    return { success: true, message: `${friendFile.content.username} added as a friend`, friends };
}

async function getFriendsGitHub(username) {
    const friendsFile = await githubRead(`accounts/${username.toLowerCase()}/friends.json`);
    return friendsFile ? friendsFile.content : [];
}

async function removeFriendGitHub(username, friendUsername) {
    const friendsPath = `accounts/${username.toLowerCase()}/friends.json`;
    const friendsFile = await githubRead(friendsPath);
    if (!friendsFile) return { success: false, message: 'Friends list not found' };

    const updated = friendsFile.content.filter(f => f.toLowerCase() !== friendUsername.toLowerCase());
    await githubWrite(
        friendsPath,
        updated,
        `Remove friend ${friendUsername} for: ${username}`,
        friendsFile.sha
    );
    return { success: true, friends: updated };
}

// ============================================================
// DEMO MODE – FRIENDS
// ============================================================

function getDemoFriends(username) {
    const key = `gameOS_friends_${username.toLowerCase()}`;
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : [];
}

function saveDemoFriends(username, friends) {
    localStorage.setItem(`gameOS_friends_${username.toLowerCase()}`, JSON.stringify(friends));
}

async function addFriendDemo(username, friendUsername) {
    if (username.toLowerCase() === friendUsername.toLowerCase()) {
        return { success: false, message: 'You cannot add yourself as a friend' };
    }
    const accounts = getDemoAccounts();
    const friendAccount = accounts.find(a => a.username.toLowerCase() === friendUsername.toLowerCase());
    if (!friendAccount) return { success: false, message: 'User not found' };

    const friends = getDemoFriends(username);
    if (friends.some(f => f.toLowerCase() === friendUsername.toLowerCase())) {
        return { success: false, message: 'Already friends with this user' };
    }
    friends.push(friendAccount.username);
    saveDemoFriends(username, friends);
    return { success: true, message: `${friendAccount.username} added as a friend`, friends };
}

async function removeFriendDemo(username, friendUsername) {
    const friends = getDemoFriends(username);
    const updated = friends.filter(f => f.toLowerCase() !== friendUsername.toLowerCase());
    saveDemoFriends(username, updated);
    return { success: true, friends: updated };
}

// ============================================================
// FRIENDS UI HELPERS
// ============================================================

async function loadFriendsList() {
    const user = getCurrentUser();
    if (!user) return;
    const listEl    = document.getElementById('friendsList');
    const countEl   = document.getElementById('friendsCount');
    if (!listEl) return;

    listEl.innerHTML = '<p style="color:#666;font-size:0.9em;">Loading…</p>';
    try {
        let friends;
        if (MODE === 'demo') {
            friends = getDemoFriends(user.username);
        } else {
            friends = await getFriendsGitHub(user.username);
        }
        if (countEl) countEl.textContent = friends.length;
        if (friends.length === 0) {
            listEl.innerHTML = '<p style="color:#666;font-size:0.9em;">No friends yet. Search above to add someone!</p>';
            return;
        }
        listEl.innerHTML = friends.map(f => `
            <div class="friend-item">
                <span class="friend-name">👤 ${f}</span>
                <button class="btn-remove-friend" onclick="handleRemoveFriend('${f}')">Remove</button>
            </div>
        `).join('');
    } catch (err) {
        listEl.innerHTML = '<p style="color:#c00;">Failed to load friends.</p>';
    }
}

async function handleAddFriend() {
    const input    = document.getElementById('friendSearch');
    const msgEl    = document.getElementById('friendMessage');
    const user     = getCurrentUser();
    if (!input || !user) return;
    const target   = input.value.trim();
    if (!target) {
        showMessage(msgEl, 'Please enter a username to add.', 'error');
        return;
    }
    clearMessage(msgEl);
    showMessage(msgEl, '⏳ Adding friend…', 'info');
    try {
        let result;
        if (MODE === 'demo') {
            result = await addFriendDemo(user.username, target);
        } else {
            result = await addFriendGitHub(user.username, target);
        }
        if (result.success) {
            showMessage(msgEl, `✅ ${result.message}`, 'success');
            input.value = '';
            loadFriendsList();
        } else {
            showMessage(msgEl, `❌ ${result.message}`, 'error');
        }
    } catch (err) {
        showMessage(msgEl, '❌ Failed to add friend. Please try again.', 'error');
    }
}

async function handleRemoveFriend(friendUsername) {
    const msgEl = document.getElementById('friendMessage');
    const user  = getCurrentUser();
    if (!user) return;
    clearMessage(msgEl);
    try {
        let result;
        if (MODE === 'demo') {
            result = await removeFriendDemo(user.username, friendUsername);
        } else {
            result = await removeFriendGitHub(user.username, friendUsername);
        }
        if (result.success) {
            loadFriendsList();
        } else {
            showMessage(msgEl, `❌ ${result.message}`, 'error');
        }
    } catch (err) {
        showMessage(msgEl, '❌ Failed to remove friend. Please try again.', 'error');
    }
}

// ============================================================
// RESET ALL ACCOUNTS
// ============================================================

/**
 * Delete all account data from the private GitHub data repository.
 * Lists every item inside accounts/, deletes files in user sub-folders,
 * then deletes email-index.json and any other top-level files.
 */
async function resetAllAccountsGitHub() {
    const resp = await fetch(
        `https://api.github.com/repos/${DATA_REPO_OWNER}/${DATA_REPO_NAME}/contents/accounts`,
        { headers: githubHeaders() }
    );
    if (resp.status === 404) return; // Nothing to delete
    if (!resp.ok) throw new Error(`GitHub API error ${resp.status}`);
    const items = await resp.json();

    for (const item of items) {
        if (item.type === 'dir') {
            // List files inside the user sub-folder and delete each one
            const folderResp = await fetch(item.url, { headers: githubHeaders() });
            if (folderResp.ok) {
                const files = await folderResp.json();
                for (const file of files) {
                    await githubDelete(file.path, file.sha, `Reset: delete ${file.path}`);
                }
            }
        } else {
            await githubDelete(item.path, item.sha, `Reset: delete ${item.path}`);
        }
    }
}

/**
 * Remove all demo-mode account data from localStorage.
 */
function resetAllAccountsDemo() {
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key === 'gameOS_accounts' || key.startsWith('gameOS_friends_'))) {
            keysToRemove.push(key);
        }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));
    // Also clear the active session
    localStorage.removeItem('gameOSUser');
    sessionStorage.removeItem('gameOSUser');
}

/**
 * UI handler – asks for confirmation then wipes all accounts in the active mode.
 */
async function handleResetAllAccounts() {
    const msgEl = document.getElementById('resetMessage');
    const btn   = document.getElementById('resetAllBtn');

    if (!confirm(
        '⚠️ WARNING: This will permanently delete ALL accounts and cannot be undone.\n\n' +
        'Are you absolutely sure you want to continue?'
    )) return;

    if (msgEl) showMessage(msgEl, '⏳ Removing all accounts… Please wait.', 'info');
    if (btn)   btn.disabled = true;

    try {
        await modeReady;
        if (MODE === 'demo') {
            resetAllAccountsDemo();
        } else {
            await resetAllAccountsGitHub();
            // Clear local session too
            localStorage.removeItem('gameOSUser');
            sessionStorage.removeItem('gameOSUser');
        }
        if (msgEl) showMessage(msgEl, '✅ All accounts have been removed. Redirecting to login…', 'success');
        setTimeout(() => { window.location.href = 'login.html'; }, 2500);
    } catch (err) {
        console.error('Reset error:', err);
        if (msgEl) showMessage(msgEl, '❌ Failed to remove accounts. Please try again.', 'error');
        if (btn)   btn.disabled = false;
    }
}

// Export functions for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        isLoggedIn,
        getCurrentUser,
        logout,
        requireLogin
    };
}
