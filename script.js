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
        loadInbox();

        // Poll every 5 seconds so friend requests appear without a manual refresh.
        // Polling is paused while the tab is hidden to avoid unnecessary API calls.
        const POLL_INTERVAL_MS = 5000;
        const pollTimer = setInterval(() => {
            if (!document.hidden) {
                loadFriendsList();
                loadInbox();
            }
        }, POLL_INTERVAL_MS);

        // When the tab becomes visible again, refresh immediately then let the
        // regular interval continue.
        function onVisibilityChange() {
            if (!document.hidden) {
                loadFriendsList();
                loadInbox();
            }
        }
        document.addEventListener('visibilitychange', onVisibilityChange);

        // Clean up when the page is unloaded to avoid memory leaks.
        window.addEventListener('pagehide', () => {
            clearInterval(pollTimer);
            document.removeEventListener('visibilitychange', onVisibilityChange);
        }, { once: true });
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
        { headers: githubHeaders(), cache: 'no-store' }
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
                    <span class="welcome-text">👋 Welcome back, <strong>${user.username}</strong>!</span>
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

    // Check if already accepted friends
    const friendsPath = `accounts/${usernameLower}/friends.json`;
    const friendsFile = await githubRead(friendsPath);
    const friends     = friendsFile ? [...friendsFile.content] : [];
    if (friends.some(f => f.toLowerCase() === friendLower)) {
        return { success: false, message: 'Already friends with this user' };
    }

    // Check if they already sent us a request → auto-accept
    const myRequestsPath = `accounts/${usernameLower}/friend_requests.json`;
    const myRequestsFile = await githubRead(myRequestsPath);
    const myRequests     = myRequestsFile ? myRequestsFile.content : [];
    if (myRequests.some(r => r.from.toLowerCase() === friendLower)) {
        return await acceptFriendRequestGitHub(username, friendFile.content.username);
    }

    // Check if we already sent them a request
    const sentPath = `accounts/${usernameLower}/sent_requests.json`;
    const sentFile = await githubRead(sentPath);
    const sent     = sentFile ? [...sentFile.content] : [];
    if (sent.some(s => s.toLowerCase() === friendLower)) {
        return { success: false, message: 'Friend request already pending' };
    }

    // Add to recipient's incoming requests
    const theirRequestsPath = `accounts/${friendLower}/friend_requests.json`;
    const theirRequestsFile = await githubRead(theirRequestsPath);
    const theirRequests     = theirRequestsFile ? [...theirRequestsFile.content] : [];
    theirRequests.push({ from: username, sentAt: new Date().toISOString() });
    await githubWrite(
        theirRequestsPath,
        theirRequests,
        `Friend request from ${username} to ${friendUsername}`,
        theirRequestsFile ? theirRequestsFile.sha : undefined
    );

    // Add to sender's outgoing requests
    sent.push(friendFile.content.username);
    await githubWrite(
        sentPath,
        sent,
        `Sent friend request to ${friendUsername} for: ${username}`,
        sentFile ? sentFile.sha : undefined
    );

    return { success: true, message: `Friend request sent to ${friendFile.content.username}! Waiting for them to accept.` };
}

async function acceptFriendRequestGitHub(username, fromUsername) {
    const usernameLower = username.toLowerCase();
    const fromLower     = fromUsername.toLowerCase();

    // Remove from recipient's incoming requests
    const requestsPath = `accounts/${usernameLower}/friend_requests.json`;
    const requestsFile = await githubRead(requestsPath);
    if (!requestsFile) return { success: false, message: 'Friend request not found' };
    const updatedRequests = requestsFile.content.filter(r => r.from.toLowerCase() !== fromLower);
    if (updatedRequests.length === requestsFile.content.length) {
        return { success: false, message: 'Friend request not found' };
    }
    await githubWrite(requestsPath, updatedRequests, `Accept friend request from ${fromUsername}`, requestsFile.sha);

    // Remove from sender's outgoing requests
    const sentPath = `accounts/${fromLower}/sent_requests.json`;
    const sentFile = await githubRead(sentPath);
    if (sentFile) {
        const updatedSent = sentFile.content.filter(s => s.toLowerCase() !== usernameLower);
        await githubWrite(sentPath, updatedSent, `Friend request accepted by ${username}`, sentFile.sha);
    }

    // Add sender to recipient's friends
    const myFriendsPath = `accounts/${usernameLower}/friends.json`;
    const myFriendsFile = await githubRead(myFriendsPath);
    const myFriends     = myFriendsFile ? [...myFriendsFile.content] : [];
    if (!myFriends.some(f => f.toLowerCase() === fromLower)) {
        const fromFile = await githubRead(`accounts/${fromLower}/profile.json`);
        myFriends.push(fromFile ? fromFile.content.username : fromUsername);
        await githubWrite(myFriendsPath, myFriends, `Add friend ${fromUsername} for: ${username}`, myFriendsFile ? myFriendsFile.sha : undefined);
    }

    // Add recipient to sender's friends
    const theirFriendsPath = `accounts/${fromLower}/friends.json`;
    const theirFriendsFile = await githubRead(theirFriendsPath);
    const theirFriends     = theirFriendsFile ? [...theirFriendsFile.content] : [];
    if (!theirFriends.some(f => f.toLowerCase() === usernameLower)) {
        const userFile = await githubRead(`accounts/${usernameLower}/profile.json`);
        theirFriends.push(userFile ? userFile.content.username : username);
        await githubWrite(theirFriendsPath, theirFriends, `Add friend ${username} for: ${fromUsername}`, theirFriendsFile ? theirFriendsFile.sha : undefined);
    }

    return { success: true, message: `You are now friends with ${fromUsername}!` };
}

async function declineFriendRequestGitHub(username, fromUsername) {
    const usernameLower = username.toLowerCase();
    const fromLower     = fromUsername.toLowerCase();

    // Remove from recipient's incoming requests
    const requestsPath = `accounts/${usernameLower}/friend_requests.json`;
    const requestsFile = await githubRead(requestsPath);
    if (!requestsFile) return { success: false, message: 'Friend request not found' };
    const updatedRequests = requestsFile.content.filter(r => r.from.toLowerCase() !== fromLower);
    await githubWrite(requestsPath, updatedRequests, `Decline friend request from ${fromUsername}`, requestsFile.sha);

    // Remove from sender's outgoing requests
    const sentPath = `accounts/${fromLower}/sent_requests.json`;
    const sentFile = await githubRead(sentPath);
    if (sentFile) {
        const updatedSent = sentFile.content.filter(s => s.toLowerCase() !== usernameLower);
        await githubWrite(sentPath, updatedSent, `Friend request declined by ${username}`, sentFile.sha);
    }

    return { success: true, message: 'Friend request declined.' };
}

async function cancelFriendRequestGitHub(username, toUsername) {
    const usernameLower = username.toLowerCase();
    const toLower       = toUsername.toLowerCase();

    // Remove from sender's outgoing requests
    const sentPath = `accounts/${usernameLower}/sent_requests.json`;
    const sentFile = await githubRead(sentPath);
    if (!sentFile) return { success: false, message: 'No sent requests found' };
    const updatedSent = sentFile.content.filter(s => s.toLowerCase() !== toLower);
    await githubWrite(sentPath, updatedSent, `Cancel friend request to ${toUsername}`, sentFile.sha);

    // Remove from recipient's incoming requests
    const theirRequestsPath = `accounts/${toLower}/friend_requests.json`;
    const theirRequestsFile = await githubRead(theirRequestsPath);
    if (theirRequestsFile) {
        const updatedRequests = theirRequestsFile.content.filter(r => r.from.toLowerCase() !== usernameLower);
        await githubWrite(theirRequestsPath, updatedRequests, `Friend request cancelled by ${username}`, theirRequestsFile.sha);
    }

    return { success: true };
}

async function getFriendsGitHub(username) {
    const friendsFile = await githubRead(`accounts/${username.toLowerCase()}/friends.json`);
    return friendsFile ? friendsFile.content : [];
}

async function getFriendRequestsGitHub(username) {
    const requestsFile = await githubRead(`accounts/${username.toLowerCase()}/friend_requests.json`);
    return requestsFile ? requestsFile.content : [];
}

async function getSentRequestsGitHub(username) {
    const sentFile = await githubRead(`accounts/${username.toLowerCase()}/sent_requests.json`);
    return sentFile ? sentFile.content : [];
}

async function removeFriendGitHub(username, friendUsername) {
    const usernameLower = username.toLowerCase();
    const friendLower   = friendUsername.toLowerCase();

    // Remove friend from requesting user's list
    const friendsPath = `accounts/${usernameLower}/friends.json`;
    const friendsFile = await githubRead(friendsPath);
    if (!friendsFile) return { success: false, message: 'Friends list not found' };

    const updated = friendsFile.content.filter(f => f.toLowerCase() !== friendLower);
    await githubWrite(
        friendsPath,
        updated,
        `Remove friend ${friendUsername} for: ${username}`,
        friendsFile.sha
    );

    // Also remove requesting user from the friend's list
    const theirFriendsPath = `accounts/${friendLower}/friends.json`;
    const theirFriendsFile = await githubRead(theirFriendsPath);
    if (theirFriendsFile) {
        const theirUpdated = theirFriendsFile.content.filter(f => f.toLowerCase() !== usernameLower);
        await githubWrite(
            theirFriendsPath,
            theirUpdated,
            `Remove friend ${username} for: ${friendUsername}`,
            theirFriendsFile.sha
        );
    }

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

function getDemoFriendRequests(username) {
    const key = `gameOS_friend_requests_${username.toLowerCase()}`;
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : [];
}

function saveDemoFriendRequests(username, requests) {
    localStorage.setItem(`gameOS_friend_requests_${username.toLowerCase()}`, JSON.stringify(requests));
}

function getDemoSentRequests(username) {
    const key = `gameOS_sent_requests_${username.toLowerCase()}`;
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : [];
}

function saveDemoSentRequests(username, sent) {
    localStorage.setItem(`gameOS_sent_requests_${username.toLowerCase()}`, JSON.stringify(sent));
}

async function addFriendDemo(username, friendUsername) {
    if (username.toLowerCase() === friendUsername.toLowerCase()) {
        return { success: false, message: 'You cannot add yourself as a friend' };
    }
    const accounts = getDemoAccounts();
    const friendAccount = accounts.find(a => a.username.toLowerCase() === friendUsername.toLowerCase());
    if (!friendAccount) return { success: false, message: 'User not found' };

    // Check already accepted friends
    const friends = getDemoFriends(username);
    if (friends.some(f => f.toLowerCase() === friendUsername.toLowerCase())) {
        return { success: false, message: 'Already friends with this user' };
    }

    // Check if they already sent us a request → auto-accept
    const myRequests = getDemoFriendRequests(username);
    if (myRequests.some(r => r.from.toLowerCase() === friendUsername.toLowerCase())) {
        return await acceptFriendRequestDemo(username, friendAccount.username);
    }

    // Check if we already sent them a request
    const sent = getDemoSentRequests(username);
    if (sent.some(s => s.toLowerCase() === friendUsername.toLowerCase())) {
        return { success: false, message: 'Friend request already pending' };
    }

    // Add to recipient's incoming requests
    const theirRequests = getDemoFriendRequests(friendUsername);
    theirRequests.push({ from: username, sentAt: new Date().toISOString() });
    saveDemoFriendRequests(friendUsername, theirRequests);

    // Add to sender's outgoing requests
    sent.push(friendAccount.username);
    saveDemoSentRequests(username, sent);

    return { success: true, message: `Friend request sent to ${friendAccount.username}! Waiting for them to accept.` };
}

async function acceptFriendRequestDemo(username, fromUsername) {
    // Remove from recipient's incoming requests
    const myRequests = getDemoFriendRequests(username);
    const updatedRequests = myRequests.filter(r => r.from.toLowerCase() !== fromUsername.toLowerCase());
    saveDemoFriendRequests(username, updatedRequests);

    // Remove from sender's outgoing requests
    const theirSent = getDemoSentRequests(fromUsername);
    const updatedSent = theirSent.filter(s => s.toLowerCase() !== username.toLowerCase());
    saveDemoSentRequests(fromUsername, updatedSent);

    // Add both as accepted friends
    const accounts = getDemoAccounts();
    const myFriends = getDemoFriends(username);
    if (!myFriends.some(f => f.toLowerCase() === fromUsername.toLowerCase())) {
        const fromAccount = accounts.find(a => a.username.toLowerCase() === fromUsername.toLowerCase());
        myFriends.push(fromAccount ? fromAccount.username : fromUsername);
        saveDemoFriends(username, myFriends);
    }
    const theirFriends = getDemoFriends(fromUsername);
    if (!theirFriends.some(f => f.toLowerCase() === username.toLowerCase())) {
        const userAccount = accounts.find(a => a.username.toLowerCase() === username.toLowerCase());
        theirFriends.push(userAccount ? userAccount.username : username);
        saveDemoFriends(fromUsername, theirFriends);
    }

    return { success: true, message: `You are now friends with ${fromUsername}!` };
}

async function declineFriendRequestDemo(username, fromUsername) {
    // Remove from recipient's incoming requests
    const myRequests = getDemoFriendRequests(username);
    const updatedRequests = myRequests.filter(r => r.from.toLowerCase() !== fromUsername.toLowerCase());
    saveDemoFriendRequests(username, updatedRequests);

    // Remove from sender's outgoing requests
    const theirSent = getDemoSentRequests(fromUsername);
    const updatedSent = theirSent.filter(s => s.toLowerCase() !== username.toLowerCase());
    saveDemoSentRequests(fromUsername, updatedSent);

    return { success: true, message: 'Friend request declined.' };
}

async function cancelFriendRequestDemo(username, toUsername) {
    // Remove from sender's outgoing requests
    const sent = getDemoSentRequests(username);
    const updatedSent = sent.filter(s => s.toLowerCase() !== toUsername.toLowerCase());
    saveDemoSentRequests(username, updatedSent);

    // Remove from recipient's incoming requests
    const theirRequests = getDemoFriendRequests(toUsername);
    const updatedRequests = theirRequests.filter(r => r.from.toLowerCase() !== username.toLowerCase());
    saveDemoFriendRequests(toUsername, updatedRequests);

    return { success: true };
}

async function removeFriendDemo(username, friendUsername) {
    // Remove friend from requesting user's list
    const friends = getDemoFriends(username);
    const updated = friends.filter(f => f.toLowerCase() !== friendUsername.toLowerCase());
    saveDemoFriends(username, updated);

    // Also remove requesting user from the friend's list
    const theirFriends = getDemoFriends(friendUsername);
    const theirUpdated = theirFriends.filter(f => f.toLowerCase() !== username.toLowerCase());
    saveDemoFriends(friendUsername, theirUpdated);

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

    await modeReady;
    listEl.innerHTML = '<p style="color:#666;font-size:0.9em;">Loading…</p>';
    try {
        let friends, sentRequests;
        if (MODE === 'demo') {
            friends      = getDemoFriends(user.username);
            sentRequests = getDemoSentRequests(user.username);
        } else {
            [friends, sentRequests] = await Promise.all([
                getFriendsGitHub(user.username),
                getSentRequestsGitHub(user.username)
            ]);
        }
        if (countEl) countEl.textContent = friends.length;

        let html = '';

        // Accepted friends
        html += friends.map(f => `
            <div class="friend-item">
                <span class="friend-name">👤 ${f}</span>
                <div class="friend-actions">
                    <a class="btn-message-friend" href="profile.html?user=${encodeURIComponent(f)}" style="text-decoration:none;">🎮 Games</a>
                    <button class="btn-message-friend" onclick="openChat('${f}')">💬 Message</button>
                    <button class="btn-remove-friend" onclick="handleRemoveFriend('${f}')">Remove</button>
                </div>
            </div>
        `).join('');

        // Outgoing pending requests
        if (sentRequests.length > 0) {
            html += '<div class="friend-requests-section" style="margin-top:12px;"><p class="friend-requests-title">⏳ Sent Requests</p>';
            html += sentRequests.map(s => `
                <div class="friend-item">
                    <span class="friend-name">👤 ${s}</span>
                    <span class="friend-pending-badge">⏳ Pending</span>
                    <button class="btn-remove-friend" onclick="handleCancelFriendRequest('${s}')">Cancel</button>
                </div>
            `).join('');
            html += '</div>';
        }

        if (!html) {
            html = '<p style="color:#666;font-size:0.9em;">No friends yet. Search above to add someone!</p>';
        }
        listEl.innerHTML = html;
    } catch (err) {
        listEl.innerHTML = '<p style="color:#c00;">Failed to load friends.</p>';
    }
}

async function loadInbox() {
    const user = getCurrentUser();
    if (!user) return;
    const inboxEl = document.getElementById('inboxList');
    const badgeEl = document.getElementById('inboxCount');
    if (!inboxEl) return;

    await modeReady;
    inboxEl.innerHTML = '<p style="color:#666;font-size:0.9em;">Loading…</p>';
    try {
        let incomingRequests, friends;
        if (MODE === 'demo') {
            incomingRequests = getDemoFriendRequests(user.username);
            friends = getDemoFriends(user.username);
        } else {
            [incomingRequests, friends] = await Promise.all([
                getFriendRequestsGitHub(user.username),
                getFriendsGitHub(user.username)
            ]);
        }

        // Build friend request items
        const requestItems = incomingRequests.map(r => `
            <div class="friend-item">
                <span class="friend-name">👤 ${r.from} <span style="color:#666;font-size:0.8em;font-weight:400;">wants to be friends</span></span>
                <div class="friend-actions">
                    <button class="btn-accept-friend" onclick="handleAcceptFriendRequest('${r.from}')">✅ Accept</button>
                    <button class="btn-decline-friend" onclick="handleDeclineFriendRequest('${r.from}')">❌ Decline</button>
                </div>
            </div>
        `);

        // Fetch unread messages from each friend (in parallel)
        const messageResults = await Promise.all(
            friends.map(friendName => {
                if (MODE === 'demo') {
                    return getMessagesDemo(user.username, friendName)
                        .then(result => ({ friendName, result }));
                } else {
                    return getMessagesGitHub(user.username, friendName)
                        .then(result => ({ friendName, result }));
                }
            })
        );
        const unreadItems = [];
        for (const { friendName, result } of messageResults) {
            if (!result.success) continue;
            const lastRead = getLastRead(user.username, friendName);
            const unread = result.messages.filter(m =>
                m.from.toLowerCase() !== user.username.toLowerCase() &&
                (!lastRead || m.sentAt > lastRead)
            );
            if (unread.length > 0) {
                const latest = unread[unread.length - 1];
                const label = unread.length > 1 ? `${unread.length} new messages` : 'sent a message';
                unreadItems.push(`
            <div class="friend-item">
                <span class="friend-name">💬 ${latest.from} <span style="color:#666;font-size:0.8em;font-weight:400;">${label}</span></span>
                <div class="friend-actions">
                    <button class="btn-message-friend" onclick="openChat('${latest.from}')">💬 Open Chat</button>
                </div>
            </div>
        `);
            }
        }

        const total = incomingRequests.length + unreadItems.length;
        if (badgeEl) {
            if (total > 0) {
                badgeEl.textContent = total;
                badgeEl.style.display = 'inline-block';
            } else {
                badgeEl.style.display = 'none';
            }
        }

        const allItems = [...requestItems, ...unreadItems];
        if (allItems.length === 0) {
            inboxEl.innerHTML = '<p style="color:#666;font-size:0.9em;">No pending requests or new messages.</p>';
            return;
        }
        inboxEl.innerHTML = allItems.join('');
    } catch (err) {
        inboxEl.innerHTML = '<p style="color:#c00;">Failed to load inbox.</p>';
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
    showMessage(msgEl, '⏳ Sending friend request…', 'info');
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
        showMessage(msgEl, '❌ Failed to send friend request. Please try again.', 'error');
    }
}

async function handleAcceptFriendRequest(fromUsername) {
    const msgEl = document.getElementById('friendMessage');
    const user  = getCurrentUser();
    if (!user) return;
    clearMessage(msgEl);
    showMessage(msgEl, '⏳ Accepting request…', 'info');
    try {
        let result;
        if (MODE === 'demo') {
            result = await acceptFriendRequestDemo(user.username, fromUsername);
        } else {
            result = await acceptFriendRequestGitHub(user.username, fromUsername);
        }
        if (result.success) {
            showMessage(msgEl, `✅ ${result.message}`, 'success');
            loadFriendsList();
            loadInbox();
        } else {
            showMessage(msgEl, `❌ ${result.message}`, 'error');
        }
    } catch (err) {
        showMessage(msgEl, '❌ Failed to accept request. Please try again.', 'error');
    }
}

async function handleDeclineFriendRequest(fromUsername) {
    const msgEl = document.getElementById('friendMessage');
    const user  = getCurrentUser();
    if (!user) return;
    clearMessage(msgEl);
    try {
        let result;
        if (MODE === 'demo') {
            result = await declineFriendRequestDemo(user.username, fromUsername);
        } else {
            result = await declineFriendRequestGitHub(user.username, fromUsername);
        }
        if (result.success) {
            loadFriendsList();
            loadInbox();
        } else {
            showMessage(msgEl, `❌ ${result.message}`, 'error');
        }
    } catch (err) {
        showMessage(msgEl, '❌ Failed to decline request. Please try again.', 'error');
    }
}

async function handleCancelFriendRequest(toUsername) {
    const msgEl = document.getElementById('friendMessage');
    const user  = getCurrentUser();
    if (!user) return;
    clearMessage(msgEl);
    try {
        let result;
        if (MODE === 'demo') {
            result = await cancelFriendRequestDemo(user.username, toUsername);
        } else {
            result = await cancelFriendRequestGitHub(user.username, toUsername);
        }
        if (result.success) {
            loadFriendsList();
        } else {
            showMessage(msgEl, `❌ ${result.message}`, 'error');
        }
    } catch (err) {
        showMessage(msgEl, '❌ Failed to cancel request. Please try again.', 'error');
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
// GITHUB MODE – MESSAGING
// ============================================================

/**
 * Returns the canonical conversation key for two users (sorted alphabetically).
 */
function conversationKey(userA, userB) {
    const [a, b] = [userA.toLowerCase(), userB.toLowerCase()].sort();
    return `accounts/messages/${a}_${b}.json`;
}

async function sendMessageGitHub(username, toUsername, text) {
    const profileFile = await githubRead(`accounts/${username.toLowerCase()}/profile.json`);
    if (!profileFile) return { success: false, message: 'Your account was not found' };

    const convPath = conversationKey(username, toUsername);
    const convFile = await githubRead(convPath);
    const messages = convFile ? [...convFile.content] : [];
    messages.push({ from: profileFile.content.username, text, sentAt: new Date().toISOString() });

    await githubWrite(convPath, messages, `Message from ${username} to ${toUsername}`, convFile ? convFile.sha : undefined);
    return { success: true };
}

async function getMessagesGitHub(username, withUsername) {
    const convPath = conversationKey(username, withUsername);
    const convFile = await githubRead(convPath);
    return { success: true, messages: convFile ? convFile.content : [] };
}

// ============================================================
// DEMO MODE – MESSAGING
// ============================================================

function demoConversationKey(userA, userB) {
    const [a, b] = [userA.toLowerCase(), userB.toLowerCase()].sort();
    return `gameOS_messages_${a}_${b}`;
}

function getDemoMessages(userA, userB) {
    const key  = demoConversationKey(userA, userB);
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : [];
}

function saveDemoMessages(userA, userB, messages) {
    localStorage.setItem(demoConversationKey(userA, userB), JSON.stringify(messages));
}

async function sendMessageDemo(username, toUsername, text) {
    const messages = getDemoMessages(username, toUsername);
    messages.push({ from: username, text, sentAt: new Date().toISOString() });
    saveDemoMessages(username, toUsername, messages);
    return { success: true };
}

async function getMessagesDemo(username, withUsername) {
    return { success: true, messages: getDemoMessages(username, withUsername) };
}

// ============================================================
// UNREAD MESSAGE TRACKING
// ============================================================

function lastReadKey(userA, userB) {
    const [a, b] = [userA.toLowerCase(), userB.toLowerCase()].sort();
    return `gameOS_lastRead_${a}_${b}`;
}

function getLastRead(userA, userB) {
    return localStorage.getItem(lastReadKey(userA, userB)) || null;
}

function markConversationRead(userA, userB) {
    localStorage.setItem(lastReadKey(userA, userB), new Date().toISOString());
}

// ============================================================
// MESSAGING UI
// ============================================================

let _chatPollId = null;

/** Close the chat panel and clear its polling interval. */
function closeChatPanel() {
    if (_chatPollId !== null) {
        clearInterval(_chatPollId);
        _chatPollId = null;
    }
    const panel = document.getElementById('chatPanel');
    if (panel) panel.remove();
}

/** Open (or focus) the chat panel for a given friend. */
function openChat(friendUsername) {
    // Remove any existing chat panel for a different user first
    closeChatPanel();

    const user = getCurrentUser();
    if (!user) return;

    // Mark conversation as read when chat is opened
    markConversationRead(user.username, friendUsername);
    loadInbox();

    const panel = document.createElement('div');
    panel.id        = 'chatPanel';
    panel.className = 'chat-panel';
    panel.innerHTML = `
        <div class="chat-header">
            <span>💬 Chat with ${friendUsername}</span>
            <button class="chat-close-btn" id="chatCloseBtn">✕</button>
        </div>
        <div class="chat-messages" id="chatMessages">
            <p style="color:#666;font-size:0.9em;text-align:center;">Loading…</p>
        </div>
        <div class="chat-input-row">
            <input type="text" id="chatInput" class="chat-input" placeholder="Type a message…" maxlength="1000" autocomplete="off">
            <button class="chat-send-btn" id="chatSendBtn">Send</button>
        </div>
    `;
    document.body.appendChild(panel);

    panel.querySelector('#chatCloseBtn').addEventListener('click', closeChatPanel);
    panel.querySelector('#chatSendBtn').addEventListener('click', () => handleSendMessage(friendUsername));
    panel.querySelector('#chatInput').addEventListener('keydown', e => {
        if (e.key === 'Enter') handleSendMessage(friendUsername);
    });

    refreshChatMessages(friendUsername);

    // Poll for new messages while this chat is open
    _chatPollId = setInterval(() => {
        if (!document.getElementById('chatPanel')) {
            clearInterval(_chatPollId);
            _chatPollId = null;
            return;
        }
        refreshChatMessages(friendUsername);
    }, 5000);
}

async function refreshChatMessages(friendUsername) {
    const panel = document.getElementById('chatPanel');
    if (!panel) return;
    const messagesEl = document.getElementById('chatMessages');
    const user = getCurrentUser();
    if (!messagesEl || !user) return;

    try {
        let result;
        if (MODE === 'demo') {
            result = await getMessagesDemo(user.username, friendUsername);
        } else {
            result = await getMessagesGitHub(user.username, friendUsername);
        }

        if (!result.success) return;
        const msgs = result.messages;

        if (msgs.length === 0) {
            messagesEl.innerHTML = '<p style="color:#666;font-size:0.9em;text-align:center;">No messages yet. Say hello! 👋</p>';
            return;
        }

        const wasAtBottom = messagesEl.scrollHeight - messagesEl.scrollTop <= messagesEl.clientHeight + 5;
        messagesEl.innerHTML = msgs.map(m => {
            const isMe = m.from.toLowerCase() === user.username.toLowerCase();
            const time = new Date(m.sentAt).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
            return `<div class="chat-message ${isMe ? 'chat-message-me' : 'chat-message-them'}">
                <span class="chat-bubble">${escapeHtml(m.text)}</span>
                <span class="chat-time">${time}</span>
            </div>`;
        }).join('');

        // Auto-scroll to bottom only when already at bottom or just opened
        if (wasAtBottom) messagesEl.scrollTop = messagesEl.scrollHeight;

        // Mark conversation as read since messages are now visible
        markConversationRead(user.username, friendUsername);
    } catch (err) {
        // Silently ignore polling errors
    }
}

async function handleSendMessage(friendUsername) {
    const input = document.getElementById('chatInput');
    const user  = getCurrentUser();
    if (!input || !user) return;
    const text = input.value.trim();
    if (!text) return;

    input.disabled = true;
    try {
        let result;
        if (MODE === 'demo') {
            result = await sendMessageDemo(user.username, friendUsername, text);
        } else {
            result = await sendMessageGitHub(user.username, friendUsername, text);
        }
        if (result.success) {
            input.value = '';
            await refreshChatMessages(friendUsername);
        }
    } catch (err) {
        console.error('Send message error:', err);
    }
    input.disabled = false;
    input.focus();
}

/** Escape HTML to prevent XSS in chat messages */
function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
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
        if (key && (key === 'gameOS_accounts' || key.startsWith('gameOS_friends_') || key.startsWith('gameOS_friend_requests_') || key.startsWith('gameOS_sent_requests_') || key.startsWith('gameOS_messages_') || key.startsWith('gameOS_lastRead_') || key.startsWith('gameOS_games_'))) {
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

// ============================================================
// GAMES DATABASE – FETCH FROM GITHUB RAW
// ============================================================

const GAMES_DB_RAW_BASE = 'https://raw.githubusercontent.com/Koriebonx98/Games.Database/main';

const GAMES_DB_PLATFORMS = [
    'PS3', 'PS4', 'Switch', 'Xbox 360'
];

async function fetchGamesDbPlatforms() {
    const available = [];
    await Promise.all(GAMES_DB_PLATFORMS.map(async platform => {
        try {
            const resp = await fetch(`${GAMES_DB_RAW_BASE}/${encodeURIComponent(platform)}.Games.json`);
            if (resp.ok) available.push(platform);
        } catch (_) {}
    }));
    // Return in the original order
    return GAMES_DB_PLATFORMS.filter(p => available.includes(p));
}

async function fetchGamesDbPlatform(platform) {
    const resp = await fetch(`${GAMES_DB_RAW_BASE}/${encodeURIComponent(platform)}.Games.json`);
    if (!resp.ok) throw new Error(`Failed to load ${platform} games`);
    const data = await resp.json();
    if (data.Games && Array.isArray(data.Games)) return data.Games;
    if (Array.isArray(data.games)) return data.games;
    if (Array.isArray(data)) return data;
    throw new Error('Invalid games JSON format');
}

// ============================================================
// GAME LIBRARY – GITHUB MODE
// ============================================================

async function getGameLibraryGitHub(username) {
    const file = await githubRead(`accounts/${username.toLowerCase()}/games.json`);
    return file ? file.content : [];
}

async function addGameGitHub(username, game, platform) {
    const path = `accounts/${username.toLowerCase()}/games.json`;
    const file = await githubRead(path);
    const library = file ? [...file.content] : [];

    // Deduplicate by platform + title (case-insensitive)
    const alreadyOwned = library.some(
        g => g.platform === platform &&
             (g.title || '').toLowerCase() === (game.Title || game.game_name || game.title || '').toLowerCase()
    );
    if (alreadyOwned) return { success: false, message: 'Game already in your library' };

    library.push({
        platform,
        title:    game.Title || game.game_name || game.title,
        titleId:  game.TitleID || game.title_id || game.id || null,
        coverUrl: getGameCoverUrl(game) || undefined,
        addedAt:  new Date().toISOString()
    });

    await githubWrite(path, library, `Add game: ${game.Title || game.title} (${platform})`, file ? file.sha : undefined);
    return { success: true, message: 'Game added to your library!' };
}

async function removeGameGitHub(username, platform, title) {
    const path = `accounts/${username.toLowerCase()}/games.json`;
    const file = await githubRead(path);
    if (!file) return { success: false, message: 'Library not found' };

    const updated = file.content.filter(
        g => !(g.platform === platform && (g.title || '').toLowerCase() === title.toLowerCase())
    );
    await githubWrite(path, updated, `Remove game: ${title} (${platform})`, file.sha);
    return { success: true, library: updated };
}

// ============================================================
// FRIENDS WHO OWN A GAME
// ============================================================

async function loadFriendLibraries(myUsername) {
    let friends = [];
    try {
        if (MODE === 'demo') {
            friends = getDemoFriends(myUsername);
        } else {
            friends = await getFriendsGitHub(myUsername);
        }
    } catch (_) {
        return {};
    }
    const entries = await Promise.all(
        friends.map(async friendName => {
            try {
                const lib = MODE === 'demo'
                    ? getDemoGameLibrary(friendName)
                    : await getGameLibraryGitHub(friendName);
                return [friendName, lib];
            } catch (_) {
                return [friendName, []];
            }
        })
    );
    return Object.fromEntries(entries);
}

function countFriendsWithGame(friendLibraries, platform, title) {
    const titleLower = (title || '').toLowerCase();
    return Object.values(friendLibraries).filter(lib =>
        lib.some(g =>
            g.platform === platform &&
            (g.title || '').toLowerCase() === titleLower
        )
    ).length;
}

// ============================================================
// GAME LIBRARY – DEMO MODE
// ============================================================

function getDemoGameLibrary(username) {
    const key  = `gameOS_games_${username.toLowerCase()}`;
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : [];
}

function saveDemoGameLibrary(username, library) {
    localStorage.setItem(`gameOS_games_${username.toLowerCase()}`, JSON.stringify(library));
}

function addGameDemo(username, game, platform) {
    const library = getDemoGameLibrary(username);
    const title   = game.Title || game.game_name || game.title || '';

    const alreadyOwned = library.some(
        g => g.platform === platform && (g.title || '').toLowerCase() === title.toLowerCase()
    );
    if (alreadyOwned) return { success: false, message: 'Game already in your library' };

    library.push({
        platform,
        title,
        titleId:  game.TitleID || game.title_id || game.id || null,
        coverUrl: getGameCoverUrl(game) || undefined,
        addedAt:  new Date().toISOString()
    });
    saveDemoGameLibrary(username, library);
    return { success: true, message: 'Game added to your library!' };
}

function removeGameDemo(username, platform, title) {
    const library = getDemoGameLibrary(username);
    const updated = library.filter(
        g => !(g.platform === platform && (g.title || '').toLowerCase() === title.toLowerCase())
    );
    saveDemoGameLibrary(username, updated);
    return { success: true, library: updated };
}

// ============================================================
// PLATFORM HELPERS
// ============================================================

function getPlatformColor(platform) {
    const p = (platform || '').toLowerCase();
    if (p.includes('ps3')) return 'linear-gradient(135deg, #00439c 0%, #0070d1 100%)';
    if (p.includes('ps4') || p.includes('ps5')) return 'linear-gradient(135deg, #003087 0%, #0050a0 100%)';
    if (p.includes('switch')) return 'linear-gradient(135deg, #e60012 0%, #b90010 100%)';
    if (p.includes('xbox')) return 'linear-gradient(135deg, #107c10 0%, #52b043 100%)';
    return 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
}

function getPlatformIcon(platform) {
    const p = (platform || '').toLowerCase();
    if (p.includes('switch')) return '🕹️';
    return '🎮';
}

// ── Game image helpers ─────────────────────────────────────
function _resolveGameDbUrl(path) {
    if (!path) return null;
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    return GAMES_DB_RAW_BASE + '/' + path.split('/').map(encodeURIComponent).join('/');
}

function getGameCoverUrl(game) {
    return _resolveGameDbUrl(game.image || game.cover_url || '');
}

function getGameBackgroundUrls(game) {
    return (game.background_images || []).map(_resolveGameDbUrl).filter(Boolean);
}

// Fallback handlers called from onerror on cover images
function _gameCoverFallback(img) {
    const p = img.parentNode;
    if (!p) return;
    const platform = p.dataset.platform || '';
    p.textContent = getPlatformIcon(platform);
    p.style.background = getPlatformColor(platform);
    p.className = 'game-cover-icon';
}

function _gameModalCoverFallback(img) {
    const p = img.parentNode;
    if (!p) return;
    const platform = p.dataset.platform || '';
    p.textContent = getPlatformIcon(platform);
    p.style.background = getPlatformColor(platform);
    p.className = 'game-modal-cover-large';
}

// ============================================================
// GAME DETAIL MODAL
// ============================================================

function ensureGameModal() {
    let modal = document.getElementById('gameDetailModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'gameDetailModal';
        modal.className = 'game-modal-overlay';
        modal.style.display = 'none';
        modal.innerHTML = `
            <div class="game-modal">
                <div class="game-modal-header">
                    <div class="game-modal-cover-large" id="gameModalCoverIcon">🎮</div>
                    <div style="flex:1;min-width:0;">
                        <h3 class="game-modal-title" id="gameModalTitle"></h3>
                        <p class="game-modal-platform" id="gameModalPlatform"></p>
                    </div>
                    <button class="game-modal-close" onclick="closeGameModal()">✕</button>
                </div>
                <div class="game-modal-body" id="gameModalBody"></div>
            </div>
        `;
        document.body.appendChild(modal);
        modal.addEventListener('click', e => { if (e.target === modal) closeGameModal(); });
    }
    return modal;
}

function closeGameModal() {
    const modal = document.getElementById('gameDetailModal');
    if (modal) modal.style.display = 'none';
}

function _buildGameModalFields(game) {
    const skipFields = new Set(['Title', 'game_name', 'title', 'image', 'background_images', 'trailers']);
    return Object.entries(game)
        .filter(([k, v]) => !skipFields.has(k) && v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0))
        .map(([k, v]) => {
            const label = k.replace(/([A-Z])/g, ' $1').replace(/_/g, ' ').trim();
            const value = Array.isArray(v) ? v.join(', ') : String(v);
            return `<div class="game-modal-field">
                <span class="game-modal-field-label">${escapeHtml(label)}</span>
                <span class="game-modal-field-value">${escapeHtml(value)}</span>
            </div>`;
        }).join('');
}

function _getYouTubeId(urlOrId) {
    if (!urlOrId) return null;
    const s = String(urlOrId).trim();
    if (/^[a-zA-Z0-9_-]{11}$/.test(s)) return s;
    const m = s.match(/(?:youtube\.com\/(?:watch\?v=|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
    return m ? m[1] : null;
}

function _buildTrailerSection(game) {
    const trailers = game.trailers;
    if (!Array.isArray(trailers) || !trailers.length) return '';
    const ytId = _getYouTubeId(trailers[0]);
    if (!ytId) return '';
    return `<div class="game-modal-trailer">
        <div class="game-modal-trailer-label">🎬 Trailer</div>
        <div class="game-modal-trailer-wrap">
            <iframe src="https://www.youtube-nocookie.com/embed/${escapeHtml(ytId)}?rel=0"
                class="game-modal-trailer-iframe"
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                allowfullscreen></iframe>
        </div>
    </div>`;
}

function _buildFriendsSection(friendLibraries, platform, title) {
    const titleLower = (title || '').toLowerCase();
    const friends = Object.keys(friendLibraries).filter(name =>
        (friendLibraries[name] || []).some(g =>
            g.platform === platform &&
            (g.title || '').toLowerCase() === titleLower
        )
    );
    if (!friends.length) return '';
    const items = friends.map(name =>
        `<a href="profile.html?user=${encodeURIComponent(name)}" class="game-friends-list-item" onclick="closeGameModal()">👤 ${escapeHtml(name)}</a>`
    ).join('');
    return `<div class="game-modal-field game-modal-friends-field">
        <span class="game-modal-field-label">Friends who own this</span>
        <span class="game-modal-field-value">
            <span class="game-friends-badge">👥 ${friends.length} friend${friends.length !== 1 ? 's' : ''}</span>
            <div class="game-friends-list">${items}</div>
        </span>
    </div>`;
}

function openGameModal(game, platform) {
    if (typeof game === 'string') {
        try { game = JSON.parse(game); } catch (_) { return; }
    }
    const modal = ensureGameModal();
    const title = game.Title || game.game_name || game.title || 'Unknown Game';

    const coverEl  = document.getElementById('gameModalCoverIcon');
    const coverUrl = getGameCoverUrl(game);
    if (coverUrl) {
        coverEl.className = 'game-modal-cover-large game-modal-cover-large--img';
        coverEl.style.background = '';
        coverEl.dataset.platform = platform || '';
        coverEl.innerHTML = `<img src="${coverUrl}" class="game-modal-cover-img" alt="${escapeHtml(title)}" onerror="_gameModalCoverFallback(this)">`;
    } else {
        coverEl.className = 'game-modal-cover-large';
        coverEl.style.background = getPlatformColor(platform);
        coverEl.textContent = getPlatformIcon(platform);
    }
    document.getElementById('gameModalTitle').textContent = title;
    document.getElementById('gameModalPlatform').textContent = platform || '';

    const bgUrls    = getGameBackgroundUrls(game);
    const fieldRows = _buildGameModalFields(game);
    const libs = (typeof _friendLibraries !== 'undefined') ? _friendLibraries : {};
    let bodyHtml = '';
    bodyHtml += _buildTrailerSection(game);
    bodyHtml += _buildFriendsSection(libs, platform, title);
    if (bgUrls.length > 0) {
        bodyHtml += `<div class="game-modal-bg-gallery">${
            bgUrls.map(u => `<img src="${escapeHtml(u)}" class="game-modal-bg-img" alt="Background">`).join('')
        }</div>`;
    }
    bodyHtml += fieldRows || '<p style="color:#666;font-size:0.9em;">No additional details available.</p>';
    document.getElementById('gameModalBody').innerHTML = bodyHtml;
    modal.style.display = 'flex';
}

async function openGameModalFromLibrary(title, platform, titleId) {
    const modal = ensureGameModal();

    const coverEl = document.getElementById('gameModalCoverIcon');
    coverEl.className       = 'game-modal-cover-large';
    coverEl.style.background = getPlatformColor(platform);
    coverEl.textContent     = getPlatformIcon(platform);
    document.getElementById('gameModalTitle').textContent    = title;
    document.getElementById('gameModalPlatform').textContent = platform || '';
    document.getElementById('gameModalBody').innerHTML =
        '<p style="color:#666;font-size:0.9em;">⏳ Loading game details…</p>';
    modal.style.display = 'flex';

    try {
        const games = await fetchGamesDbPlatform(platform);
        const titleLower = title.toLowerCase();
        const game = games.find(g =>
            (g.Title || g.game_name || g.title || '').toLowerCase() === titleLower ||
            (titleId && String(g.TitleID || g.title_id || g.id || '') === String(titleId))
        );

        if (game) {
            const coverUrl = getGameCoverUrl(game);
            if (coverUrl) {
                coverEl.className = 'game-modal-cover-large game-modal-cover-large--img';
                coverEl.style.background = '';
                coverEl.dataset.platform = platform || '';
                coverEl.innerHTML = `<img src="${coverUrl}" class="game-modal-cover-img" alt="${escapeHtml(title)}" onerror="_gameModalCoverFallback(this)">`;
            }
        }

        const source    = game || (titleId ? { TitleID: titleId } : {});
        const bgUrls    = getGameBackgroundUrls(source);
        const fieldRows = _buildGameModalFields(source);
        const libs = (typeof _friendLibraries !== 'undefined') ? _friendLibraries : {};
        let bodyHtml = '';
        bodyHtml += _buildTrailerSection(source);
        bodyHtml += _buildFriendsSection(libs, platform, title);
        if (bgUrls.length > 0) {
            bodyHtml += `<div class="game-modal-bg-gallery">${
                bgUrls.map(u => `<img src="${escapeHtml(u)}" class="game-modal-bg-img" alt="Background">`).join('')
            }</div>`;
        }
        bodyHtml += fieldRows || '<p style="color:#666;font-size:0.9em;">No additional details available.</p>';
        document.getElementById('gameModalBody').innerHTML = bodyHtml;
    } catch (_) {
        document.getElementById('gameModalBody').innerHTML =
            '<p style="color:#c00;font-size:0.9em;">Failed to load game details.</p>';
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
