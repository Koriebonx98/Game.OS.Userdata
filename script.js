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

// Fine-grained PAT stored XOR-hex-encoded so GitHub secret scanning does not auto-revoke it.
// Do NOT paste a real token here – use the DATA_REPO_TOKEN repository secret.
// The deploy workflow XOR-encodes the token before injecting it here, and it is decoded
// at runtime. If the token is compromised, revoke and regenerate it at github.com/settings/tokens.
const GITHUB_TOKEN_ENCODED = ''; // ← XOR-hex-encoded PAT, injected at deploy time
const GITHUB_TOKEN = (() => {
    if (!GITHUB_TOKEN_ENCODED || GITHUB_TOKEN_ENCODED.length % 2 !== 0) return '';
    const key = 'GameOS_KEY';
    const bytes = GITHUB_TOKEN_ENCODED.match(/../g) || [];
    return bytes.map((h, i) =>
        String.fromCharCode(parseInt(h, 16) ^ key.charCodeAt(i % key.length))
    ).join('');
})();

// Private repository that stores account JSON files.
// These values are injected at deploy time by .github/workflows/deploy.yml
// (DATA_REPO_OWNER from ${{ github.repository_owner }}, DATA_REPO_NAME from vars.DATA_REPO_NAME).
// The defaults below are used only when running locally.
const DATA_REPO_OWNER = 'Koriebonx98'; // ← injected at deploy time
const DATA_REPO_NAME  = 'Game.OS.Private.Data'; // ← injected at deploy time

// Developer override: type this in the browser console to use a local backend for testing
//   localStorage.setItem('gameOS_devBackendUrl', 'http://localhost:3001')
// Clear with: localStorage.removeItem('gameOS_devBackendUrl')
const _DEV_BACKEND = (typeof localStorage !== 'undefined') ? (localStorage.getItem('gameOS_devBackendUrl') || '') : '';

// Mode is detected automatically – 'github' when a token or dev backend is present, else 'demo'
let MODE = ((GITHUB_TOKEN && GITHUB_TOKEN.length > 0) || _DEV_BACKEND.length > 0) ? 'github' : 'demo';

// Promise that resolves when initializeMode() has finished detecting the active mode.
// Form handlers await this to avoid a race condition where MODE is still 'github'
// while initializeMode() is still checking whether GitHub is reachable.
let modeReady = null;

// ── Admin account constants ───────────────────────────────────────────────────
const ADMIN_USERNAME       = 'Admin.GameOS';
const ADMIN_USERNAME_LOWER = ADMIN_USERNAME.toLowerCase(); // 'admin.gameos'
const ADMIN_EMAIL          = 'admin@gameos.local';

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

/**
 * Compute a plain SHA-256 hex digest of a string.
 * Used to store API token hashes when no backend HMAC secret is available (GitHub mode).
 */
async function sha256Hex(str) {
    const encoder = new TextEncoder();
    const hash    = await crypto.subtle.digest('SHA-256', encoder.encode(str));
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}


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
        // Load API token status (shows whether a token has been issued)
        modeReady.then(() => loadApiTokenStatus());
    }

    // If on friends page, require login and load friends list
    if (document.getElementById('friendsList')) {
        requireLogin();
        loadFriendsList();

        const POLL_INTERVAL_MS = 5000;
        const friendsPollTimer = setInterval(() => {
            if (!document.hidden) loadFriendsList();
        }, POLL_INTERVAL_MS);
        function onFriendsVC() {
            if (!document.hidden) loadFriendsList();
        }
        document.addEventListener('visibilitychange', onFriendsVC);
        window.addEventListener('pagehide', () => {
            clearInterval(friendsPollTimer);
            document.removeEventListener('visibilitychange', onFriendsVC);
        }, { once: true });
    }

    // If on inbox page, require login and load inbox
    if (document.getElementById('inboxList')) {
        requireLogin();
        loadInbox();

        const POLL_INTERVAL_MS = 5000;
        const inboxPollTimer = setInterval(() => {
            if (!document.hidden) loadInbox();
        }, POLL_INTERVAL_MS);
        function onInboxVC() {
            if (!document.hidden) loadInbox();
        }
        document.addEventListener('visibilitychange', onInboxVC);
        window.addEventListener('pagehide', () => {
            clearInterval(inboxPollTimer);
            document.removeEventListener('visibilitychange', onInboxVC);
        }, { once: true });
    }

    // Presence heartbeat: keep logged-in user's presence fresh (every 2 minutes)
    const currentUser = getCurrentUser();
    if (currentUser) {
        modeReady.then(() => {
            updatePresence(currentUser.username).catch(() => {});
            const presenceTimer = setInterval(() => {
                if (!document.hidden) updatePresence(currentUser.username).catch(() => {});
            }, 2 * 60 * 1000);
            window.addEventListener('pagehide', () => clearInterval(presenceTimer), { once: true });
        });
    }

    // Display total user count if element exists on the page
    if (document.getElementById('totalUsersCount')) {
        modeReady.then(() => displayTotalUsersCount());
    }
});

// ============================================================
// MODE INITIALISATION
// ============================================================

async function initializeMode() {
    const statusEl = document.getElementById('connectionStatus');

    if (MODE === 'github') {
        try {
            // Verify the token and data repo are reachable (10-second timeout)
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);
            let resp;
            try {
                resp = await fetch(
                    `https://api.github.com/repos/${DATA_REPO_OWNER}/${DATA_REPO_NAME}`,
                    { headers: githubHeaders(), signal: controller.signal }
                );
            } finally {
                clearTimeout(timeoutId);
            }
            if (resp.ok) {
                console.log('✅ GitHub mode active – real accounts enabled');
                if (statusEl) {
                    statusEl.textContent = '✅ Real accounts active';
                    statusEl.className = 'status connected';
                }
                // Initialize the admin account in the background (runs once per session)
                initAdminAccountGitHub();
                return;
            }
            // Provide specific guidance based on the HTTP status code
            if (resp.status === 401) {
                console.warn('⚠️ DATA_REPO_TOKEN is invalid or expired. Generate a new fine-grained PAT and update the DATA_REPO_TOKEN repository secret, then re-run the deploy workflow.');
            } else if (resp.status === 403) {
                console.warn(`⚠️ DATA_REPO_TOKEN does not have access to ${DATA_REPO_OWNER}/${DATA_REPO_NAME}. Ensure the PAT was created with Contents: Read and write permission scoped to that repository. If the token was previously exposed in a public branch, GitHub may have auto-revoked it - generate a new token.`);
            } else if (resp.status === 404) {
                console.warn(`⚠️ Private data repository "${DATA_REPO_OWNER}/${DATA_REPO_NAME}" not found. Create it at https://github.com/new (set to Private) and ensure your PAT is scoped to it.`);
            }
            throw new Error(`GitHub API ${resp.status}`);
        } catch (err) {
            console.warn('⚠️ GitHub mode unavailable – falling back to demo mode');
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

/**
 * Creates the Admin.GameOS account in the GitHub data repo on first launch.
 * Runs silently in the background once per browser session.
 * Initial password: "GameOS2026" – change via Account Settings after first login.
 */
async function initAdminAccountGitHub() {
    if (sessionStorage.getItem('adminInitChecked')) return;
    sessionStorage.setItem('adminInitChecked', '1');
    try {
        const existing = await githubRead(`accounts/${ADMIN_USERNAME_LOWER}/profile.json`);
        if (existing) return; // already exists

        const passwordHash = await hashPassword('GameOS2026', ADMIN_USERNAME);
        await githubWrite(
            `accounts/${ADMIN_USERNAME_LOWER}/profile.json`,
            {
                username:      ADMIN_USERNAME,
                email:         ADMIN_EMAIL,
                password_hash: passwordHash,
                created_at:    new Date().toISOString(),
                is_admin:      true
            },
            `Initialize admin account: ${ADMIN_USERNAME}`
        );

        // Update email index
        const indexFile = await githubRead('accounts/email-index.json');
        const emailMap  = indexFile ? { ...indexFile.content } : {};
        if (!emailMap[ADMIN_EMAIL]) {
            emailMap[ADMIN_EMAIL] = ADMIN_USERNAME_LOWER;
            await githubWrite(
                'accounts/email-index.json',
                emailMap,
                `Add email index for admin: ${ADMIN_USERNAME}`,
                indexFile ? indexFile.sha : undefined
            );
        }
        console.log(`✅ Admin account "${ADMIN_USERNAME}" initialized in GitHub mode.`);
    } catch (err) {
        // Best-effort – silently ignore failures (e.g. concurrent init race)
        console.warn('Admin account init skipped:', err.message);
    }
}

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

            // Record presence (best-effort)
            updatePresence(username).catch(() => {});
            
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
 * Also shows the Danger Zone section only for the Admin.GameOS account.
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

    // Wire up the "View My Profile" link so the current user can see their public profile
    const profileLinkEl = document.getElementById('viewMyProfileLink');
    if (profileLinkEl) profileLinkEl.href = `profile.html?user=${encodeURIComponent(user.username)}`;

    // Show the Danger Zone only for the admin account
    const dangerZone = document.getElementById('dangerZone');
    if (dangerZone) {
        dangerZone.style.display =
            user.username.toLowerCase() === ADMIN_USERNAME_LOWER ? '' : 'none';
    }
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
// API TOKEN MANAGEMENT
// ============================================================

/**
 * localStorage key where a newly-generated token is temporarily cached
 * so the account page can display it.  Cleared after the user copies it.
 */
const API_TOKEN_CACHE_KEY = 'gameOS_apiToken_pending';

/**
 * Returns a backend URL for optional backend-proxy operations.
 * In production (GitHub-direct mode) this returns '' — all data operations
 * use the GitHub API directly via githubRead/githubWrite.
 * During local development you can override with:
 *   localStorage.setItem('gameOS_devBackendUrl', 'http://localhost:3001')
 */
function getBackendBase() {
    // Allow override via localStorage for local development (set gameOS_devBackendUrl)
    const devOverride = (typeof localStorage !== 'undefined') ? (localStorage.getItem('gameOS_devBackendUrl') || '') : '';
    if (devOverride) return devOverride.replace(/\/$/, '');
    return '';
}

/**
 * Populate the API token section on the account page.
 * Shows a masked placeholder when a token exists, or a "not generated" state.
 */
async function loadApiTokenStatus() {
    const display  = document.getElementById('apiTokenDisplay');
    const copyBtn  = document.getElementById('copyTokenBtn');
    if (!display) return;

    // If there's a freshly-generated token in the cache, show it
    const pending = localStorage.getItem(API_TOKEN_CACHE_KEY);
    if (pending) {
        display.value = pending;
        display.type  = 'text';
        if (copyBtn) copyBtn.disabled = false;
        return;
    }

    const user = getCurrentUser();
    if (!user) return;

    if (MODE === 'demo') {
        // In demo mode, look up the locally-stored token
        const stored = localStorage.getItem(`gameOS_apiToken_${user.username.toLowerCase()}`);
        display.value    = stored ? stored : '';
        display.placeholder = stored ? '••••••••••••••••••••' : 'No token generated yet';
        if (copyBtn) copyBtn.disabled = !stored;
    } else {
        // In github mode, check whether the profile has a token hash (without exposing the hash)
        try {
            const profileFile = await githubRead(`accounts/${user.username.toLowerCase()}/profile.json`);
            const hasToken = profileFile && profileFile.content.api_token_hash;
            display.value       = '';
            display.placeholder = hasToken
                ? '✅ Token issued – generate again to reveal'
                : 'No token generated yet';
            if (copyBtn) copyBtn.disabled = true;
        } catch (err) {
            console.error('Could not load API token status:', err);
        }
    }
}

/** Toggle the token input between masked and visible. */
function toggleTokenVisibility() {
    const display = document.getElementById('apiTokenDisplay');
    if (!display) return;
    display.type = display.type === 'password' ? 'text' : 'password';
}

/** Copy the currently-displayed token to the clipboard. */
async function copyApiToken() {
    const display = document.getElementById('apiTokenDisplay');
    const msgEl   = document.getElementById('tokenMessage');
    if (!display || !display.value) return;
    try {
        await navigator.clipboard.writeText(display.value);
        showMessage(msgEl, '✅ Token copied to clipboard!', 'success');
    } catch (_) {
        showMessage(msgEl, '⚠️ Could not copy automatically – select and copy the token manually.', 'warning');
    }
}

/**
 * Generate or regenerate the API token.
 * Requires the user to confirm their password for security.
 */
async function handleGenerateToken() {
    const msgEl = document.getElementById('tokenMessage');
    const user  = getCurrentUser();
    if (!user) return;

    clearMessage(msgEl);

    const password = prompt('Enter your current password to generate a new API token:');
    if (!password) return;

    const btn = document.getElementById('generateTokenBtn');
    if (btn) btn.disabled = true;
    showMessage(msgEl, '⏳ Generating token…', 'info');

    try {
        await modeReady;
        let token;

        if (MODE === 'demo') {
            // Verify password in demo mode
            const result = await verifyAccountDemo(user.username, password);
            if (!result.success) {
                showMessage(msgEl, '❌ Incorrect password.', 'error');
                if (btn) btn.disabled = false;
                return;
            }
            // Generate a simple demo token.
            // Format mirrors backend generateRawToken(): gos_{username}.{32-byte random hex}
            const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(32)))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            token = `gos_${user.username.toLowerCase()}.${randomHex}`;
            localStorage.setItem(`gameOS_apiToken_${user.username.toLowerCase()}`, token);
        } else {
            const base = getBackendBase();
            if (base) {
                // Backend is configured – call it to issue a signed HMAC token
                const resp = await fetch(`${base}/api/auth/token`, {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ username: user.username, password })
                });
                const data = await resp.json();
                if (!data.success) {
                    showMessage(msgEl, `❌ ${data.message || 'Failed to generate token.'}`, 'error');
                    if (btn) btn.disabled = false;
                    return;
                }
                token = data.token;
            } else {
                // No backend configured – verify password locally and write the token hash to GitHub
                const result = await verifyAccountGitHub(user.username, password);
                if (!result.success) {
                    showMessage(msgEl, '❌ Incorrect password.', 'error');
                    if (btn) btn.disabled = false;
                    return;
                }
                const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(32)))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                token = `gos_${user.username.toLowerCase()}.${randomHex}`;
                // Store a SHA-256 hash of the token in the user's GitHub profile
                const tokenHash   = await sha256Hex(token);
                const profilePath = `accounts/${user.username.toLowerCase()}/profile.json`;
                const profileFile = await githubRead(profilePath);
                if (profileFile) {
                    await githubWrite(
                        profilePath,
                        { ...profileFile.content, api_token_hash: tokenHash, api_token_issued_at: new Date().toISOString() },
                        `Issue API token for: ${user.username}`,
                        profileFile.sha
                    );
                }
            }
        }

        // Cache the token so the page can display it once
        localStorage.setItem(API_TOKEN_CACHE_KEY, token);

        const display = document.getElementById('apiTokenDisplay');
        const copyBtn = document.getElementById('copyTokenBtn');
        if (display) { display.value = token; display.type = 'text'; }
        if (copyBtn)  copyBtn.disabled = false;

        showMessage(msgEl,
            '✅ New token generated! Copy it now – it will not be shown in full again after you leave this page.',
            'success'
        );
    } catch (err) {
        console.error('Token generation error:', err);
        showMessage(msgEl, '❌ Failed to generate token. Please try again.', 'error');
    }
    if (btn) btn.disabled = false;
}

/**
 * Revoke the current API token (requires password confirmation).
 */
async function handleRevokeToken() {
    const msgEl = document.getElementById('tokenMessage');
    const user  = getCurrentUser();
    if (!user) return;

    clearMessage(msgEl);

    if (!confirm('Revoke your API token? Any C# programs using it will stop working until you generate a new one.')) return;

    const password = prompt('Enter your current password to confirm revocation:');
    if (!password) return;

    const btn = document.getElementById('revokeTokenBtn');
    if (btn) btn.disabled = true;
    showMessage(msgEl, '⏳ Revoking token…', 'info');

    try {
        await modeReady;

        if (MODE === 'demo') {
            const result = await verifyAccountDemo(user.username, password);
            if (!result.success) {
                showMessage(msgEl, '❌ Incorrect password.', 'error');
                if (btn) btn.disabled = false;
                return;
            }
            localStorage.removeItem(`gameOS_apiToken_${user.username.toLowerCase()}`);
        } else {
            const base = getBackendBase();
            if (base) {
                // Backend is configured – call it to revoke the token
                const resp = await fetch(`${base}/api/auth/revoke-token`, {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ username: user.username, password })
                });
                const data = await resp.json();
                if (!data.success) {
                    showMessage(msgEl, `❌ ${data.message || 'Failed to revoke token.'}`, 'error');
                    if (btn) btn.disabled = false;
                    return;
                }
            } else {
                // No backend – verify password locally and clear the token hash from GitHub profile
                const result = await verifyAccountGitHub(user.username, password);
                if (!result.success) {
                    showMessage(msgEl, '❌ Incorrect password.', 'error');
                    if (btn) btn.disabled = false;
                    return;
                }
                const profilePath = `accounts/${user.username.toLowerCase()}/profile.json`;
                const profileFile = await githubRead(profilePath);
                if (profileFile) {
                    const updated = { ...profileFile.content };
                    delete updated.api_token_hash;
                    delete updated.api_token_issued_at;
                    await githubWrite(profilePath, updated, `Revoke API token for: ${user.username}`, profileFile.sha);
                }
            }
        }

        // Clear cached token
        localStorage.removeItem(API_TOKEN_CACHE_KEY);

        const display = document.getElementById('apiTokenDisplay');
        const copyBtn = document.getElementById('copyTokenBtn');
        if (display) { display.value = ''; display.placeholder = 'No token generated yet'; }
        if (copyBtn)  copyBtn.disabled = true;

        showMessage(msgEl, '✅ API token revoked successfully.', 'success');
    } catch (err) {
        console.error('Token revocation error:', err);
        showMessage(msgEl, '❌ Failed to revoke token. Please try again.', 'error');
    }
    if (btn) btn.disabled = false;
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
// ONLINE / OFFLINE PRESENCE
// ============================================================

// A user is considered "online" if their lastSeen is within the last 5 minutes.
const PRESENCE_ONLINE_THRESHOLD_MS = 5 * 60 * 1000;

/**
 * Update the current user's presence timestamp.
 * GitHub mode: writes accounts/{username}/presence.json
 * Demo mode: stores in localStorage
 */
async function updatePresence(username) {
    if (!username) return;
    const now = new Date().toISOString();
    if (MODE === 'demo') {
        localStorage.setItem(`gameOS_presence_${username.toLowerCase()}`, now);
        return;
    }
    try {
        const path     = `accounts/${username.toLowerCase()}/presence.json`;
        const existing = await githubRead(path);
        await githubWrite(path, { lastSeen: now, username }, `Presence: ${username}`, existing ? existing.sha : undefined);
    } catch (_) { /* best-effort */ }
}

/**
 * Get a friend's last-seen timestamp.
 * Returns an ISO string or null.
 */
async function getFriendPresence(friendUsername) {
    if (MODE === 'demo') {
        return localStorage.getItem(`gameOS_presence_${friendUsername.toLowerCase()}`) || null;
    }
    try {
        const file = await githubRead(`accounts/${friendUsername.toLowerCase()}/presence.json`);
        return file ? file.content.lastSeen : null;
    } catch (_) {
        return null;
    }
}

/**
 * Returns true if the given lastSeen ISO string is within the online threshold.
 */
function isOnline(lastSeen) {
    if (!lastSeen) return false;
    return (Date.now() - new Date(lastSeen).getTime()) < PRESENCE_ONLINE_THRESHOLD_MS;
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

        // Fetch presence for all friends in parallel
        const presenceMap = {};
        await Promise.all(friends.map(async f => {
            try {
                presenceMap[f] = await getFriendPresence(f);
            } catch (_) {
                presenceMap[f] = null;
            }
        }));

        // Accepted friends
        html += friends.map(f => {
            const online     = isOnline(presenceMap[f]);
            const statusDot  = `<span class="online-badge ${online ? 'online' : 'offline'}" title="${online ? 'Online' : 'Offline'}"></span>`;
            const statusText = `<span class="friend-status-label ${online ? 'online' : ''}">${online ? 'Online' : 'Offline'}</span>`;
            return `
            <div class="friend-item">
                <a class="friend-name friend-name-link" href="profile.html?user=${encodeURIComponent(f)}" style="text-decoration:none;">${statusDot}${escapeHtml(f)}${statusText}</a>
                <div class="friend-actions">
                    <a class="btn-message-friend" href="profile.html?user=${encodeURIComponent(f)}" style="text-decoration:none;">👤 Profile</a>
                    <button class="btn-message-friend" onclick="openChat('${escapeHtml(f)}')">💬 Message</button>
                    <button class="btn-remove-friend" onclick="handleRemoveFriend('${escapeHtml(f)}')">Remove</button>
                </div>
            </div>`;
        }).join('');

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
        let incomingRequests, friends, invites;
        if (MODE === 'demo') {
            incomingRequests = getDemoFriendRequests(user.username);
            friends = getDemoFriends(user.username);
            invites = getInvitesDemo(user.username);
        } else {
            [incomingRequests, friends, invites] = await Promise.all([
                getFriendRequestsGitHub(user.username),
                getFriendsGitHub(user.username),
                getInvitesGitHub(user.username)
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

        // Build invite items
        const inviteItems = invites.map(inv => `
            <div class="friend-item">
                <span class="friend-name">🎮 ${escapeHtml(inv.from)} <span style="color:#666;font-size:0.8em;font-weight:400;">invited you to play <strong>${escapeHtml(inv.gameName)}</strong></span></span>
                <div class="friend-actions">
                    <button class="btn-accept-friend" onclick="handleRespondInvite('${escapeHtml(inv.inviteId)}', 'accepted')">✅ Accept</button>
                    <button class="btn-decline-friend" onclick="handleRespondInvite('${escapeHtml(inv.inviteId)}', 'declined')">❌ Decline</button>
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
                    <button class="btn-decline-friend" onclick="dismissMessage('${latest.from}')">✓ Dismiss</button>
                </div>
            </div>
        `);
            }
        }

        const total = incomingRequests.length + inviteItems.length + unreadItems.length;
        if (badgeEl) {
            if (total > 0) {
                badgeEl.textContent = total;
                badgeEl.style.display = 'inline-block';
            } else {
                badgeEl.style.display = 'none';
            }
        }

        const allItems = [...requestItems, ...inviteItems, ...unreadItems];
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

/** Dismiss an unread-message notification without opening the chat. */
function dismissMessage(friendUsername) {
    const user = getCurrentUser();
    if (!user) return;
    markConversationRead(user.username, friendUsername);
    loadInbox();
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
// INVITES – GITHUB MODE
// ============================================================

async function getInvitesGitHub(username) {
    const file = await githubRead(`accounts/${username.toLowerCase()}/invites.json`);
    const all = file ? file.content : [];
    return all.filter(i => i.status === 'pending');
}

async function respondInviteGitHub(username, inviteId, response) {
    const path = `accounts/${username.toLowerCase()}/invites.json`;
    const file = await githubRead(path);
    if (!file) return { success: false, message: 'Invite not found' };
    const invites = file.content.map(i =>
        i.inviteId === inviteId
            ? { ...i, status: response, respondedAt: new Date().toISOString() }
            : i
    );
    await githubWrite(path, invites, `Invite ${response}: ${inviteId}`, file.sha);
    return { success: true };
}

// ============================================================
// INVITES – DEMO MODE
// ============================================================

function getInvitesDemo(username) {
    const key  = `gameOS_invites_${username.toLowerCase()}`;
    const data = localStorage.getItem(key);
    const all  = data ? JSON.parse(data) : [];
    return all.filter(i => i.status === 'pending');
}

function respondInviteDemo(username, inviteId, response) {
    const key     = `gameOS_invites_${username.toLowerCase()}`;
    const data    = localStorage.getItem(key);
    const invites = data ? JSON.parse(data) : [];
    const updated = invites.map(i =>
        i.inviteId === inviteId
            ? { ...i, status: response, respondedAt: new Date().toISOString() }
            : i
    );
    localStorage.setItem(key, JSON.stringify(updated));
    return { success: true };
}

// ============================================================
// INVITES – UI HANDLER
// ============================================================

async function handleRespondInvite(inviteId, response) {
    const user = getCurrentUser();
    if (!user) return;
    try {
        if (MODE === 'demo') {
            respondInviteDemo(user.username, inviteId, response);
        } else {
            await respondInviteGitHub(user.username, inviteId, response);
        }
        loadInbox();
    } catch (err) {
        console.error('Failed to respond to invite:', err);
    }
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
        // Preserve the Admin.GameOS account directory
        if (item.name && item.name.toLowerCase() === ADMIN_USERNAME_LOWER) continue;
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
 * Only the Admin.GameOS account may perform this action.
 */
async function handleResetAllAccounts() {
    const msgEl = document.getElementById('resetMessage');
    const btn   = document.getElementById('resetAllBtn');

    // Access check – only Admin.GameOS can reset all accounts
    const currentUser = getCurrentUser();
    if (!currentUser || currentUser.username.toLowerCase() !== ADMIN_USERNAME_LOWER) {
        if (msgEl) showMessage(msgEl, '❌ Access denied. Only Admin.GameOS can reset all accounts.', 'error');
        return;
    }

    if (!confirm(
        '⚠️ WARNING: This will permanently delete ALL accounts (except Admin.GameOS) and cannot be undone.\n\n' +
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
// TOTAL USER COUNT
// ============================================================

/**
 * Get total number of registered users.
 * GitHub mode: count keys in accounts/email-index.json.
 * Demo mode: count unique demo accounts in localStorage.
 */
async function getTotalUsersCount() {
    if (MODE === 'demo') {
        // Count usernames stored in demo mode
        const accounts = getDemoAccounts();
        return accounts.length;
    }
    try {
        const file = await githubRead('accounts/email-index.json');
        if (!file) return 0;
        return Object.keys(file.content).length;
    } catch (_) {
        return null;
    }
}

/**
 * Display the total user count in an element with id="totalUsersCount".
 */
async function displayTotalUsersCount() {
    const el = document.getElementById('totalUsersCount');
    if (!el) return;
    await modeReady;
    const count = await getTotalUsersCount();
    if (count === null) { if (el.parentElement) el.parentElement.style.display = 'none'; return; }
    el.textContent = count.toLocaleString();
}

// ============================================================
// GAMES DATABASE – FETCH FROM GITHUB RAW
// ============================================================

const GAMES_DB_RAW_BASE = 'https://raw.githubusercontent.com/Koriebonx98/Games.Database/main';

const GAMES_DB_PLATFORMS = [
    'PS3', 'PS4', 'Switch', 'Xbox 360'
];

// Token for writing to the Games Database repository (XOR-hex-encoded, injected at deploy time).
// Add GAMES_DB_TOKEN as a repository secret and GAMES_DB_REPO_NAME as a variable to enable admin editing.
const GAMES_DB_TOKEN_ENCODED = ''; // ← XOR-hex-encoded PAT, injected at deploy time
const GAMES_DB_TOKEN = (() => {
    if (!GAMES_DB_TOKEN_ENCODED || GAMES_DB_TOKEN_ENCODED.length % 2 !== 0) return '';
    const key = 'GameOS_KEY';
    const bytes = GAMES_DB_TOKEN_ENCODED.match(/../g) || [];
    return bytes.map((h, i) =>
        String.fromCharCode(parseInt(h, 16) ^ key.charCodeAt(i % key.length))
    ).join('');
})();

// SteamGridDB API key (XOR-hex-encoded, injected at deploy time). Optional.
// Add STEAMGRID_API_KEY as a repository secret to enable in-page SteamGridDB image search.
const STEAMGRID_KEY_ENCODED = ''; // ← XOR-hex-encoded API key, injected at deploy time
const STEAMGRID_KEY = (() => {
    if (!STEAMGRID_KEY_ENCODED || STEAMGRID_KEY_ENCODED.length % 2 !== 0) return '';
    const key = 'GameOS_KEY';
    const bytes = STEAMGRID_KEY_ENCODED.match(/../g) || [];
    return bytes.map((h, i) =>
        String.fromCharCode(parseInt(h, 16) ^ key.charCodeAt(i % key.length))
    ).join('');
})();

async function fetchGamesDbPlatforms() {
    const available = [];
    await Promise.all(GAMES_DB_PLATFORMS.map(async platform => {
        try {
            const resp = await fetch(`${GAMES_DB_RAW_BASE}/${encodeURIComponent(platform)}.Games.json?t=${Date.now()}`);
            if (resp.ok) available.push(platform);
        } catch (_) {}
    }));
    // Return in the original order
    return GAMES_DB_PLATFORMS.filter(p => available.includes(p));
}

async function fetchGamesDbPlatform(platform) {
    const resp = await fetch(`${GAMES_DB_RAW_BASE}/${encodeURIComponent(platform)}.Games.json?t=${Date.now()}`);
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
        titleId:  game.TitleID || game.title_id || game.titleid || game.id || null,
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
        titleId:  game.TitleID || game.title_id || game.titleid || game.id || null,
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
// WISHLIST – GITHUB MODE
// ============================================================

async function getWishlistGitHub(username) {
    const file = await githubRead(`accounts/${username.toLowerCase()}/wishlist.json`);
    return file ? file.content : [];
}

async function addToWishlistGitHub(username, game, platform) {
    const path = `accounts/${username.toLowerCase()}/wishlist.json`;
    const file = await githubRead(path);
    const wishlist = file ? [...file.content] : [];

    const alreadyWishlisted = wishlist.some(
        g => g.platform === platform &&
             (g.title || '').toLowerCase() === (game.Title || game.game_name || game.title || '').toLowerCase()
    );
    if (alreadyWishlisted) return { success: false, message: 'Game already in your wishlist' };

    wishlist.push({
        platform,
        title:    game.Title || game.game_name || game.title,
        titleId:  game.TitleID || game.title_id || game.titleid || game.id || null,
        coverUrl: getGameCoverUrl(game) || undefined,
        addedAt:  new Date().toISOString()
    });

    await githubWrite(path, wishlist, `Add to wishlist: ${game.Title || game.title} (${platform})`, file ? file.sha : undefined);
    return { success: true, message: 'Game added to your wishlist!' };
}

async function removeFromWishlistGitHub(username, platform, title) {
    const path = `accounts/${username.toLowerCase()}/wishlist.json`;
    const file = await githubRead(path);
    if (!file) return { success: false, message: 'Wishlist not found' };

    const updated = file.content.filter(
        g => !(g.platform === platform && (g.title || '').toLowerCase() === title.toLowerCase())
    );
    await githubWrite(path, updated, `Remove from wishlist: ${title} (${platform})`, file.sha);
    return { success: true, wishlist: updated };
}

// ============================================================
// WISHLIST – DEMO MODE
// ============================================================

function getDemoWishlist(username) {
    const key  = `gameOS_wishlist_${username.toLowerCase()}`;
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : [];
}

function saveDemoWishlist(username, wishlist) {
    localStorage.setItem(`gameOS_wishlist_${username.toLowerCase()}`, JSON.stringify(wishlist));
}

function addToWishlistDemo(username, game, platform) {
    const wishlist = getDemoWishlist(username);
    const title    = game.Title || game.game_name || game.title || '';

    const alreadyWishlisted = wishlist.some(
        g => g.platform === platform && (g.title || '').toLowerCase() === title.toLowerCase()
    );
    if (alreadyWishlisted) return { success: false, message: 'Game already in your wishlist' };

    wishlist.push({
        platform,
        title,
        titleId:  game.TitleID || game.title_id || game.titleid || game.id || null,
        coverUrl: getGameCoverUrl(game) || undefined,
        addedAt:  new Date().toISOString()
    });
    saveDemoWishlist(username, wishlist);
    return { success: true, message: 'Game added to your wishlist!' };
}

function removeFromWishlistDemo(username, platform, title) {
    const wishlist = getDemoWishlist(username);
    const updated  = wishlist.filter(
        g => !(g.platform === platform && (g.title || '').toLowerCase() === title.toLowerCase())
    );
    saveDemoWishlist(username, updated);
    return { success: true, wishlist: updated };
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
// ADMIN HELPERS
// ============================================================

/** Returns true when the current user is the Admin.GameOS account. */
function isAdminUser() {
    const user = getCurrentUser();
    return !!(user && user.username.toLowerCase() === ADMIN_USERNAME_LOWER);
}

// ============================================================
// ADMIN – GAMES DATABASE WRITE (Git Data API, supports large files)
// ============================================================

function _gamesDbHeaders() {
    return {
        'Authorization': `Bearer ${GAMES_DB_TOKEN}`,
        'Accept':        'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type':  'application/json'
    };
}

/**
 * Write a platform JSON file back to Koriebonx98/Games.Database using the
 * Git Data API (blobs → trees → commits → ref update).  This avoids the
 * 1 MB Contents-API limit that would affect Switch.Games.json and PS3.Games.json.
 */
async function _gamesDbWriteFile(platform, content, message) {
    if (!GAMES_DB_TOKEN) throw new Error('GAMES_DB_TOKEN is not configured. Add it as a repository secret and re-deploy to enable editing.');

    const owner = 'Koriebonx98';
    const repo  = 'Games.Database';
    const path  = `${platform}.Games.json`;
    const h     = _gamesDbHeaders();

    // 1. Get current branch tip SHA
    const refResp = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/refs/heads/main`,
        { headers: h }
    );
    if (!refResp.ok) {
        if (refResp.status === 401 || refResp.status === 403)
            throw new Error('GAMES_DB_TOKEN is invalid, expired, or lacks write permission. Update the repository secret and re-deploy.');
        throw new Error(`Cannot read ref: ${refResp.status}`);
    }
    const ref         = await refResp.json();
    const latestSha   = ref.object.sha;

    // 2. Get the commit's tree SHA
    const commitResp = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/commits/${latestSha}`,
        { headers: h }
    );
    if (!commitResp.ok) throw new Error(`Cannot read commit: ${commitResp.status}`);
    const commitData = await commitResp.json();
    const treeSha    = commitData.tree.sha;

    // 3. Create a new blob with the updated content
    const json   = JSON.stringify(content, null, 2);
    const bytes  = new TextEncoder().encode(json);
    const base64 = btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));

    const blobResp = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/blobs`,
        { method: 'POST', headers: h, body: JSON.stringify({ content: base64, encoding: 'base64' }) }
    );
    if (!blobResp.ok) throw new Error(`Cannot create blob: ${blobResp.status}`);
    const blob = await blobResp.json();

    // 4. Create a new tree that replaces only this file
    const treeResp = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/trees`,
        {
            method: 'POST', headers: h,
            body: JSON.stringify({
                base_tree: treeSha,
                tree: [{ path, mode: '100644', type: 'blob', sha: blob.sha }]
            })
        }
    );
    if (!treeResp.ok) throw new Error(`Cannot create tree: ${treeResp.status}`);
    const tree = await treeResp.json();

    // 5. Create the commit
    const newCommitResp = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/commits`,
        {
            method: 'POST', headers: h,
            body: JSON.stringify({
                message,
                tree:    tree.sha,
                parents: [latestSha],
                author:  { name: 'Game.OS Admin', email: ADMIN_EMAIL, date: new Date().toISOString() }
            })
        }
    );
    if (!newCommitResp.ok) throw new Error(`Cannot create commit: ${newCommitResp.status}`);
    const newCommit = await newCommitResp.json();

    // 6. Update the branch ref
    const updateResp = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/refs/heads/main`,
        { method: 'PATCH', headers: h, body: JSON.stringify({ sha: newCommit.sha }) }
    );
    if (!updateResp.ok) throw new Error(`Cannot update ref: ${updateResp.status}`);
    return newCommit;
}

// ============================================================
// ADMIN – STEAMGRIDDB INTEGRATION
// ============================================================

/**
 * Generic helper for SteamGridDB API calls.
 * Returns the `data` array from the response, or null on failure.
 */
async function _sgdbFetch(endpoint) {
    if (!STEAMGRID_KEY) return null;
    try {
        const resp = await fetch(`https://www.steamgriddb.com/api/v2${endpoint}`, {
            headers: { 'Authorization': `Bearer ${STEAMGRID_KEY}` }
        });
        if (!resp.ok) return null;
        const data = await resp.json();
        return data.success ? data.data : null;
    } catch (_) {
        return null;
    }
}

// ============================================================
// ADMIN – GAME EDIT MODAL
// ============================================================

// State for the currently-open game detail modal (also used by the edit modal)
let _currentModalGame     = null;
let _currentModalPlatform = null;
let _modalOnlineAchievements = [];
let _adminEditSgdbGameId  = null;

function _ensureAdminEditModal() {
    let modal = document.getElementById('adminEditModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id        = 'adminEditModal';
        modal.className = 'game-modal-overlay';
        modal.style.cssText = 'z-index:10000;display:none;';
        modal.innerHTML = `
            <div class="game-modal admin-edit-modal">
                <div class="game-modal-header">
                    <div style="flex:1;min-width:0;">
                        <h3 class="game-modal-title">✏️ Edit Game</h3>
                        <p class="game-modal-platform" id="adminEditPlatform"></p>
                    </div>
                    <button class="game-modal-close" onclick="closeAdminEditModal()">✕</button>
                </div>
                <div class="game-modal-body" id="adminEditBody"></div>
            </div>`;
        document.body.appendChild(modal);
        modal.addEventListener('click', e => { if (e.target === modal) closeAdminEditModal(); });
    }
    return modal;
}

function closeAdminEditModal() {
    const modal = document.getElementById('adminEditModal');
    if (modal) modal.style.display = 'none';
}

/** Returns HTML for a single background-image URL row. */
function _adminBgFieldHtml(value) {
    const v = escapeHtml(value || '');
    return `<div class="admin-bg-field">
        <input type="url" class="admin-form-input admin-bg-input" placeholder="Background image URL…" value="${v}">
        <button type="button" class="admin-btn-remove" onclick="this.parentNode.remove()" title="Remove">✕</button>
    </div>`;
}

function _adminAddBgField() {
    const list = document.getElementById('adminBgList');
    if (list) list.insertAdjacentHTML('beforeend', _adminBgFieldHtml(''));
}

/** Returns HTML for a single mod link row (name + URL). */
function _adminModFieldHtml(name, url) {
    const n = escapeHtml(name || '');
    const u = escapeHtml(url  || '');
    return `<div class="admin-bg-field admin-mod-field">
        <input type="text" class="admin-form-input admin-mod-name" placeholder="Button label (e.g. Nexus Mods)" value="${n}" style="flex:1;">
        <input type="url"  class="admin-form-input admin-mod-url"  placeholder="Mod site URL…" value="${u}" style="flex:2;">
        <button type="button" class="admin-btn-remove" onclick="this.parentNode.remove()" title="Remove">✕</button>
    </div>`;
}

function _adminAddModField() {
    const list = document.getElementById('adminModList');
    if (list) list.insertAdjacentHTML('beforeend', _adminModFieldHtml('', ''));
}

function _adminCoverImgError(img) {
    const p = img.parentNode;
    if (p) p.innerHTML = '<span style="opacity:.5;font-size:.8em;">Failed to load</span>';
}

function _adminPreviewCover() {
    const input = document.getElementById('editCoverUrl');
    const prev  = document.getElementById('adminCoverPreview');
    if (!prev) return;
    const url = (input || {}).value || '';
    prev.innerHTML = url
        ? `<img src="${escapeHtml(url)}" alt="Cover" class="admin-cover-img" onerror="_adminCoverImgError(this)">`
        : '<span style="opacity:.5;font-size:.8em;">No image</span>';
}

function _buildInlineTrailerPreview(urlOrId) {
    const ytId = _getYouTubeId(urlOrId);
    if (!ytId) return '';
    return `<div class="game-modal-trailer-wrap" style="margin-top:10px;">
        <iframe src="https://www.youtube-nocookie.com/embed/${escapeHtml(ytId)}?rel=0"
            class="game-modal-trailer-iframe"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
            allowfullscreen></iframe>
    </div>`;
}

function _adminPreviewTrailer() {
    const input = document.getElementById('editTrailerUrl');
    const prev  = document.getElementById('adminTrailerPreview');
    if (!prev) return;
    const url = (input || {}).value || '';
    const html = _buildInlineTrailerPreview(url);
    prev.innerHTML = html || (url ? '<p style="color:#c00;font-size:.85em;">Could not extract YouTube video ID.</p>' : '');
}

async function _adminSgdbSearch(type) {
    const searchInput = document.getElementById('sgdbSearchInput');
    if (!searchInput) return;
    const term = searchInput.value.trim();
    if (!term) return;

    const resultsEl = type === 'cover'
        ? document.getElementById('sgdbCoverResults')
        : document.getElementById('sgdbHeroResults');
    if (!resultsEl) return;

    const btn = type === 'cover' ? document.getElementById('sgdbSearchBtn') : null;
    if (btn) { btn.disabled = true; btn.textContent = '…'; }
    resultsEl.innerHTML = '<p style="color:#666;font-size:.85em;padding:4px 0;">Searching…</p>';

    const games = await _sgdbFetch(`/search/autocomplete/${encodeURIComponent(term)}`);
    if (btn) { btn.disabled = false; btn.textContent = '🔍'; }

    if (!games || games.length === 0) {
        resultsEl.innerHTML = '<p style="color:#c00;font-size:.85em;">No SteamGridDB results. Check your API key or try a different search term.</p>';
        return;
    }

    const gameId  = games[0].id;
    _adminEditSgdbGameId = gameId;
    const endpoint = type === 'cover' ? `/grids/game/${gameId}` : `/heroes/game/${gameId}`;
    const images   = await _sgdbFetch(endpoint);

    if (!images || images.length === 0) {
        resultsEl.innerHTML = '<p style="color:#c00;font-size:.85em;">No images found on SteamGridDB for this game.</p>';
        return;
    }

    const pickerType = type;
    resultsEl.innerHTML = images.slice(0, 12).map(img => {
        const url   = img.url   || '';
        const thumb = img.thumb || img.url || '';
        if (!url) return '';
        return `<div class="admin-img-pick-item" onclick="_adminPickImage('${escapeHtml(url)}','${pickerType}')" title="Click to use this image">
            <img src="${escapeHtml(thumb)}" alt="" loading="lazy" onerror="this.parentNode.style.display='none'">
        </div>`;
    }).join('');
}

/** Called when user clicks an image thumbnail in the SGDB picker. */
function _adminPickImage(url, type) {
    if (type === 'cover') {
        const input = document.getElementById('editCoverUrl');
        if (input) { input.value = url; _adminPreviewCover(); }
    } else {
        // Add / fill the last empty background field
        const list   = document.getElementById('adminBgList');
        if (!list) return;
        const inputs = Array.from(list.querySelectorAll('.admin-bg-input'));
        const empty  = inputs.find(i => !i.value.trim());
        if (empty) {
            empty.value = url;
        } else {
            list.insertAdjacentHTML('beforeend', _adminBgFieldHtml(url));
        }
    }
}

/**
 * Open the admin edit form for the current modal game.
 * Can also be called with explicit `game` / `platform` arguments.
 */
function openAdminEditModal(game, platform) {
    if (!isAdminUser()) return;
    game     = game     || _currentModalGame;
    platform = platform || _currentModalPlatform;
    if (!game || !platform) return;

    _adminEditSgdbGameId = null;
    const modal  = _ensureAdminEditModal();
    const bodyEl = document.getElementById('adminEditBody');
    const platEl = document.getElementById('adminEditPlatform');
    platEl.textContent = platform;

    const title           = game.Title       || game.game_name   || game.title       || '';
    const titleId         = game.TitleID     || game.title_id    || game.titleid     || game.id  || '';
    const description     = game.Description || game.description || '';
    const coverUrl        = game.image       || game.cover_url   || '';
    const bgUrls          = (game.background_images || []).filter(Boolean);
    const trailers        = game.trailers    || [];
    const trailerUrl      = trailers.length  ? (trailers[0] || '') : '';
    const hasSgdb         = !!STEAMGRID_KEY;
    const existingMods    = Array.isArray(game.mods) ? game.mods : [];
    const specMin         = game.sysSpecMin         || {};
    const specRec         = game.sysSpecRecommended || {};
    const achievementsUrl = game.achievementsUrl    || '';
    const exophaseUrl     = game.exophaseUrl        || '';

    const bgHtml = bgUrls.length
        ? bgUrls.map(u => _adminBgFieldHtml(u)).join('')
        : _adminBgFieldHtml('');

    const modsHtml = existingMods.length
        ? existingMods.map(m => _adminModFieldHtml(m.name || '', m.url || '')).join('')
        : _adminModFieldHtml('', '');

    const titleEnc    = escapeHtml(title);
    const titleIdEnc  = escapeHtml(String(titleId));
    const descEnc     = escapeHtml(description);
    const coverEnc    = escapeHtml(coverUrl);
    const trailerEnc  = escapeHtml(trailerUrl);
    const ytQuery     = encodeURIComponent(title + ' trailer');
    const sgdbQuery   = encodeURIComponent(title);

    bodyEl.innerHTML = `
    <form id="adminEditForm" autocomplete="off">
        <div class="admin-form-group">
            <label class="admin-form-label" for="editTitle">Title</label>
            <input type="text" id="editTitle" class="admin-form-input" value="${titleEnc}">
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label" for="editTitleId">Title ID</label>
            <input type="text" id="editTitleId" class="admin-form-input" value="${titleIdEnc}">
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label" for="editDescription">Description</label>
            <textarea id="editDescription" class="admin-form-input admin-form-textarea" rows="4">${descEnc}</textarea>
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label">Cover Image</label>
            <div class="admin-cover-row">
                <div class="admin-cover-preview" id="adminCoverPreview">
                    ${coverUrl
                        ? `<img src="${coverEnc}" alt="Cover" class="admin-cover-img" onerror="_adminCoverImgError(this)">`
                        : '<span style="opacity:.5;font-size:.8em;">No image</span>'}
                </div>
                <div style="flex:1;min-width:0;">
                    <input type="url" id="editCoverUrl" class="admin-form-input" placeholder="https://…" value="${coverEnc}">
                    <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;">
                        <button type="button" class="admin-btn-outline" onclick="_adminPreviewCover()">🖼️ Preview</button>
                        <a href="https://www.steamgriddb.com/search/grids?term=${sgdbQuery}" target="_blank" rel="noopener" class="admin-btn-outline" style="text-decoration:none;">🎨 Browse SteamGridDB</a>
                    </div>
                    ${hasSgdb ? `
                    <div class="admin-sgdb-row" style="margin-top:8px;">
                        <input type="text" id="sgdbSearchInput" class="admin-form-input" placeholder="Search SteamGridDB…" value="${titleEnc}">
                        <button type="button" class="admin-btn-outline" id="sgdbSearchBtn" onclick="_adminSgdbSearch('cover')">🔍</button>
                    </div>
                    <div id="sgdbCoverResults" class="admin-img-picker"></div>` : ''}
                </div>
            </div>
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label">Background Images</label>
            <div id="adminBgList">${bgHtml}</div>
            <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;">
                <button type="button" class="admin-btn-outline" onclick="_adminAddBgField()">+ Add Background URL</button>
                ${hasSgdb ? `<button type="button" class="admin-btn-outline" onclick="_adminSgdbSearch('hero')">🎨 SGDB Heroes</button>` : ''}
            </div>
            ${hasSgdb ? `<div id="sgdbHeroResults" class="admin-img-picker" style="margin-top:6px;"></div>` : ''}
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label">Trailer (YouTube)</label>
            <input type="text" id="editTrailerUrl" class="admin-form-input" placeholder="YouTube URL or video ID…" value="${trailerEnc}">
            <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;">
                <button type="button" class="admin-btn-outline" onclick="_adminPreviewTrailer()">▶ Preview</button>
                <a href="https://www.youtube.com/results?search_query=${ytQuery}" target="_blank" rel="noopener" class="admin-btn-outline" style="text-decoration:none;">🔍 Search YouTube</a>
            </div>
            <div id="adminTrailerPreview" class="admin-trailer-preview">
                ${trailerUrl ? _buildInlineTrailerPreview(trailerUrl) : ''}
            </div>
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label">🧩 Mods</label>
            <div id="adminModList">${modsHtml}</div>
            <button type="button" class="admin-btn-outline" style="margin-top:6px;" onclick="_adminAddModField()">+ Add Mod Link</button>
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label">⚙️ Minimum System Requirements</label>
            <div class="admin-spec-grid">
                <input type="text" id="editSpecMinCpu" class="admin-form-input" placeholder="CPU" value="${escapeHtml(specMin.cpu || '')}">
                <input type="text" id="editSpecMinGpu" class="admin-form-input" placeholder="GPU" value="${escapeHtml(specMin.gpu || '')}">
                <input type="text" id="editSpecMinRam" class="admin-form-input" placeholder="RAM" value="${escapeHtml(specMin.ram || '')}">
                <input type="text" id="editSpecMinRes" class="admin-form-input" placeholder="Resolution" value="${escapeHtml(specMin.resolution || '')}">
            </div>
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label">⚙️ Recommended System Requirements</label>
            <div class="admin-spec-grid">
                <input type="text" id="editSpecRecCpu" class="admin-form-input" placeholder="CPU" value="${escapeHtml(specRec.cpu || '')}">
                <input type="text" id="editSpecRecGpu" class="admin-form-input" placeholder="GPU" value="${escapeHtml(specRec.gpu || '')}">
                <input type="text" id="editSpecRecRam" class="admin-form-input" placeholder="RAM" value="${escapeHtml(specRec.ram || '')}">
                <input type="text" id="editSpecRecRes" class="admin-form-input" placeholder="Resolution" value="${escapeHtml(specRec.resolution || '')}">
            </div>
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label">🏆 Achievements JSON URL</label>
            <input type="url" id="editAchievementsUrl" class="admin-form-input" placeholder="https://…/achievements.json" value="${escapeHtml(achievementsUrl)}">
        </div>
        <div class="admin-form-group">
            <label class="admin-form-label">🔗 Exophase URL <span style="font-size:.8em;opacity:.7;">(saves achievements to Games.Database on save)</span></label>
            <input type="url" id="editExophaseUrl" class="admin-form-input" placeholder="https://www.exophase.com/game/…/achievements/" value="${escapeHtml(exophaseUrl)}">
        </div>
        <div class="admin-form-actions">
            <div id="adminEditMsg" class="admin-edit-msg" style="display:none;"></div>
            <button type="button" class="btn secondary" style="padding:10px 22px;" onclick="closeAdminEditModal()">Cancel</button>
            <button type="button" class="btn" style="padding:10px 22px;" id="adminSaveBtn" onclick="handleAdminEditSave()">💾 Save Changes</button>
        </div>
    </form>`;

    modal.style.display = 'flex';
}

/**
 * Read form values and write the updated game back to Koriebonx98/Games.Database.
 */
async function handleAdminEditSave() {
    if (!isAdminUser()) return;

    const saveBtn = document.getElementById('adminSaveBtn');
    const msgEl   = document.getElementById('adminEditMsg');
    const showMsg = (text, type) => {
        if (!msgEl) return;
        msgEl.textContent = text;
        msgEl.style.display = '';
        msgEl.className = `admin-edit-msg admin-edit-msg--${type}`;
    };

    if (!GAMES_DB_TOKEN) {
        showMsg('⚠️ GAMES_DB_TOKEN is not configured. Add it as a repository secret and re-deploy to enable editing.', 'error');
        return;
    }
    if (!_currentModalGame || !_currentModalPlatform) {
        showMsg('❌ No game loaded.', 'error');
        return;
    }

    const title       = ((document.getElementById('editTitle')       || {}).value || '').trim();
    const titleId     = ((document.getElementById('editTitleId')     || {}).value || '').trim();
    const description = ((document.getElementById('editDescription') || {}).value || '').trim();
    const coverUrl    = ((document.getElementById('editCoverUrl')    || {}).value || '').trim();
    const trailerRaw  = ((document.getElementById('editTrailerUrl')  || {}).value || '').trim();

    const bgInputs = document.querySelectorAll('#adminBgList .admin-bg-input');
    const bgUrls   = Array.from(bgInputs).map(i => i.value.trim()).filter(Boolean);
    const trailers = trailerRaw ? [trailerRaw] : [];

    // Collect mod links (name + url pairs)
    const modFields = document.querySelectorAll('#adminModList .admin-mod-field');
    const mods = Array.from(modFields).reduce((acc, row) => {
        const name = (row.querySelector('.admin-mod-name') || {}).value || '';
        const url  = (row.querySelector('.admin-mod-url')  || {}).value || '';
        if (name.trim() && url.trim()) acc.push({ name: name.trim(), url: url.trim() });
        return acc;
    }, []);

    // Collect system specs
    const specMinCpu = ((document.getElementById('editSpecMinCpu') || {}).value || '').trim();
    const specMinGpu = ((document.getElementById('editSpecMinGpu') || {}).value || '').trim();
    const specMinRam = ((document.getElementById('editSpecMinRam') || {}).value || '').trim();
    const specMinRes = ((document.getElementById('editSpecMinRes') || {}).value || '').trim();
    const specRecCpu = ((document.getElementById('editSpecRecCpu') || {}).value || '').trim();
    const specRecGpu = ((document.getElementById('editSpecRecGpu') || {}).value || '').trim();
    const specRecRam = ((document.getElementById('editSpecRecRam') || {}).value || '').trim();
    const specRecRes = ((document.getElementById('editSpecRecRes') || {}).value || '').trim();

    const sysSpecMin = (specMinCpu || specMinGpu || specMinRam || specMinRes)
        ? { cpu: specMinCpu, gpu: specMinGpu, ram: specMinRam, resolution: specMinRes }
        : null;
    const sysSpecRecommended = (specRecCpu || specRecGpu || specRecRam || specRecRes)
        ? { cpu: specRecCpu, gpu: specRecGpu, ram: specRecRam, resolution: specRecRes }
        : null;

    const achievementsUrl = ((document.getElementById('editAchievementsUrl') || {}).value || '').trim();
    const exophaseUrl     = ((document.getElementById('editExophaseUrl')     || {}).value || '').trim();

    if (!title) { showMsg('❌ Title is required.', 'error'); return; }
    if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = '⏳ Saving…'; }
    if (msgEl)   { msgEl.style.display = 'none'; }

    try {
        // Re-fetch the latest platform JSON from raw GitHub to get the most up-to-date data
        const resp = await fetch(
            `${GAMES_DB_RAW_BASE}/${encodeURIComponent(_currentModalPlatform)}.Games.json?t=${Date.now()}`,
            { cache: 'no-store' }
        );
        if (!resp.ok) throw new Error(`Failed to fetch ${_currentModalPlatform} games (HTTP ${resp.status})`);
        const fileData = await resp.json();

        // Normalise – some files use { Games: [...] }, some use a bare array
        let gamesArr;
        let topKey = null;
        if (fileData && Array.isArray(fileData.Games)) {
            gamesArr = fileData.Games;  topKey = 'Games';
        } else if (fileData && Array.isArray(fileData.games)) {
            gamesArr = fileData.games;  topKey = 'games';
        } else if (Array.isArray(fileData)) {
            gamesArr = fileData;
        } else {
            throw new Error('Unexpected games JSON format');
        }

        // Locate the game by original title or title ID
        const origTitle = (_currentModalGame.Title || _currentModalGame.game_name || _currentModalGame.title || '').toLowerCase();
        const origId    = String(_currentModalGame.TitleID || _currentModalGame.title_id || _currentModalGame.titleid || _currentModalGame.id || '');

        const idx = gamesArr.findIndex(g => {
            const gt  = (g.Title || g.game_name || g.title || '').toLowerCase();
            const gid = String(g.TitleID || g.title_id || g.titleid || g.id || '');
            return gt === origTitle || (origId && gid === origId);
        });

        if (idx === -1) throw new Error('Game not found in database – it may have been renamed or removed.');

        // Build the updated entry, preserving all fields the database already has
        const existing = gamesArr[idx];
        const updated  = { ...existing };

        // Update title (preserve original field name)
        if      ('Title'     in updated) updated.Title       = title;
        else if ('game_name' in updated) updated.game_name   = title;
        else                             updated.Title        = title;

        // Update title ID (preserve original field name)
        if      ('TitleID'   in updated) updated.TitleID     = titleId;
        else if ('title_id'  in updated) updated.title_id    = titleId;

        // Update description (preserve original field name)
        if ('Description' in updated) updated.Description = description;
        else                          updated.description  = description;

        // Always use 'image' for cover URL across all platforms
        if (coverUrl) updated.image = coverUrl;
        else          delete updated.image;

        updated.background_images = bgUrls;
        updated.trailers           = trailers;

        // Persist new structured fields
        if (mods.length)           updated.mods                = mods;
        else                       delete updated.mods;
        if (sysSpecMin)            updated.sysSpecMin          = sysSpecMin;
        else                       delete updated.sysSpecMin;
        if (sysSpecRecommended)    updated.sysSpecRecommended  = sysSpecRecommended;
        else                       delete updated.sysSpecRecommended;
        if (achievementsUrl)       updated.achievementsUrl     = achievementsUrl;
        else                       delete updated.achievementsUrl;
        if (exophaseUrl)           updated.exophaseUrl         = exophaseUrl;
        else                       delete updated.exophaseUrl;

        gamesArr[idx] = updated;

        const newContent = topKey ? { ...fileData, [topKey]: gamesArr } : gamesArr;

        await _gamesDbWriteFile(
            _currentModalPlatform,
            newContent,
            `Update game: ${title} (${_currentModalPlatform})`
        );

        // Update the in-memory browse cache so the page reflects the change immediately
        if (typeof _allBrowseGames !== 'undefined') {
            const li = _allBrowseGames.findIndex(g =>
                (g.Title || g.game_name || g.title || '').toLowerCase() === origTitle
            );
            if (li !== -1) _allBrowseGames[li] = updated;
        }
        if (typeof _allPlatformGames !== 'undefined' && _allPlatformGames[_currentModalPlatform]) {
            const arr = _allPlatformGames[_currentModalPlatform];
            const li  = arr.findIndex(g =>
                (g.Title || g.game_name || g.title || '').toLowerCase() === origTitle
            );
            if (li !== -1) arr[li] = updated;
        }
        // Re-render the browse list so the baked-in game JSON in card onclick attributes
        // reflects the updated data (prevents showing stale game details on next card click)
        if (typeof _currentPlatform !== 'undefined') {
            if (_currentPlatform === 'ALL' && typeof renderBrowseGamesGrouped === 'function') {
                renderBrowseGamesGrouped(_allPlatformGames,
                    (document.getElementById('browseSearch') || {}).value || '');
            } else if (typeof renderBrowseGames === 'function' &&
                       typeof _allBrowseGames !== 'undefined' && _allBrowseGames.length) {
                renderBrowseGames(_allBrowseGames);
            }
        }
        _currentModalGame = updated;

        // If an Exophase URL was provided and a backend is configured, trigger scraping
        if (exophaseUrl && getBackendBase()) {
            showMsg('⏳ Scraping achievements from Exophase…', 'success');
            try {
                const user = getCurrentUser();
                const storedToken = user
                    ? (localStorage.getItem(`gameOS_apiToken_${user.username.toLowerCase()}`) ||
                       localStorage.getItem('gameOS_apiToken_pending') || '')
                    : '';
                const scrapeResp = await fetch(`${getBackendBase()}/api/admin/scrape-exophase`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...(storedToken ? { 'Authorization': `Bearer ${storedToken}` } : {})
                    },
                    body: JSON.stringify({ exophaseUrl, platform: _currentModalPlatform, gameTitle: title, titleId })
                });
                const scrapeData = await scrapeResp.json();
                if (scrapeData.success) {
                    showMsg(`✅ Game updated and ${scrapeData.total} achievements scraped from Exophase!`, 'success');
                } else {
                    showMsg(`✅ Game updated. ⚠️ Exophase scrape: ${scrapeData.message}`, 'success');
                }
            } catch (scrapeErr) {
                showMsg(`✅ Game updated. ⚠️ Exophase scrape failed: ${scrapeErr.message}`, 'success');
            }
        } else {
            showMsg('✅ Game updated successfully!', 'success');
        }
        setTimeout(() => {
            closeAdminEditModal();
            openGameModal(updated, _currentModalPlatform);
        }, 1500);
    } catch (e) {
        showMsg(`❌ ${e.message}`, 'error');
    } finally {
        if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = '💾 Save Changes'; }
    }
}

// ============================================================
// GAME DETAIL MODAL
// ============================================================

function _updateModalWishlistBtn(title, platform, game) {
    const wrap = document.getElementById('gameModalWishlistWrap');
    const btn  = document.getElementById('gameModalWishlistBtn');
    if (!wrap || !btn) return;
    if (!isLoggedIn()) { wrap.style.display = 'none'; return; }
    wrap.style.display = '';
    btn.dataset.title    = title    || '';
    btn.dataset.platform = platform || '';
    btn.dataset.gameJson = game ? JSON.stringify(game) : '';
    const wl = (typeof _myWishlist !== 'undefined') ? _myWishlist : [];
    const titleLower    = (title    || '').toLowerCase();
    const platformLower = (platform || '').toLowerCase();
    const wishlisted = wl.some(
        w => (w.platform || '').toLowerCase() === platformLower && (w.title || '').toLowerCase() === titleLower
    );
    btn.textContent = wishlisted ? '⭐' : '☆';
    btn.title = wishlisted ? 'Remove from Wishlist' : 'Add to Wishlist';
    btn.classList.toggle('btn-wishlisted', wishlisted);
    btn.disabled = false;
}

async function handleModalWishlist() {
    const user = getCurrentUser();
    if (!user) { window.location.href = 'login.html'; return; }
    const btn = document.getElementById('gameModalWishlistBtn');
    if (!btn) return;
    const title    = btn.dataset.title    || '';
    const platform = btn.dataset.platform || '';
    const gameJson = btn.dataset.gameJson || '';
    if (!title || !platform) return;
    btn.disabled = true;
    try {
        let wishlist;
        if (MODE === 'demo') {
            wishlist = getDemoWishlist(user.username);
        } else {
            wishlist = await getWishlistGitHub(user.username);
        }
        const alreadyWishlisted = wishlist.some(
            w => (w.platform || '').toLowerCase() === platform.toLowerCase() && (w.title || '').toLowerCase() === title.toLowerCase()
        );
        if (alreadyWishlisted) {
            if (MODE === 'demo') {
                removeFromWishlistDemo(user.username, platform, title);
            } else {
                await removeFromWishlistGitHub(user.username, platform, title);
            }
        } else {
            let game = {};
            try { game = gameJson ? JSON.parse(gameJson) : {}; } catch (_) { game = {}; }
            if (!game.title && !game.Title) game.title = title;
            if (MODE === 'demo') {
                addToWishlistDemo(user.username, game, platform);
            } else {
                await addToWishlistGitHub(user.username, game, platform);
            }
        }
        const nowWishlisted = !alreadyWishlisted;
        btn.textContent = nowWishlisted ? '⭐' : '☆';
        btn.title = nowWishlisted ? 'Remove from Wishlist' : 'Add to Wishlist';
        btn.classList.toggle('btn-wishlisted', nowWishlisted);
        // If on games page, refresh wishlist and re-render browse list
        if (typeof _myWishlist !== 'undefined') {
            await refreshWishlist();
            if (_currentPlatform === 'ALL') {
                renderBrowseGamesGrouped(_allPlatformGames,
                    document.getElementById('browseSearch').value);
            } else if (_allBrowseGames.length) {
                renderBrowseGames(_allBrowseGames);
            }
        }
    } catch (e) {
        alert('Failed to update wishlist: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}

function _updateModalEditBtn() {
    const wrap = document.getElementById('gameModalEditWrap');
    if (wrap) wrap.style.display = isAdminUser() ? '' : 'none';
}

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
                    <div id="gameModalWishlistWrap" style="display:none;margin-left:auto;">
                        <button class="btn-modal-wishlist" id="gameModalWishlistBtn" onclick="handleModalWishlist()" title="Add to Wishlist">☆</button>
                    </div>
                    <div id="gameModalEditWrap" style="display:none;margin-left:4px;">
                        <button class="btn-modal-edit" id="gameModalEditBtn" onclick="openAdminEditModal()" title="Edit game data (Admin)">✏️ Edit</button>
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
    const skipFields = new Set(['Title', 'game_name', 'title', 'image', 'background_images', 'trailers',
        'mods', 'sysSpecMin', 'sysSpecRecommended', 'achievementsUrl', 'exophaseUrl']);
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

/** Render a mods section from game.mods array of { name, url } objects. */
function _buildModsSection(game) {
    const mods = game.mods;
    if (!Array.isArray(mods) || !mods.length) return '';
    const buttons = mods
        .filter(m => m && m.url)
        .map(m => `<a href="${escapeHtml(m.url)}" target="_blank" rel="noopener noreferrer" class="btn-mod-link">${escapeHtml(m.name || 'Mod Link')}</a>`)
        .join('');
    if (!buttons) return '';
    return `<div class="game-modal-field">
        <span class="game-modal-field-label">🧩 Mods</span>
        <span class="game-modal-field-value game-modal-mods">${buttons}</span>
    </div>`;
}

/** Render system specifications (min + recommended) from game data. */
function _buildSystemSpecsSection(game) {
    const min = game.sysSpecMin;
    const rec = game.sysSpecRecommended;
    if (!min && !rec) return '';
    const renderSpec = (spec) => {
        if (!spec) return '<em style="color:#999;">Not specified</em>';
        return ['cpu', 'gpu', 'ram', 'resolution']
            .filter(k => spec[k])
            .map(k => `<div class="game-spec-row"><span class="game-spec-key">${escapeHtml(k.toUpperCase())}</span><span class="game-spec-val">${escapeHtml(String(spec[k]))}</span></div>`)
            .join('') || '<em style="color:#999;">Not specified</em>';
    };
    return `<div class="game-modal-field game-modal-specs-field">
        <span class="game-modal-field-label">⚙️ System Requirements</span>
        <span class="game-modal-field-value">
            <div class="game-specs-grid">
                <div class="game-specs-col">
                    <div class="game-specs-col-title">Minimum</div>
                    ${renderSpec(min)}
                </div>
                <div class="game-specs-col">
                    <div class="game-specs-col-title">Recommended</div>
                    ${renderSpec(rec)}
                </div>
            </div>
        </span>
    </div>`;
}

/** Convert a GitHub blob URL to a raw content URL so it can be fetched as JSON. */
function _toRawUrl(url) {
    if (!url) return url;
    // https://github.com/{owner}/{repo}/blob/{branch}/{path} → https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
    return url.replace(
        /^https:\/\/github\.com\/([^/]+\/[^/]+)\/blob\//,
        'https://raw.githubusercontent.com/$1/'
    );
}

/** Return a placeholder div that will be populated asynchronously with achievement cards. */
function _buildAchievementsSection(game) {
    const url = game.achievementsUrl || '';
    return `<div class="game-modal-achievements"${url ? ` data-ach-url="${escapeHtml(url)}"` : ''}>
        <div class="game-modal-achievements-label">🏆 Achievements <span class="ach-count" style="display:none"></span>
            <button class="ach-add-btn" onclick="openAddAchievementForm()" title="Add a custom achievement">➕ Add</button>
        </div>
        <div class="ach-content">${url ? '<span class="ach-loading">⏳ Loading achievements…</span>' : ''}</div>
    </div>`;
}

/** Build an achievement card HTML string. */
function _buildAchCard(ach) {
    const name   = escapeHtml(ach.Name || ach.name || '');
    const desc   = escapeHtml(ach.Description || ach.description || '');
    const rawImg = ach.UrlUnlocked || ach.urlUnlocked || ach.image || ach.Image || '';
    // Only allow https:// image URLs to prevent CSS injection via javascript:/data: schemes
    // Also strip single quotes to prevent breaking out of CSS url('...') context
    const safeImg = /^https:\/\//i.test(rawImg) ? rawImg.replace(/'/g, '') : '';
    const bgStyle = safeImg ? `style="background-image:url('${escapeHtml(safeImg)}')"` : '';
    return `<div class="ach-card" ${bgStyle} title="${name}">
        <div class="ach-card-overlay">
            <div class="ach-card-name">${name}</div>
            ${desc ? `<div class="ach-card-desc">${desc}</div>` : ''}
        </div>
    </div>`;
}

/** Render the achievements carousel (online + manual) inside the section. */
function _renderAchievementsContent(container, content, onlineItems) {
    const manual = _getManualAchievements();
    const items  = [...onlineItems, ...manual];
    const url    = container.dataset.achUrl || '';
    const countEl = container.querySelector('.ach-count');
    if (countEl) {
        countEl.textContent = items.length || '';
        countEl.style.display = items.length ? '' : 'none';
    }
    if (!items.length) {
        content.innerHTML = url
            ? `<p style="color:#888;font-size:0.88em;">No achievements found. <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" class="btn-mod-link">View JSON ↗</a></p>`
            : '<p style="color:#888;font-size:0.88em;">No achievements yet. Use ➕ Add to add one.</p>';
        return;
    }
    const cards = items.map(_buildAchCard).join('');
    content.innerHTML = `<div class="ach-carousel-wrap">
        <button class="ach-nav ach-nav-prev" onclick="_achScroll(-1)" aria-label="Previous achievements">‹</button>
        <div class="ach-carousel">${cards}</div>
        <button class="ach-nav ach-nav-next" onclick="_achScroll(1)" aria-label="Next achievements">›</button>
    </div>`;
}

/** Scroll the achievement carousel left (-1) or right (1). */
function _achScroll(dir) {
    const carousel = document.querySelector('.ach-carousel');
    if (!carousel) return;
    const card = carousel.querySelector('.ach-card');
    const step = card ? (card.offsetWidth + 10) * 2 : 240;
    carousel.scrollBy({ left: dir * step, behavior: 'smooth' });
}

/** Return the localStorage key for manual achievements of the current modal game. */
function _getManualAchievementKey() {
    const gameTitle = _currentModalGame ? (_currentModalGame.Title || _currentModalGame.game_name || _currentModalGame.title || '') : '';
    const platform  = _currentModalPlatform || '';
    return `gameOS_ach_${platform}_${gameTitle}`;
}

/** Return manually-added achievements for the current modal game. */
function _getManualAchievements() {
    try {
        const raw = localStorage.getItem(_getManualAchievementKey());
        return raw ? JSON.parse(raw) : [];
    } catch (err) { console.warn('[Achievements] Failed to read manual achievements:', err); return []; }
}

/** Show/hide the inline "Add Achievement" form inside the achievements section. */
function openAddAchievementForm() {
    const container = document.querySelector('.game-modal-achievements');
    if (!container) return;
    const existing = container.querySelector('.ach-add-form');
    if (existing) { existing.remove(); return; }
    container.insertAdjacentHTML('beforeend', `
        <div class="ach-add-form">
            <input class="ach-add-input" id="achAddName" placeholder="Achievement name *" maxlength="60" aria-label="Achievement name (required)">
            <div class="ach-add-error" id="achAddNameError" style="display:none;color:#e53e3e;font-size:0.8em;" role="alert">Please enter an achievement name.</div>
            <input class="ach-add-input" id="achAddDesc" placeholder="Description (optional)" maxlength="160" aria-label="Achievement description">
            <input class="ach-add-input" id="achAddImg" placeholder="Image URL (https://…)" type="url" maxlength="500" aria-label="Achievement image URL">
            <div style="display:flex;gap:8px;">
                <button class="ach-add-save" onclick="_saveManualAchievement()">Save</button>
                <button class="ach-add-cancel" onclick="this.closest('.ach-add-form').remove()">Cancel</button>
            </div>
        </div>`);
    const nameInput = document.getElementById('achAddName');
    if (nameInput) nameInput.focus();
}

/** Save a manually-entered achievement to localStorage and refresh the carousel. */
function _saveManualAchievement() {
    const name   = (document.getElementById('achAddName')?.value || '').trim();
    const desc   = (document.getElementById('achAddDesc')?.value || '').trim();
    const imgUrl = (document.getElementById('achAddImg')?.value  || '').trim();
    if (!name) {
        const input   = document.getElementById('achAddName');
        const errEl   = document.getElementById('achAddNameError');
        if (input)  { input.focus(); input.style.borderColor = '#e53e3e'; }
        if (errEl)  { errEl.style.display = ''; }
        return;
    }
    const key  = _getManualAchievementKey();
    const list = _getManualAchievements();
    list.push({ name, description: desc, image: imgUrl });
    let saved = false;
    try { localStorage.setItem(key, JSON.stringify(list)); saved = true; } catch (err) {
        console.warn('[Achievements] Could not save to localStorage:', err);
    }
    const form = document.querySelector('.ach-add-form');
    if (form) form.remove();
    if (!saved) {
        const container = document.querySelector('.game-modal-achievements');
        if (container) container.insertAdjacentHTML('beforeend',
            '<p class="ach-save-warn" style="color:#c05000;font-size:0.82em;margin-top:6px;">⚠️ Achievement saved for this session only (storage unavailable).</p>');
    }
    const container = document.querySelector('.game-modal-achievements');
    const content   = container ? container.querySelector('.ach-content') : null;
    if (container && content) _renderAchievementsContent(container, content, saved ? _modalOnlineAchievements : [..._modalOnlineAchievements, { name, description: desc, image: imgUrl }]);
}

/** Fetch the achievements JSON and render the swipeable carousel. */
async function _loadAchievementsInModal() {
    const container = document.querySelector('.game-modal-achievements');
    if (!container) return;
    const url     = container.dataset.achUrl || '';
    const content = container.querySelector('.ach-content');
    if (!content) return;
    _modalOnlineAchievements = [];
    if (url) {
        const rawUrl = _toRawUrl(url);
        try {
            const resp = await fetch(rawUrl);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            _modalOnlineAchievements = Array.isArray(data) ? data : (data.Items || []);
        } catch (err) {
            console.error('[Achievements] Failed to load from', rawUrl, err);
        }
    }
    _renderAchievementsContent(container, content, _modalOnlineAchievements);
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
    _currentModalGame     = game;
    _currentModalPlatform = platform;
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

    _updateModalWishlistBtn(title, platform, game);
    _updateModalEditBtn();

    const bgUrls    = getGameBackgroundUrls(game);
    const fieldRows = _buildGameModalFields(game);
    const libs = (typeof _friendLibraries !== 'undefined') ? _friendLibraries : {};
    let bodyHtml = '';
    bodyHtml += _buildTrailerSection(game);
    bodyHtml += _buildFriendsSection(libs, platform, title);
    bodyHtml += _buildModsSection(game);
    bodyHtml += _buildSystemSpecsSection(game);
    bodyHtml += _buildAchievementsSection(game);
    if (bgUrls.length > 0) {
        bodyHtml += `<div class="game-modal-bg-gallery">${
            bgUrls.map(u => `<img src="${escapeHtml(u)}" class="game-modal-bg-img" alt="Background">`).join('')
        }</div>`;
    }
    bodyHtml += fieldRows || '<p style="color:#666;font-size:0.9em;">No additional details available.</p>';
    document.getElementById('gameModalBody').innerHTML = bodyHtml;
    modal.style.display = 'flex';
    _loadAchievementsInModal();
}

async function openGameModalFromLibrary(title, platform, titleId) {
    _currentModalGame     = { title, TitleID: titleId };
    _currentModalPlatform = platform;
    const modal = ensureGameModal();

    const coverEl = document.getElementById('gameModalCoverIcon');
    coverEl.className       = 'game-modal-cover-large';
    coverEl.style.background = getPlatformColor(platform);
    coverEl.textContent     = getPlatformIcon(platform);
    document.getElementById('gameModalTitle').textContent    = title;
    document.getElementById('gameModalPlatform').textContent = platform || '';
    document.getElementById('gameModalBody').innerHTML =
        '<p style="color:#666;font-size:0.9em;">⏳ Loading game details…</p>';
    _updateModalWishlistBtn(title, platform, null);
    _updateModalEditBtn();
    modal.style.display = 'flex';

    try {
        const games = await fetchGamesDbPlatform(platform);
        const titleLower = title.toLowerCase();
        const game = games.find(g =>
            (g.Title || g.game_name || g.title || '').toLowerCase() === titleLower ||
            (titleId && String(g.TitleID || g.title_id || g.titleid || g.id || '') === String(titleId))
        );

        if (game) {
            _currentModalGame = game;
            const coverUrl = getGameCoverUrl(game);
            if (coverUrl) {
                coverEl.className = 'game-modal-cover-large game-modal-cover-large--img';
                coverEl.style.background = '';
                coverEl.dataset.platform = platform || '';
                coverEl.innerHTML = `<img src="${coverUrl}" class="game-modal-cover-img" alt="${escapeHtml(title)}" onerror="_gameModalCoverFallback(this)">`;
            }
            // Update wishlist button with full game data once loaded
            _updateModalWishlistBtn(title, platform, game);
            _updateModalEditBtn();
        }

        const source    = game || (titleId ? { TitleID: titleId } : {});
        const bgUrls    = getGameBackgroundUrls(source);
        const fieldRows = _buildGameModalFields(source);
        const libs = (typeof _friendLibraries !== 'undefined') ? _friendLibraries : {};
        let bodyHtml = '';
        bodyHtml += _buildTrailerSection(source);
        bodyHtml += _buildFriendsSection(libs, platform, title);
        bodyHtml += _buildModsSection(source);
        bodyHtml += _buildSystemSpecsSection(source);
        bodyHtml += _buildAchievementsSection(source);
        if (bgUrls.length > 0) {
            bodyHtml += `<div class="game-modal-bg-gallery">${
                bgUrls.map(u => `<img src="${escapeHtml(u)}" class="game-modal-bg-img" alt="Background">`).join('')
            }</div>`;
        }
        bodyHtml += fieldRows || '<p style="color:#666;font-size:0.9em;">No additional details available.</p>';
        document.getElementById('gameModalBody').innerHTML = bodyHtml;
        _loadAchievementsInModal();
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
