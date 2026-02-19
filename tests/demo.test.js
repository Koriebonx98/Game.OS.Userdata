/**
 * Automated tests for Game.OS Userdata – Demo Mode
 *
 * Exercises the core account-management logic (hashing, signup, login) using
 * the same algorithms as script.js but running entirely in Node.js so no browser
 * is required.  All tests use the Node.js built-in test runner (node:test) and
 * the Web Crypto API that ships with Node.js >= 18.
 *
 * Run:  node --test tests/demo.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

// ─────────────────────────────────────────────────────────────────────────────
// Minimal in-memory localStorage shim
// ─────────────────────────────────────────────────────────────────────────────
const store = {};
const localStorage = {
    getItem:    (k) => (k in store ? store[k] : null),
    setItem:    (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; }
};

// ─────────────────────────────────────────────────────────────────────────────
// Replicate the exact hashing functions from script.js
// ─────────────────────────────────────────────────────────────────────────────

/** SHA-256 hex hash (demo mode) */
async function hashPasswordDemo(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/** PBKDF2 hex hash (GitHub mode) */
async function hashPassword(password, username) {
    const encoder = new TextEncoder();
    const keyMat = await crypto.subtle.importKey(
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
        256
    );
    return Array.from(new Uint8Array(bits))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// Replicate the demo-mode account functions from script.js
// ─────────────────────────────────────────────────────────────────────────────

function getDemoAccounts() {
    const accounts = localStorage.getItem('gameOS_accounts');
    return accounts ? JSON.parse(accounts) : [];
}

function saveDemoAccounts(accounts) {
    localStorage.setItem('gameOS_accounts', JSON.stringify(accounts));
}

async function createAccountDemo(username, email, password) {
    const passwordHash = await hashPasswordDemo(password);
    return new Promise((resolve) => {
        setTimeout(() => {
            const accounts = getDemoAccounts();

            if (accounts.find(acc => acc.username.toLowerCase() === username.toLowerCase())) {
                resolve({ success: false, message: 'Username already exists' });
                return;
            }

            if (accounts.find(acc => acc.email.toLowerCase() === email.toLowerCase())) {
                resolve({ success: false, message: 'Email already registered' });
                return;
            }

            accounts.push({
                username,
                email,
                password_hash: passwordHash,
                createdAt: new Date().toISOString()
            });
            saveDemoAccounts(accounts);
            resolve({ success: true, message: 'Account created successfully' });
        }, 0); // no artificial delay needed for tests
    });
}

async function verifyAccountDemo(identifier, password) {
    const passwordHash = await hashPasswordDemo(password);
    return new Promise((resolve) => {
        setTimeout(() => {
            const accounts = getDemoAccounts();
            const account = accounts.find(acc =>
                acc.email.toLowerCase()    === identifier.toLowerCase() ||
                acc.username.toLowerCase() === identifier.toLowerCase()
            );

            if (!account) {
                resolve({ success: false, message: 'Account not found' });
                return;
            }

            if (account.password_hash !== passwordHash) {
                resolve({ success: false, message: 'Invalid password' });
                return;
            }

            resolve({
                success: true,
                message: 'Login successful',
                user: { username: account.username, email: account.email }
            });
        }, 0);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

describe('Password hashing', () => {
    test('hashPasswordDemo returns a 64-character hex string', async () => {
        const hash = await hashPasswordDemo('password123');
        assert.match(hash, /^[0-9a-f]{64}$/);
    });

    test('hashPasswordDemo is deterministic', async () => {
        const h1 = await hashPasswordDemo('mySecret');
        const h2 = await hashPasswordDemo('mySecret');
        assert.equal(h1, h2);
    });

    test('hashPasswordDemo produces different hashes for different passwords', async () => {
        const h1 = await hashPasswordDemo('abc');
        const h2 = await hashPasswordDemo('def');
        assert.notEqual(h1, h2);
    });

    test('hashPassword (PBKDF2) returns a 64-character hex string', async () => {
        const hash = await hashPassword('password123', 'testuser');
        assert.match(hash, /^[0-9a-f]{64}$/);
    });

    test('hashPassword is deterministic for the same user', async () => {
        const h1 = await hashPassword('mySecret', 'alice');
        const h2 = await hashPassword('mySecret', 'alice');
        assert.equal(h1, h2);
    });

    test('hashPassword differs per user (username acts as salt)', async () => {
        const h1 = await hashPassword('samePassword', 'alice');
        const h2 = await hashPassword('samePassword', 'bob');
        assert.notEqual(h1, h2);
    });
});

describe('Demo mode – account creation', () => {
    test('creates a test account successfully', async () => {
        // Clear storage before test
        localStorage.removeItem('gameOS_accounts');

        const result = await createAccountDemo('TestPlayer', 'test@example.com', 'password123');
        assert.equal(result.success, true);
        assert.equal(result.message, 'Account created successfully');

        const accounts = getDemoAccounts();
        assert.equal(accounts.length, 1);
        assert.equal(accounts[0].username, 'TestPlayer');
        assert.equal(accounts[0].email, 'test@example.com');
        // Password must NOT be stored in plaintext
        assert.notEqual(accounts[0].password_hash, 'password123');
        assert.match(accounts[0].password_hash, /^[0-9a-f]{64}$/);
    });

    test('rejects a duplicate username', async () => {
        const result = await createAccountDemo('TestPlayer', 'other@example.com', 'pass456');
        assert.equal(result.success, false);
        assert.equal(result.message, 'Username already exists');
    });

    test('rejects a duplicate email', async () => {
        const result = await createAccountDemo('AnotherPlayer', 'test@example.com', 'pass789');
        assert.equal(result.success, false);
        assert.equal(result.message, 'Email already registered');
    });
});

describe('Demo mode – login', () => {
    test('logs in with correct username and password', async () => {
        const result = await verifyAccountDemo('TestPlayer', 'password123');
        assert.equal(result.success, true);
        assert.equal(result.message, 'Login successful');
        assert.equal(result.user.username, 'TestPlayer');
        assert.equal(result.user.email, 'test@example.com');
    });

    test('logs in with correct email and password', async () => {
        const result = await verifyAccountDemo('test@example.com', 'password123');
        assert.equal(result.success, true);
        assert.equal(result.user.username, 'TestPlayer');
    });

    test('rejects an incorrect password', async () => {
        const result = await verifyAccountDemo('TestPlayer', 'wrongpassword');
        assert.equal(result.success, false);
        assert.equal(result.message, 'Invalid password');
    });

    test('rejects an unknown username', async () => {
        const result = await verifyAccountDemo('ghost', 'password123');
        assert.equal(result.success, false);
        assert.equal(result.message, 'Account not found');
    });

    test('rejects an unknown email', async () => {
        const result = await verifyAccountDemo('nobody@example.com', 'password123');
        assert.equal(result.success, false);
        assert.equal(result.message, 'Account not found');
    });

    test('login lookup is case-insensitive for username', async () => {
        const result = await verifyAccountDemo('testplayer', 'password123');
        assert.equal(result.success, true);
    });
});

describe('Demo mode – full account lifecycle (create → login → wrong-password)', () => {
    test('complete flow for a second account', async () => {
        // Create a fresh account
        const signup = await createAccountDemo('GamerOne', 'gamer@gameos.com', 'g@m3rP@ss!');
        assert.equal(signup.success, true, 'signup should succeed');

        // Correct-password login by username
        const loginOk = await verifyAccountDemo('GamerOne', 'g@m3rP@ss!');
        assert.equal(loginOk.success, true, 'login with correct password should succeed');
        assert.equal(loginOk.user.username, 'GamerOne');

        // Correct-password login by email
        const loginEmail = await verifyAccountDemo('gamer@gameos.com', 'g@m3rP@ss!');
        assert.equal(loginEmail.success, true, 'login by email should succeed');

        // Wrong-password login
        const loginBad = await verifyAccountDemo('GamerOne', 'badpassword');
        assert.equal(loginBad.success, false, 'login with wrong password should fail');
        assert.equal(loginBad.message, 'Invalid password');
    });
});
