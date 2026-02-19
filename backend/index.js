/**
 * Game.OS Userdata – Backend Server
 *
 * Stores user accounts as JSON files in a private GitHub repository.
 * Deploy this server to Railway, Render, Fly.io, or any Node.js host.
 *
 * Required environment variables (see .env.example):
 *   GITHUB_TOKEN  - Personal access token with "repo" scope
 *   REPO_OWNER    - GitHub username/org that owns the data repo
 *   REPO_NAME     - Name of the private data repository
 *   PORT          - (optional) Port to listen on, default 3000
 *   ALLOWED_ORIGIN - (optional) Frontend URL for CORS, default allows all
 */

const express = require('express');
const { Octokit } = require('@octokit/rest');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ── CORS ──────────────────────────────────────────────────────────────────────
const corsOptions = {
    origin: process.env.ALLOWED_ORIGIN || '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
};
app.use(cors(corsOptions));

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));

// ── GitHub client ─────────────────────────────────────────────────────────────
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const REPO_OWNER = process.env.REPO_OWNER;
const REPO_NAME  = process.env.REPO_NAME;
const BCRYPT_ROUNDS = 10;

// ── GitHub helpers ────────────────────────────────────────────────────────────

/**
 * Read a JSON file from the data repository.
 * Returns { content, sha } on success, or null if the file doesn't exist.
 */
async function getFile(path) {
    try {
        const { data } = await octokit.repos.getContent({
            owner: REPO_OWNER,
            repo:  REPO_NAME,
            path
        });
        const content = Buffer.from(data.content, 'base64').toString('utf8');
        return { content: JSON.parse(content), sha: data.sha };
    } catch (err) {
        if (err.status === 404) return null;
        throw err;
    }
}

/**
 * Create or update a JSON file in the data repository.
 * Pass `sha` when updating an existing file.
 */
async function putFile(path, content, message, sha) {
    const params = {
        owner: REPO_OWNER,
        repo:  REPO_NAME,
        path,
        message,
        content: Buffer.from(JSON.stringify(content, null, 2)).toString('base64'),
        committer: {
            name:  'Game OS Bot',
            email: 'bot@gameos.com'
        }
    };
    if (sha) params.sha = sha;
    await octokit.repos.createOrUpdateFileContents(params);
}

// ── Validation helpers ────────────────────────────────────────────────────────

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sanitiseUsername(username) {
    // Allow only alphanumeric, underscore, and hyphen
    return /^[a-zA-Z0-9_-]+$/.test(username);
}

// ── Routes ────────────────────────────────────────────────────────────────────

// Health check – the frontend polls this to detect the backend
app.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'Game.OS backend running' });
});

// ── POST /api/create-account ──────────────────────────────────────────────────
app.post('/api/create-account', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Input validation
        if (!username || !email || !password) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        if (username.length < 3) {
            return res.status(400).json({ success: false, message: 'Username must be at least 3 characters' });
        }
        if (!sanitiseUsername(username)) {
            return res.status(400).json({ success: false, message: 'Username may only contain letters, numbers, underscores, and hyphens' });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ success: false, message: 'Please enter a valid email address' });
        }
        if (password.length < 6) {
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
        }

        // Check for duplicate username
        const existingAccount = await getFile(`accounts/${username.toLowerCase()}.json`);
        if (existingAccount) {
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }

        // Check for duplicate email via index
        const emailIndexFile = await getFile('accounts/email-index.json');
        const emailMap = emailIndexFile ? emailIndexFile.content : {};
        if (emailMap[email.toLowerCase()]) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }

        // Hash the password server-side with bcrypt
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        // Write account file
        const accountData = {
            username,
            email,
            password_hash: passwordHash,
            created_at: new Date().toISOString()
        };
        await putFile(
            `accounts/${username.toLowerCase()}.json`,
            accountData,
            `Create account: ${username}`
        );

        // Update email → username index (retry once on SHA conflict)
        emailMap[email.toLowerCase()] = username.toLowerCase();
        try {
            await putFile(
                'accounts/email-index.json',
                emailMap,
                `Add email index for: ${username}`,
                emailIndexFile ? emailIndexFile.sha : undefined
            );
        } catch (indexErr) {
            // If another registration raced us, re-fetch and retry
            if (indexErr.status === 409 || indexErr.status === 422) {
                const freshIndex = await getFile('accounts/email-index.json');
                const freshMap = freshIndex ? freshIndex.content : {};
                freshMap[email.toLowerCase()] = username.toLowerCase();
                await putFile(
                    'accounts/email-index.json',
                    freshMap,
                    `Add email index for: ${username}`,
                    freshIndex ? freshIndex.sha : undefined
                );
            } else {
                throw indexErr;
            }
        }

        res.json({ success: true, message: 'Account created successfully' });
    } catch (err) {
        console.error('Error creating account:', err);
        res.status(500).json({ success: false, message: 'Failed to create account. Please try again.' });
    }
});

// ── POST /api/verify-account ──────────────────────────────────────────────────
app.post('/api/verify-account', async (req, res) => {
    try {
        const { username: identifier, password } = req.body;

        if (!identifier || !password) {
            return res.status(400).json({ success: false, message: 'Missing credentials' });
        }

        // Resolve identifier (email or username) to the account file key
        let accountKey;
        if (identifier.includes('@')) {
            const emailIndexFile = await getFile('accounts/email-index.json');
            if (!emailIndexFile) {
                return res.status(401).json({ success: false, message: 'Account not found' });
            }
            accountKey = emailIndexFile.content[identifier.toLowerCase()];
            if (!accountKey) {
                return res.status(401).json({ success: false, message: 'Account not found' });
            }
        } else {
            accountKey = identifier.toLowerCase();
        }

        // Fetch account data
        const accountFile = await getFile(`accounts/${accountKey}.json`);
        if (!accountFile) {
            return res.status(401).json({ success: false, message: 'Account not found' });
        }

        // Verify password
        const valid = await bcrypt.compare(password, accountFile.content.password_hash);
        if (!valid) {
            return res.status(401).json({ success: false, message: 'Invalid password' });
        }

        res.json({
            success: true,
            message: 'Login successful',
            user: {
                username: accountFile.content.username,
                email:    accountFile.content.email
            }
        });
    } catch (err) {
        console.error('Error verifying account:', err);
        res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Game.OS Backend running on port ${PORT}`);
    console.log(`   Data repository: ${REPO_OWNER}/${REPO_NAME}`);
});
