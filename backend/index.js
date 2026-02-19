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
        const existingAccount = await getFile(`accounts/${username.toLowerCase()}/profile.json`);
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

        // Write account profile file (one folder per user)
        const accountData = {
            username,
            email,
            password_hash: passwordHash,
            created_at: new Date().toISOString()
        };
        await putFile(
            `accounts/${username.toLowerCase()}/profile.json`,
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
        const accountFile = await getFile(`accounts/${accountKey}/profile.json`);
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

// ── POST /api/update-account ──────────────────────────────────────────────────
app.post('/api/update-account', async (req, res) => {
    try {
        const { username, currentPassword, newEmail, newPassword } = req.body;

        if (!username || !currentPassword) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }

        const accountFile = await getFile(`accounts/${username.toLowerCase()}/profile.json`);
        if (!accountFile) {
            return res.status(404).json({ success: false, message: 'Account not found' });
        }

        const account = accountFile.content;
        const valid = await bcrypt.compare(currentPassword, account.password_hash);
        if (!valid) {
            return res.status(401).json({ success: false, message: 'Current password is incorrect' });
        }

        let updated = { ...account };

        if (newEmail && newEmail.toLowerCase() !== account.email.toLowerCase()) {
            if (!isValidEmail(newEmail)) {
                return res.status(400).json({ success: false, message: 'Invalid email address' });
            }
            const emailLower = newEmail.toLowerCase();
            const indexFile  = await getFile('accounts/email-index.json');
            const emailMap   = indexFile ? { ...indexFile.content } : {};
            if (emailMap[emailLower] && emailMap[emailLower] !== username.toLowerCase()) {
                return res.status(400).json({ success: false, message: 'Email already in use' });
            }
            delete emailMap[account.email.toLowerCase()];
            emailMap[emailLower] = username.toLowerCase();
            await putFile(
                'accounts/email-index.json',
                emailMap,
                `Update email index for: ${username}`,
                indexFile ? indexFile.sha : undefined
            );
            updated.email = newEmail;
        }

        if (newPassword) {
            if (newPassword.length < 6) {
                return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
            }
            updated.password_hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        }

        await putFile(
            `accounts/${username.toLowerCase()}/profile.json`,
            updated,
            `Update account: ${username}`,
            accountFile.sha
        );

        res.json({ success: true, message: 'Account updated successfully', email: updated.email });
    } catch (err) {
        console.error('Error updating account:', err);
        res.status(500).json({ success: false, message: 'Failed to update account. Please try again.' });
    }
});

// ── GET /api/check-user ───────────────────────────────────────────────────────
app.get('/api/check-user', async (req, res) => {
    try {
        const { username } = req.query;
        if (!username || !sanitiseUsername(username)) {
            return res.status(400).json({ success: false, message: 'Invalid username' });
        }
        const accountFile = await getFile(`accounts/${username.toLowerCase()}/profile.json`);
        if (!accountFile) {
            return res.json({ exists: false });
        }
        res.json({ exists: true, username: accountFile.content.username });
    } catch (err) {
        console.error('Error checking user:', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ── POST /api/add-friend ──────────────────────────────────────────────────────
app.post('/api/add-friend', async (req, res) => {
    try {
        const { username, friendUsername } = req.body;

        if (!username || !friendUsername) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }
        if (username.toLowerCase() === friendUsername.toLowerCase()) {
            return res.status(400).json({ success: false, message: 'You cannot add yourself as a friend' });
        }

        // Verify both users exist
        const userFile   = await getFile(`accounts/${username.toLowerCase()}/profile.json`);
        if (!userFile) {
            return res.status(404).json({ success: false, message: 'Your account was not found' });
        }
        const friendFile = await getFile(`accounts/${friendUsername.toLowerCase()}/profile.json`);
        if (!friendFile) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Read or initialise friends list
        const friendsPath  = `accounts/${username.toLowerCase()}/friends.json`;
        const friendsFile  = await getFile(friendsPath);
        const friends      = friendsFile ? friendsFile.content : [];

        if (friends.some(f => f.toLowerCase() === friendUsername.toLowerCase())) {
            return res.status(400).json({ success: false, message: 'Already friends with this user' });
        }

        friends.push(friendFile.content.username);
        await putFile(
            friendsPath,
            friends,
            `Add friend ${friendUsername} for: ${username}`,
            friendsFile ? friendsFile.sha : undefined
        );

        res.json({ success: true, message: `${friendFile.content.username} added as a friend` });
    } catch (err) {
        console.error('Error adding friend:', err);
        res.status(500).json({ success: false, message: 'Failed to add friend. Please try again.' });
    }
});

// ── GET /api/get-friends ──────────────────────────────────────────────────────
app.get('/api/get-friends', async (req, res) => {
    try {
        const { username } = req.query;
        if (!username || !sanitiseUsername(username)) {
            return res.status(400).json({ success: false, message: 'Invalid username' });
        }
        const friendsFile = await getFile(`accounts/${username.toLowerCase()}/friends.json`);
        res.json({ success: true, friends: friendsFile ? friendsFile.content : [] });
    } catch (err) {
        console.error('Error getting friends:', err);
        res.status(500).json({ success: false, message: 'Failed to get friends list.' });
    }
});

// ── POST /api/remove-friend ───────────────────────────────────────────────────
app.post('/api/remove-friend', async (req, res) => {
    try {
        const { username, friendUsername } = req.body;

        if (!username || !friendUsername) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }

        const friendsPath = `accounts/${username.toLowerCase()}/friends.json`;
        const friendsFile = await getFile(friendsPath);
        if (!friendsFile) {
            return res.status(404).json({ success: false, message: 'Friends list not found' });
        }

        const updated = friendsFile.content.filter(
            f => f.toLowerCase() !== friendUsername.toLowerCase()
        );

        await putFile(
            friendsPath,
            updated,
            `Remove friend ${friendUsername} for: ${username}`,
            friendsFile.sha
        );

        res.json({ success: true, message: 'Friend removed' });
    } catch (err) {
        console.error('Error removing friend:', err);
        res.status(500).json({ success: false, message: 'Failed to remove friend. Please try again.' });
    }
});

// ── POST /api/reset-all-accounts ─────────────────────────────────────────────
app.post('/api/reset-all-accounts', async (req, res) => {
    try {
        const { adminKey } = req.body;
        if (!adminKey || !process.env.ADMIN_KEY || adminKey !== process.env.ADMIN_KEY) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        // List all items in the accounts directory
        let items;
        try {
            const { data } = await octokit.repos.getContent({
                owner: REPO_OWNER,
                repo:  REPO_NAME,
                path:  'accounts'
            });
            items = Array.isArray(data) ? data : [data];
        } catch (err) {
            if (err.status === 404) {
                return res.json({ success: true, message: 'No accounts to remove' });
            }
            throw err;
        }

        const committer = { name: 'Game OS Bot', email: 'bot@gameos.com' };

        // Delete every file; recurse one level into user sub-folders
        for (const item of items) {
            if (item.type === 'dir') {
                try {
                    const { data: files } = await octokit.repos.getContent({
                        owner: REPO_OWNER,
                        repo:  REPO_NAME,
                        path:  item.path
                    });
                    for (const file of (Array.isArray(files) ? files : [files])) {
                        await octokit.repos.deleteFile({
                            owner: REPO_OWNER,
                            repo:  REPO_NAME,
                            path:  file.path,
                            message: `Reset: delete ${file.path}`,
                            sha:   file.sha,
                            committer
                        });
                    }
                } catch (e) {
                    if (e.status !== 404) throw e;
                }
            } else {
                await octokit.repos.deleteFile({
                    owner: REPO_OWNER,
                    repo:  REPO_NAME,
                    path:  item.path,
                    message: `Reset: delete ${item.path}`,
                    sha:   item.sha,
                    committer
                });
            }
        }

        res.json({ success: true, message: 'All accounts removed successfully' });
    } catch (err) {
        console.error('Error resetting accounts:', err);
        res.status(500).json({ success: false, message: 'Failed to reset accounts. Please try again.' });
    }
});

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Game.OS Backend running on port ${PORT}`);
    console.log(`   Data repository: ${REPO_OWNER}/${REPO_NAME}`);
});
