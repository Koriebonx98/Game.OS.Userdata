# GitHub Repository Integration Guide 📦

This guide explains how to integrate the Game.OS Userdata system with a GitHub repository for secure data storage.

## Overview

Instead of using a traditional database, this system can store user account data directly in a private GitHub repository. This approach offers:

- ✅ **Version Control**: Every account creation is a Git commit
- ✅ **Audit Trail**: Complete history of all changes
- ✅ **Free Storage**: No database hosting costs
- ✅ **GitHub Security**: Leverages GitHub's security infrastructure
- ✅ **Easy Backups**: Git-based backup and recovery

## Architecture

```
User Browser (Frontend)
    ↓
GitHub Actions API / Backend Server
    ↓
Private GitHub Repository (Game.OS.Private.Data)
    └── accounts/
        ├── user1.json
        ├── user2.json
        └── user3.json
```

## Implementation Options

### Option 1: GitHub Actions Workflow (Recommended)

Use GitHub Actions to automatically commit user data when triggered via repository dispatch.

**Advantages:**
- No backend server required
- Serverless architecture
- Free with GitHub Actions
- Secure with GitHub tokens

**Setup:**

1. **Create Workflow File** in `.github/workflows/create-account.yml`:

```yaml
name: Create Account

on:
  repository_dispatch:
    types: [create-account]

jobs:
  create-account:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout private data repo
        uses: actions/checkout@v3
        with:
          repository: Koriebonx98/Game.OS.Private.Data
          token: ${{ secrets.DATA_REPO_TOKEN }}
          
      - name: Create account file
        run: |
          mkdir -p accounts
          echo '${{ github.event.client_payload.account_data }}' > accounts/${{ github.event.client_payload.username }}.json
          
      - name: Commit and push
        run: |
          git config user.name "Game OS Bot"
          git config user.email "bot@gameos.com"
          git add accounts/
          git commit -m "Add account: ${{ github.event.client_payload.username }}"
          git push
```

2. **Trigger from Frontend**:

```javascript
async function createAccountGitHub(username, email, password) {
    const response = await fetch(
        'https://api.github.com/repos/Koriebonx98/Game.OS.Userdata/dispatches',
        {
            method: 'POST',
            headers: {
                'Accept': 'application/vnd.github.v3+json',
                'Authorization': 'token YOUR_GITHUB_TOKEN',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                event_type: 'create-account',
                client_payload: {
                    username: username,
                    account_data: JSON.stringify({
                        username: username,
                        email: email,
                        password_hash: await hashPassword(password),
                        created_at: new Date().toISOString()
                    })
                }
            })
        }
    );
    return response.ok;
}
```

### Option 2: Backend Server with GitHub API

Create a simple backend server that manages GitHub repository operations.

**Advantages:**
- More control over logic
- Can implement complex features
- Better error handling
- Rate limiting support

**Setup:**

1. **Create Backend Server** (Node.js example):

```javascript
// backend-server/index.js
const express = require('express');
const { Octokit } = require('@octokit/rest');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const octokit = new Octokit({
    auth: process.env.GITHUB_TOKEN
});

const REPO_OWNER = 'Koriebonx98';
const REPO_NAME = 'Game.OS.Private.Data';

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'Backend server running' });
});

// Create account endpoint
app.post('/api/create-account', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);
        
        // Create account data
        const accountData = {
            username,
            email,
            password_hash: passwordHash,
            created_at: new Date().toISOString()
        };
        
        // Check if account exists
        try {
            await octokit.repos.getContent({
                owner: REPO_OWNER,
                repo: REPO_NAME,
                path: `accounts/${username}.json`
            });
            // If we get here, file exists
            return res.status(400).json({
                success: false,
                message: 'Username already exists'
            });
        } catch (error) {
            // File doesn't exist, continue
        }
        
        // Create file in GitHub
        await octokit.repos.createOrUpdateFileContents({
            owner: REPO_OWNER,
            repo: REPO_NAME,
            path: `accounts/${username}.json`,
            message: `Create account: ${username}`,
            content: Buffer.from(JSON.stringify(accountData, null, 2)).toString('base64'),
            committer: {
                name: 'Game OS Bot',
                email: 'bot@gameos.com'
            }
        });
        
        res.json({ success: true, message: 'Account created successfully' });
    } catch (error) {
        console.error('Error creating account:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create account'
        });
    }
});

// Verify account endpoint
app.post('/api/verify-account', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Get account file from GitHub
        const { data } = await octokit.repos.getContent({
            owner: REPO_OWNER,
            repo: REPO_NAME,
            path: `accounts/${username}.json`
        });
        
        // Decode content
        const accountData = JSON.parse(
            Buffer.from(data.content, 'base64').toString()
        );
        
        // Verify password
        const valid = await bcrypt.compare(password, accountData.password_hash);
        
        if (valid) {
            res.json({
                success: true,
                message: 'Login successful',
                user: {
                    username: accountData.username,
                    email: accountData.email
                }
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Invalid password'
            });
        }
    } catch (error) {
        console.error('Error verifying account:', error);
        res.status(401).json({
            success: false,
            message: 'Account not found'
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

2. **Package.json**:

```json
{
  "name": "gameos-backend",
  "version": "1.0.0",
  "description": "Backend server for Game.OS Userdata",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js"
  },
  "dependencies": {
    "@octokit/rest": "^19.0.0",
    "bcrypt": "^5.1.0",
    "cors": "^2.8.5",
    "express": "^4.18.0",
    "dotenv": "^16.0.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.0"
  }
}
```

3. **Environment Variables** (.env):

```
GITHUB_TOKEN=your_github_personal_access_token
PORT=3000
```

## GitHub Token Setup

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. Select scopes:
   - `repo` (Full control of private repositories)
4. Copy token and store securely
5. Add to environment variables or GitHub Secrets

## Deployment Options

### Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Deploy
railway up
```

### Render

1. Create new Web Service
2. Connect GitHub repository
3. Set build command: `npm install`
4. Set start command: `npm start`
5. Add environment variables

### Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy
vercel
```

## Security Best Practices

1. **Use Environment Variables**: Never commit tokens to Git
2. **Private Repository**: Keep data repository private
3. **HTTPS Only**: Always use HTTPS in production
4. **Rate Limiting**: Implement rate limiting to prevent abuse
5. **Input Validation**: Validate all inputs on backend
6. **Password Hashing**: Always hash passwords with bcrypt
7. **Token Permissions**: Use minimum required GitHub token permissions
8. **CORS Configuration**: Restrict CORS to your domain only

## Data Structure

### Account File Format (accounts/username.json):

```json
{
  "username": "testuser123",
  "email": "testuser@example.com",
  "password_hash": "$2b$10$...",
  "created_at": "2026-02-19T03:40:54.875Z",
  "last_login": "2026-02-19T04:15:30.123Z",
  "profile": {
    "display_name": "Test User",
    "avatar_url": "",
    "bio": ""
  }
}
```

## Testing

### Test Backend Locally:

```bash
# Start backend server
npm start

# Test health endpoint
curl http://localhost:3000/health

# Test account creation
curl -X POST http://localhost:3000/api/create-account \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'

# Test login
curl -X POST http://localhost:3000/api/verify-account \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

## Troubleshooting

### Common Issues:

1. **GitHub API Rate Limit**:
   - Use authenticated requests (increases limit to 5000/hour)
   - Implement caching for frequently accessed data

2. **CORS Errors**:
   - Configure CORS properly in backend
   - Ensure frontend URL is whitelisted

3. **File Conflicts**:
   - Implement proper locking mechanism
   - Use GitHub's conditional requests (If-None-Match)

4. **Large Files**:
   - GitHub has a 100MB file size limit
   - Consider splitting large datasets

## Migration from Demo Mode

To migrate existing demo mode accounts to GitHub:

```javascript
// Migration script
async function migrateDemoAccounts() {
    const accounts = getDemoAccounts();
    
    for (const account of accounts) {
        await fetch(`${API_BASE_URL}/api/create-account`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(account)
        });
    }
    
    console.log(`Migrated ${accounts.length} accounts`);
}
```

## Monitoring

### GitHub Actions Monitoring:
- Check workflow runs in GitHub Actions tab
- Review commit history in data repository
- Set up notifications for failed workflows

### Backend Server Monitoring:
- Use logging service (Logtail, Papertrail)
- Monitor server uptime (UptimeRobot, Pingdom)
- Track API usage and errors

## Future Enhancements

- [ ] Email verification for new accounts
- [ ] Password reset functionality
- [ ] Two-factor authentication (2FA)
- [ ] User profile management
- [ ] Account deletion/suspension
- [ ] Activity logging and audit trail
- [ ] Admin dashboard for account management
- [ ] Bulk operations (import/export)

## Support

For questions or issues with GitHub integration, please:
1. Check the troubleshooting section above
2. Review GitHub API documentation
3. Contact the repository maintainer

---

**Last Updated**: February 19, 2026
