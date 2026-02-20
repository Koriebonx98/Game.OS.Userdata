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
User's Browser / C# Launcher
    │
    │  HTTPS  (api.github.com)
    ▼
GitHub REST API  ←────────────────── GitHub Pages (frontend)
    │
    ▼
Private GitHub Repository (Game.OS.Private.Data)
    └── accounts/
        ├── email-index.json
        ├── alice/
        │     ├── profile.json
        │     ├── games.json
        │     ├── achievements.json
        │     └── friends.json
        └── bob/ ...
```

No external server is required. The frontend (hosted on GitHub Pages) calls the
GitHub REST API directly, and all data is stored as JSON files in the private
data repository.

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

## GitHub Token Setup

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. Select scopes:
   - `repo` (Full control of private repositories)
4. Copy token and store securely
5. Add to environment variables or GitHub Secrets

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

### Test the site locally:

```bash
# Serve the frontend with any static file server
python3 -m http.server 8080
# Then open http://localhost:8080

# The site will run in demo mode (localStorage) locally.
# GitHub mode activates automatically after deploying to GitHub Pages
# with the DATA_REPO_TOKEN secret configured.
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

To migrate existing demo mode accounts to the GitHub-backed live site,
re-register them through the sign-up page once the site is deployed to
GitHub Pages with `DATA_REPO_TOKEN` configured.  Demo-mode data is stored only
in browser localStorage and cannot be transferred automatically.

## Monitoring

### GitHub Actions Monitoring:
- Check workflow runs in the **Actions** tab of your GitHub repository
- Review commit history in the data repository to audit all account changes
- Set up email / Slack notifications for failed workflow runs in
  Settings → Notifications

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
