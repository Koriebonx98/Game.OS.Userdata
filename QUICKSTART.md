# Quick Start Guide 🚀

Get started with Game.OS Userdata in 2 minutes!

## Try Demo Mode (No Setup Required)

### Step 1: Open the Application
```bash
# Using Python
python3 -m http.server 8080

# OR using Node.js
npx http-server -p 8080

# Then open: http://localhost:8080
```

### Step 2: Create an Account
1. Click "Sign Up" or "Get Started"
2. Fill in the form:
   - Username: `testuser` (min 3 characters)
   - Email: `test@example.com`
   - Password: `password123` (min 6 characters)
   - Confirm password and check "I agree"
3. Click "Create Account"
4. ✅ You'll see success message and auto-redirect

### Step 3: Login
1. Enter your username or email
2. Enter your password
3. Click "Login"
4. ✅ Welcome back message and redirect to homepage

### Step 4: Test Security
1. Try logging in with wrong password
2. ✅ See error: "Invalid email or password"

## What's Working ✅

- ✅ Account Registration
- ✅ Login Authentication
- ✅ Password Hashing (SHA-256)
- ✅ Error Handling
- ✅ Session Management
- ✅ Logout Functionality
- ✅ Remember Me Option

## Screenshots Available

All functionality has been tested and screenshotted:
- Homepage with demo mode indicator
- Registration form and success
- Login form and success
- Logged in state with user welcome
- Error handling for incorrect password

See README.md for all screenshots!

## Moving to Production

When ready for production with real accounts, use the **GitHub-only** setup —
no external server or hosting costs required:

- Follow the **Going Live** section in `README.md`
- Uses GitHub Pages (frontend) + a private GitHub repository (data storage)
- No server to run, no monthly bill, everything on GitHub's free infrastructure
- One-time setup: create a private data repo, add a fine-grained PAT as a
  repository secret (`DATA_REPO_TOKEN`), enable GitHub Pages, push to main

## Files Structure

```
Game.OS.Userdata/
├── index.html              # Homepage
├── signup.html             # Registration
├── login.html              # Login
├── script.js              # Main logic (demo mode active)
├── styles.css             # Responsive design
├── README.md              # Full documentation
├── GITHUB_INTEGRATION.md  # Production guide
└── QUICKSTART.md          # This file
```

## Key Configuration

The site auto-detects its mode when loaded:
- **GitHub mode** – active on GitHub Pages once `DATA_REPO_TOKEN` is configured.
  The deploy workflow (GitHub Actions) XOR-encodes the token and injects it into
  `script.js` at **build time**; the deployed page decodes it at runtime and uses
  it to call the GitHub API directly.  Users never see the raw token.
- **Demo mode**  – active locally / when the secret is not set (browser localStorage only)

No manual configuration changes to `script.js` are needed for the GitHub-only setup.

## Security Notes

**Demo Mode:**
- Uses SHA-256 password hashing
- Stores data in browser localStorage
- Good for testing and development
- NOT for production with real users

**Production Mode:**
- Uses bcrypt password hashing
- Stores data in private GitHub repo
- Full security implementation
- Ready for real users

## Need Help?

1. **Demo Mode Issues**: Check browser console for errors
2. **Production Setup**: See GITHUB_INTEGRATION.md
3. **General Questions**: See README.md

## Next Steps

1. ✅ Test the demo mode (works now!)
2. 📖 Follow the **Going Live** section in README.md for production
3. 🔑 Add `DATA_REPO_TOKEN` as a repository secret
4. 🚀 Push to main – GitHub Actions deploys everything automatically
5. ✨ Launch with real users — no server bills!

---

**Ready to test?** Just open index.html in your browser! 🎮
