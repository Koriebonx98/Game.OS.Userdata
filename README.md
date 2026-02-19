# Game.OS.Userdata 🎮

**Secure Account Management System for Game OS**

A modern, secure web-based account registration and login system that supports both demo mode (localStorage) and GitHub repository-based storage for user accounts.

## 📋 Table of Contents

- [Features](#features)
- [Demo Mode](#demo-mode)
- [GitHub Repository Integration](#github-repository-integration)
- [Screenshots](#screenshots)
- [Setup Instructions](#setup-instructions)
- [Usage](#usage)
- [Security Considerations](#security-considerations)

## ✨ Features

- **🔐 Secure Registration**: Create accounts with username, email, and password
- **✅ Login Authentication**: Sign in with username or email
- **🎮 Demo Mode**: Works immediately with browser localStorage (no backend required)
- **📦 GitHub Integration**: Optional integration with private GitHub repository for data storage
- **🔒 Password Validation**: Enforces minimum password requirements
- **⚡ Real-time Feedback**: Instant validation and user-friendly error messages
- **📱 Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices
- **🌐 Session Management**: Remember me functionality and logout support

## 🎮 Demo Mode

The system includes a built-in demo mode that uses browser localStorage to simulate a backend. This allows you to test and use the account system immediately without any server setup.

### Demo Mode Features:
- ✓ Accounts stored in browser localStorage
- ✓ Full registration and login functionality
- ✓ Password validation and security checks
- ✓ Duplicate username/email detection
- ✓ Session management with "Remember me" option

### Testing Demo Mode:

The demo mode is **currently active** and ready to use. Simply:
1. Open `index.html` in your web browser
2. Click "Sign Up" to create an account
3. Fill in your details and submit
4. Login with your credentials

## 📦 GitHub Repository Integration

For production use, this system integrates with a private GitHub repository ([Game.OS.Private.Data](https://github.com/Koriebonx98/Game.OS.Private.Data)) to store user account data securely.

### How It Works:

1. **Account Creation**: When a user registers, the system triggers a GitHub Action
2. **Data Storage**: User data is committed to a private repository as JSON files
3. **Authentication**: Login requests verify credentials against stored data
4. **Security**: All data stored in a private repository with restricted access

### Integration Steps:

1. **Set up Private Data Repository**:
   ```bash
   # Clone the private data repository
   git clone https://github.com/Koriebonx98/Game.OS.Private.Data
   ```

2. **Configure Backend URL**:
   Update `script.js` with your backend URL:
   ```javascript
   const API_BASE_URL = 'https://your-backend-url.com';
   ```

3. **Deploy Backend Server**:
   - The backend server should be deployed from `Game.OS.Private.Data/backend-server`
   - Configure environment variables for GitHub token and repository access
   - Deploy to a hosting platform (Railway, Render, Vercel, etc.)

4. **Test Connection**:
   - Refresh the page
   - The connection status should show "✅ Connected to backend"

## 📸 Screenshots

### 1. Homepage
![Homepage](https://github.com/user-attachments/assets/90137b0e-72e4-4579-b268-3aaade8e8c58)
*Welcome page with demo mode active*

### 2. Account Registration
![Signup Page](https://github.com/user-attachments/assets/0effd3c6-63c5-4976-8750-6cb78260284b)
*User registration form*

![Signup Filled](https://github.com/user-attachments/assets/acbe478e-0918-44f5-addb-abe53e4eaf4e)
*Registration form with test data*

![Signup Success](https://github.com/user-attachments/assets/b018846b-9125-455e-8bd0-f259b6b903d8)
*Successful account creation*

### 3. Login Process
![Login Page](https://github.com/user-attachments/assets/f199b5b6-e880-4496-bc8e-ff1c5a07652f)
*Sign in page*

![Login Success](https://github.com/user-attachments/assets/81714511-3e1c-4c28-813e-351dbd351d85)
*Successful login confirmation*

![Logged In](https://github.com/user-attachments/assets/f085f1b6-d4a1-4c74-b0c3-432a427ebbc1)
*Homepage showing logged-in user*

### 4. Security - Incorrect Password
![Wrong Password](https://github.com/user-attachments/assets/90e6d31b-3328-4e23-983a-9f23ec78cf5f)
*Login attempt with incorrect password*

![Error Message](https://github.com/user-attachments/assets/8158e6dd-d029-41c5-8547-a9647ea58bb3)
*Error message displayed for invalid credentials*

## 🚀 Setup Instructions

### Local Development:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Koriebonx98/Game.OS.Userdata.git
   cd Game.OS.Userdata
   ```

2. **Start a local web server**:
   ```bash
   # Using Python
   python3 -m http.server 8080
   
   # OR using Node.js
   npx http-server -p 8080
   ```

3. **Open in browser**:
   ```
   http://localhost:8080
   ```

4. **Test the system**:
   - Create a test account
   - Login with your credentials
   - Test incorrect password handling
   - Verify logout functionality

### Production Deployment:

1. **GitHub Pages** (Recommended for frontend):
   - Enable GitHub Pages in repository settings
   - Select main branch and root directory
   - Access at: `https://koriebonx98.github.io/Game.OS.Userdata/`

2. **Configure Backend**:
   - Deploy backend from Game.OS.Private.Data repository
   - Update `API_BASE_URL` in `script.js`
   - Commit and push changes

## 📖 Usage

### Creating an Account:

1. Navigate to the homepage
2. Click "Sign Up" or "Get Started"
3. Fill in the registration form:
   - Username (minimum 3 characters)
   - Email address
   - Password (minimum 6 characters)
   - Confirm password
4. Agree to Terms and Conditions
5. Click "Create Account"
6. Wait for confirmation and automatic redirect to login

### Logging In:

1. Navigate to the login page
2. Enter your username or email
3. Enter your password
4. Optional: Check "Remember me" for persistent session
5. Click "Login"
6. You'll be redirected to the homepage upon success

### Account Management:

- **View Account**: Your username is displayed on the homepage when logged in
- **Logout**: Click the "Logout" button to end your session
- **Session Persistence**: Use "Remember me" during login to stay logged in

## 🔒 Security Considerations

### Current Implementation:

- ✅ Client-side validation (username length, email format, password strength)
- ✅ Password confirmation matching
- ✅ Duplicate username/email detection
- ✅ Session management with localStorage/sessionStorage
- ⚠️ **Demo mode stores passwords in plain text** (suitable for testing only)

### For Production:

When integrating with the GitHub repository backend:

1. **Password Hashing**: Passwords should be hashed using bcrypt or similar
2. **HTTPS Only**: Always use HTTPS in production
3. **Token-based Auth**: Implement JWT or similar for session management
4. **Rate Limiting**: Add rate limiting to prevent brute-force attacks
5. **Input Sanitization**: Validate and sanitize all user inputs on the backend
6. **Private Repository**: Ensure the data repository remains private
7. **Access Control**: Restrict GitHub token permissions to minimum required

### Demo Mode Security Notice:

⚠️ **Important**: Demo mode is for testing and demonstration purposes only. It stores passwords in plain text in localStorage. **Do NOT use demo mode with real passwords or in production environments.**

## 🛠️ Technical Stack

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Styling**: Custom CSS with responsive design
- **Storage**: Browser localStorage (demo mode) / GitHub Repository (production)
- **Backend** (optional): Node.js with GitHub API integration
- **Automation**: GitHub Actions for data management

## 📝 Files Structure

```
Game.OS.Userdata/
├── index.html          # Homepage
├── signup.html         # Registration page
├── login.html          # Login page
├── script.js           # Main JavaScript logic
├── styles.css          # Styling and responsive design
└── README.md           # This file
```

## 🤝 Contributing

This is a private repository. For contributions or issues, please contact the repository owner.

## 📄 License

© 2026 Game OS Userdata. All rights reserved.

## 📞 Support

For support or questions, please refer to the main Game OS documentation or contact the development team.

---

**Powered by GitHub Actions & Node.js** 
