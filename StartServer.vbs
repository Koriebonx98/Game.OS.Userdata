' =============================================================================
' StartServer.vbs – Game.OS Local Backend Launcher
'
' What this script does:
'   1. Locates the backend folder next to this script.
'   2. Checks that Node.js is installed (node.exe on PATH).
'   3. Installs npm dependencies if node_modules is missing.
'   4. Starts the backend server in a new elevated Command Prompt window
'      (running as Administrator so the server can bind to port 3000).
'   5. Opens launch-local.html in the default browser, which connects the
'      website to the local backend and exits demo mode automatically.
'
' Prerequisites:
'   • Node.js v18+ installed  (https://nodejs.org)
'   • backend\.env file populated (copy backend\.env.example and fill in
'     your GitHub token and repository details).
'
' Admin account:
'   The backend creates the Admin.GameOS account automatically on first start.
'   Username : Admin.GameOS
'   Password : GameOS2026   (change this via Account Settings after login)
'
' Usage:
'   Double-click StartServer.vbs.  Windows may ask for admin permission —
'   click Yes to allow the server to bind to port 3000.
' =============================================================================

Option Explicit

Dim oShell, oFSO
Dim scriptDir, backendDir, envFile, launchHtml
Dim nodeCheck

Set oShell = CreateObject("WScript.Shell")
Set oFSO   = CreateObject("Scripting.FileSystemObject")

' ── Resolve paths ──────────────────────────────────────────────────────────────
scriptDir  = oFSO.GetParentFolderName(WScript.ScriptFullName)
backendDir = oFSO.BuildPath(scriptDir, "backend")
envFile    = oFSO.BuildPath(backendDir, ".env")
launchHtml = oFSO.BuildPath(scriptDir, "launch-local.html")

' ── Check backend folder ───────────────────────────────────────────────────────
If Not oFSO.FolderExists(backendDir) Then
    MsgBox "Could not find the backend folder:" & vbCrLf & backendDir & vbCrLf & vbCrLf & _
           "Make sure this script is in the Game.OS.Userdata root directory.", _
           vbCritical, "Game.OS – Backend Folder Missing"
    WScript.Quit 1
End If

' ── Check .env file ────────────────────────────────────────────────────────────
If Not oFSO.FileExists(envFile) Then
    Dim envExample
    envExample = oFSO.BuildPath(backendDir, ".env.example")
    Dim envMsg
    envMsg = "backend\.env not found." & vbCrLf & vbCrLf & _
             "To enable real accounts:" & vbCrLf & _
             "  1. Copy  backend\.env.example  to  backend\.env" & vbCrLf & _
             "  2. Fill in GITHUB_TOKEN, REPO_OWNER, REPO_NAME" & vbCrLf & _
             "     (and the other required values)." & vbCrLf & vbCrLf & _
             "The site will still start but may fall back to demo mode" & vbCrLf & _
             "without a valid GitHub token." & vbCrLf & vbCrLf & _
             "Continue anyway?"
    Dim envAns
    envAns = MsgBox(envMsg, vbExclamation + vbYesNo, "Game.OS – .env File Missing")
    If envAns = vbNo Then WScript.Quit 0
End If

' ── Check Node.js is installed ─────────────────────────────────────────────────
nodeCheck = oShell.Run("cmd /c node --version >nul 2>&1", 0, True)
If nodeCheck <> 0 Then
    MsgBox "Node.js was not found on your PATH." & vbCrLf & vbCrLf & _
           "Please install Node.js v18 or later from:" & vbCrLf & _
           "  https://nodejs.org" & vbCrLf & vbCrLf & _
           "Then run this script again.", _
           vbCritical, "Game.OS – Node.js Not Found"
    WScript.Quit 1
End If

' ── Install npm dependencies if node_modules is missing ────────────────────────
Dim nodeModulesDir
nodeModulesDir = oFSO.BuildPath(backendDir, "node_modules")
If Not oFSO.FolderExists(nodeModulesDir) Then
    Dim installMsg
    installMsg = MsgBox("npm dependencies are not installed." & vbCrLf & vbCrLf & _
                        "This only needs to happen once." & vbCrLf & _
                        "Install now? (This may take a minute.)", _
                        vbQuestion + vbYesNo, "Game.OS – Install Dependencies")
    If installMsg = vbNo Then WScript.Quit 0

    ' Run npm install in the backend directory (visible window, wait for completion)
    Dim installResult
    installResult = oShell.Run("cmd /c cd /d """ & backendDir & """ && npm install", 1, True)
    If installResult <> 0 Then
        MsgBox "npm install failed (exit code " & installResult & ")." & vbCrLf & vbCrLf & _
               "Check the Command Prompt window for error details." & vbCrLf & _
               "Common causes: no internet connection, Node.js not in PATH.", _
               vbCritical, "Game.OS – Dependency Installation Failed"
        WScript.Quit 1
    End If
End If

' ── Start the backend server in a new elevated Command Prompt ──────────────────
' The server window stays open so logs are visible.  The /K flag keeps the window
' alive even if the server crashes, so error messages can be read.
'
' Use Chr(34) for embedded double-quotes inside the argument string so VBScript
' string delimiters do not interfere with the cmd /K command.
Dim q, serverArgs
q = Chr(34)
serverArgs = "/K " & q & _
             "cd /d " & q & backendDir & q & _
             " && echo." & _
             " && echo  ==============================================" & _
             " && echo   Game.OS Backend Server" & _
             " && echo   Admin account : Admin.GameOS" & _
             " && echo   Admin password: GameOS2026" & _
             " && echo   (change via Account Settings after login)" & _
             " && echo  ==============================================" & _
             " && echo." & _
             " && npm start" & q

' Use ShellExecute with "runas" verb to request administrator elevation.
' The UAC prompt will appear asking for permission – click Yes.
oShell.ShellExecute "cmd", serverArgs, backendDir, "runas", 1

' ── Wait a moment for the server to start before opening the browser ───────────
WScript.Sleep 3000

' ── Open launch-local.html in the default browser ─────────────────────────────
If oFSO.FileExists(launchHtml) Then
    oShell.Run "explorer """ & launchHtml & """"
Else
    MsgBox "launch-local.html was not found next to this script." & vbCrLf & vbCrLf & _
           "Open launch-local.html manually from the Game.OS.Userdata folder.", _
           vbInformation, "Game.OS – Browser Launch"
End If

' ── Done ───────────────────────────────────────────────────────────────────────
MsgBox "Game.OS Backend is starting!" & vbCrLf & vbCrLf & _
       "A new Command Prompt window has been opened for the server." & vbCrLf & _
       "Your browser will open launch-local.html to connect the site." & vbCrLf & vbCrLf & _
       "Admin credentials:" & vbCrLf & _
       "  Username : Admin.GameOS" & vbCrLf & _
       "  Password : GameOS2026" & vbCrLf & vbCrLf & _
       "Change the admin password after your first login via Account Settings.", _
       vbInformation, "Game.OS – Server Started"

Set oShell = Nothing
Set oFSO   = Nothing
