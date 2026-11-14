// Digital Abyss - Interactive Mystery Game
// Main Game Logic

class DigitalAbyssGame {
    constructor() {
        this.currentScenario = null;
        this.gameStartTime = null;
        this.gameDuration = 60 * 60 * 1000; // 60 minutes in milliseconds
        this.timerInterval = null;
        this.currentApp = null;
        this.currentView = 'home';
        this.cluesFound = [];
        this.soundEnabled = true;
        
        // Lives system
        this.lives = 3;
        this.maxLives = 3;
        this.wrongAttempts = 0;
        
        // Time-based mechanics
        this.timeBasedCluesRevealed = {
            fiveMinutes: false,
            tenMinutes: false,
            fifteenMinutes: false,
            twentyMinutes: false
        };
        this.dynamicMessages = [];
        
        // Wrong answer relocation system
        this.wrongAnswerHintsAdded = false;
        this.narrativeShifted = false;
        
        // Multi-stage puzzle tracking
        this.currentStage = 1;
        this.completedStages = [];
        
        // Clue engagement tracking system
        this.viewedMessages = new Set();
        this.viewedEmails = new Set();
        this.viewedNotes = new Set();
        this.viewedVoicemails = new Set();
        
        // Constants for filtering dropdown options
        this.EXCLUDED_ENDINGS = ['gameover', 'timeout'];
        this.EXCLUDED_CONTACTS = ['Unknown', 'Anonymous'];
        
        this.init();
    }
    
    async init() {
        console.log('Digital Abyss game initializing...');
        
        // Show loading screen
        this.showLoading();
        
        // Game OS exclusive: requires a signed-in account that owns the game
        const session = await GameOSSDK.boot();
        if (!session) {
            const loading = document.getElementById('loading-screen');
            if (loading) loading.remove();
            return;
        }

        // Load scenario data
        await this.loadScenarios();
        this.checkForNewLevels();
        window.addEventListener('online', () => this.checkForNewLevels());
        window.addEventListener('da-reconnected', () => this.showNotification('☁️ Back online – progress synced'));
        
        // Select random scenario
        this.selectRandomScenario();
        this.savedRun = this.findSavedRun();
        
        // Hide loading screen and show intro
        this.hideLoading();
        
        // Show intro screen instead of starting game immediately
        this.showIntro();
        
        console.log('Game ready! Scenario:', this.currentScenario.name);
    }
    
    showLoading() {
        const loadingHTML = `
            <div class="loading-screen" id="loading-screen">
                <div class="loading-spinner"></div>
                <div class="loading-text">Loading Elena's Phone...</div>
            </div>
        `;
        document.getElementById('screen').insertAdjacentHTML('afterbegin', loadingHTML);
    }
    
    hideLoading() {
        setTimeout(() => {
            const loadingScreen = document.getElementById('loading-screen');
            if (loadingScreen) {
                loadingScreen.style.opacity = '0';
                setTimeout(() => loadingScreen.remove(), 300);
            }
        }, 1500);
    }
    
    showIntro() {
        const introHTML = `
            <div class="intro-screen" id="intro-screen">
                <div class="intro-content">
                    <div class="intro-icon">📱</div>
                    <h1 class="intro-title">Digital Abyss</h1>
                    <div class="intro-subtitle">A Mystery Investigation Game</div>
                    
                    <div class="intro-story">
                        <h2>The Situation</h2>
                        <p><strong>Elena Martinez</strong> has vanished without a trace. Her phone was found abandoned at the scene, still unlocked.</p>
                        
                        <h2>Your Mission</h2>
                        <p>You have <strong>60 minutes</strong> to explore Elena's phone, piece together the clues, and discover what happened to her before the trail goes cold.</p>
                        
                        <h2>How to Play</h2>
                        <ul>
                            <li>🔍 Explore the apps: Messages, Email, Phone, and Notes</li>
                            <li>🧩 Find and connect clues hidden throughout</li>
                            <li>💡 Solve the mystery by submitting your solution</li>
                            <li>⏱️ Beat the clock - you only have 60 minutes!</li>
                        </ul>
                        
                        <p class="intro-warning">⚠️ Time is of the essence. Every second counts.</p>
                    </div>
                    
                    <div class="intro-account">👤 ${this.escapeHtml(GameOSSDK.user.username)} · ${GameOSSDK.cloud ? '☁️ cloud save on' : 'progress saved on this device'}</div>
                    ${this.savedRun ? '<button class="start-button" id="continue-game-button">Continue Saved Case</button>' : ''}
                    <button class="start-button${this.savedRun ? ' secondary' : ''}" id="start-game-button">${this.savedRun ? 'Start New Investigation' : 'Start Investigation'}</button>
                    <button class="start-button secondary" id="achievements-button">🏆 Achievements</button>
                    <button class="start-button secondary" id="quit-game-button">⏻ Quit to Game OS</button>
                </div>
            </div>
        `;
        
        document.getElementById('screen').insertAdjacentHTML('afterbegin', introHTML);
        
        // Setup start button listener
        document.getElementById('start-game-button').addEventListener('click', () => {
            this.startGame();
        });
        const continueButton = document.getElementById('continue-game-button');
        if (continueButton) continueButton.addEventListener('click', () => {
            this.restoreRun(this.savedRun);
            this.startGame();
        });
        document.getElementById('quit-game-button').addEventListener('click', () => this.exitGame());
        document.getElementById('achievements-button').addEventListener('click', () => this.showAchievementsScreen());
    }
    
    startGame() {
        // Remove intro screen
        const introScreen = document.getElementById('intro-screen');
        if (introScreen) {
            introScreen.style.opacity = '0';
            setTimeout(() => introScreen.remove(), 300);
        }
        
        // Setup game UI
        this.setupUI();
        
        // Start timer
        this.startTimer();
        GameOSSDK.setRunning(true);
        if (!this.resumeElapsed) GameOSSDK.report('start', {});
        this.persistRun();
        
        // Play startup sound
        this.playSound('startup');
    }
    
    async loadScenarios() {
        try {
            const response = await fetch('scenarios/scenario-data.json');
            const text = await response.text();
            this.scenarioFingerprint = text.length + ':' + text.slice(-64);
            this.scenarios = JSON.parse(text).scenarios;
        } catch (error) {
            console.error('Error loading scenarios:', error);
            // Fallback to embedded scenario if file not found
            this.scenarios = this.getDefaultScenarios();
        }
    }
    
    // The service worker serves cached levels offline; when online, look for newer ones.
    async checkForNewLevels() {
        if (!navigator.onLine || !this.scenarioFingerprint) return;
        try {
            const text = await (await fetch('scenarios/scenario-data.json', { cache: 'no-store' })).text();
            if (text.length + ':' + text.slice(-64) !== this.scenarioFingerprint) {
                this.scenarioFingerprint = text.length + ':' + text.slice(-64);
                this.showNotification('🆕 New levels available – reload the game to play them');
            }
        } catch (_) {}
    }

    getDefaultScenarios() {
        // Fallback scenarios embedded in code
        return [
            {
                id: 1,
                name: "The Art Gallery Mystery",
                solution: "warehouse",
                messages: [
                    {
                        id: 1,
                        contact: "Marcus Chen",
                        avatar: "M",
                        messages: [
                            { type: "received", text: "Hey! Are you coming to the gallery opening tonight?", time: "6:45 PM" },
                            { type: "sent", text: "Wouldn't miss it! What time?", time: "6:47 PM" },
                            { type: "received", text: "8 PM sharp. Address is at the warehouse on 5th and Main.", time: "6:50 PM" }
                        ],
                        unread: false
                    }
                ],
                emails: [
                    {
                        id: 1,
                        sender: "Gallery Nouveau",
                        subject: "Tonight's Event Location",
                        date: "Today, 7:30 PM",
                        body: "The venue has changed to our warehouse location at 312 5th Street. See you tonight!",
                        unread: true
                    }
                ],
                calls: [
                    { id: 1, name: "Marcus Chen", type: "outgoing", time: "7:15 PM", duration: "3m 42s" }
                ],
                voicemails: [],
                notes: [
                    {
                        id: 1,
                        title: "Tonight's Plan",
                        content: "Meet at warehouse - 5th and Main. Check for evidence.",
                        date: "Today"
                    }
                ],
                endings: {
                    warehouse: {
                        title: "Mystery Solved!",
                        message: "You found Elena at the warehouse! Great detective work!",
                        success: true
                    },
                    timeout: {
                        title: "Time's Up",
                        message: "You ran out of time. The mystery remains unsolved.",
                        success: false
                    }
                }
            }
        ];
    }
    
    selectRandomScenario() {
        const randomIndex = Math.floor(Math.random() * this.scenarios.length);
        this.setScenario(this.scenarios[randomIndex]);
    }

    setScenario(scenario) {
        this.currentScenario = scenario;
        const ids = list => (list || []).map(item => item.id);
        this.baseIds = {
            messages: ids(scenario.messages), emails: ids(scenario.emails),
            voicemails: ids(scenario.voicemails), notes: ids(scenario.notes)
        };
    }

    // ── Game OS: cloud save, achievements ──
    findSavedRun() {
        const run = GameOSSDK.getRun();
        if (!run || !this.scenarios.some(s => s.id === run.scenarioId)) return null;
        return run;
    }

    snapshotRun() {
        return {
            scenarioId: this.currentScenario.id,
            elapsedMs: Date.now() - this.gameStartTime,
            lives: this.lives,
            wrongAttempts: this.wrongAttempts,
            narrativeShifted: this.narrativeShifted,
            viewed: {
                messages: [...this.viewedMessages], emails: [...this.viewedEmails],
                notes: [...this.viewedNotes], voicemails: [...this.viewedVoicemails]
            }
        };
    }

    persistRun() {
        if (this.gameStartTime && !this.finished) GameOSSDK.saveRun(this.snapshotRun());
    }

    restoreRun(run) {
        this.setScenario(this.scenarios.find(s => s.id === run.scenarioId));
        this.lives = Math.max(1, Math.min(this.maxLives, run.lives));
        this.wrongAttempts = run.wrongAttempts || 0;
        this.resumeElapsed = Math.max(0, run.elapsedMs || 0);
        const v = run.viewed || {};
        this.viewedMessages = new Set(v.messages); this.viewedEmails = new Set(v.emails);
        this.viewedNotes = new Set(v.notes); this.viewedVoicemails = new Set(v.voicemails);
        if (run.narrativeShifted) {
            this.narrativeShifted = true;
            (this.getRelocationHints().messages || []).forEach(m => this.currentScenario.messages.push(m));
        }
    }

    allCluesViewed() {
        const b = this.baseIds;
        return b.messages.every(id => this.viewedMessages.has(id)) && b.emails.every(id => this.viewedEmails.has(id)) &&
               b.voicemails.every(id => this.viewedVoicemails.has(id)) && b.notes.every(id => this.viewedNotes.has(id));
    }

    achievementContext(extra) {
        const elapsedMs = Date.now() - this.gameStartTime;
        return Object.assign({
            scenarioId: this.currentScenario.id, wrongAttempts: this.wrongAttempts, lives: this.lives,
            elapsedMs, remainingMs: this.gameDuration - elapsedMs, allViewed: this.allCluesViewed()
        }, extra);
    }

    showAchievementToast(a) {
        const toast = document.createElement('div');
        toast.className = 'achievement-toast';
        toast.innerHTML = `<div class="achievement-toast-icon">🏆</div><div><strong>Achievement unlocked</strong><div>${this.escapeHtml(a.name)}</div><small>${this.escapeHtml(a.description)}</small></div>`;
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 20);
        setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 400); }, 5000);
    }

    showAchievementsScreen() {
        const items = GameOSSDK.list();
        const done = items.filter(a => a.unlockedAt).length;
        const rows = items.map(a => `
            <div class="ach-row ${a.unlockedAt ? '' : 'locked'}">
                <div class="ach-icon">${a.unlockedAt ? '🏆' : (a.hidden ? '❓' : '🔒')}</div>
                <div><strong>${this.escapeHtml(a.name)}</strong><small>${this.escapeHtml(a.description)}</small></div>
            </div>`).join('');
        const panel = document.createElement('div');
        panel.className = 'ach-screen';
        panel.innerHTML = `<div class="ach-panel"><h2>🏆 Achievements <small>${done} / ${items.length}</small></h2>${rows}<button class="game-over-button" id="ach-close">Close</button></div>`;
        document.getElementById('screen').appendChild(panel);
        panel.querySelector('#ach-close').onclick = () => panel.remove();
    }
    
    setupUI() {
        const screen = document.getElementById('screen');
        
        screen.innerHTML = `
            <!-- Status Bar -->
            <div id="status-bar">
                <div class="left">
                    <span id="current-time">12:00</span>
                </div>
                <div class="center">
                    <span id="lives-display">${'❤️'.repeat(this.lives)}${'🖤'.repeat(this.maxLives - this.lives)}</span>
                </div>
                <div class="right">
                    <span id="timer-display">60:00</span>
                    <span>🔋 100%</span>
                    <button id="exit-game-btn" type="button" title="Exit game" aria-label="Exit game">⏻</button>
                </div>
            </div>
            
            <!-- Home Screen -->
            <div id="home-screen">
                <div class="wallpaper"></div>
                
                <!-- Clock Widget -->
                <div style="text-align: center; padding: 40px 0; position: relative; z-index: 1;">
                    <div style="color: white; font-size: 72px; font-weight: 200;">${this.getCurrentTime()}</div>
                    <div style="color: rgba(255,255,255,0.7); font-size: 18px; margin-top: 8px;">${this.getCurrentDate()}</div>
                </div>
                
                <!-- App Grid -->
                <div id="app-grid">
                    <div class="app-icon" data-app="messages">
                        <div class="app-icon-image messages">
                            💬
                            ${this.getUnreadCount('messages') > 0 ? `<div class="badge">${this.getUnreadCount('messages')}</div>` : ''}
                        </div>
                        <div class="app-icon-label">Messages</div>
                    </div>
                    
                    <div class="app-icon" data-app="email">
                        <div class="app-icon-image email">
                            ✉️
                            ${this.getUnreadCount('email') > 0 ? `<div class="badge">${this.getUnreadCount('email')}</div>` : ''}
                        </div>
                        <div class="app-icon-label">Email</div>
                    </div>
                    
                    <div class="app-icon" data-app="phone">
                        <div class="app-icon-image phone">
                            📞
                            ${this.getUnreadCount('phone') > 0 ? `<div class="badge">${this.getUnreadCount('phone')}</div>` : ''}
                        </div>
                        <div class="app-icon-label">Phone</div>
                    </div>
                    
                    <div class="app-icon" data-app="notes">
                        <div class="app-icon-image notes">
                            📝
                        </div>
                        <div class="app-icon-label">Notes</div>
                    </div>
                </div>
                
                <!-- Solve Mystery Button -->
                <div style="position: absolute; bottom: 80px; left: 50%; transform: translateX(-50%); width: 90%; z-index: 5;">
                    <button id="solve-mystery-button" class="solve-mystery-button">
                        🔍 Solve Mystery
                    </button>
                </div>
                
                <!-- Home Button -->
                <div id="home-button"></div>
            </div>
            
            <!-- App Screens Container -->
            <div id="app-screens"></div>
            
            <!-- Solution Modal -->
            <div id="solution-modal" class="solution-modal">
                <div class="solution-modal-content">
                    <h2>Solve the Mystery</h2>
                    <div id="stage-info" style="margin-bottom: 10px; color: #8e8e93; font-size: 14px;"></div>
                    <p id="solution-prompt">Where is Elena? Select the location based on the clues you've gathered:</p>
                    <select id="solution-input" class="solution-input">
                        <option value="">-- Select Location --</option>
                    </select>
                    <input type="text" id="solution-input-2" class="solution-input" placeholder="Enter access code" style="display: none; margin-top: 10px;">
                    <select id="solution-input-3" class="solution-input" style="display: none; margin-top: 10px;">
                        <option value="">-- Select Person --</option>
                    </select>
                    <div class="solution-buttons">
                        <button id="submit-solution" class="solution-submit">Submit Answer</button>
                        <button id="cancel-solution" class="solution-cancel">Keep Investigating</button>
                    </div>
                    <div id="solution-feedback" class="solution-feedback"></div>
                    <div id="lives-warning" style="margin-top: 10px; color: #ff3b30; font-weight: bold; display: none;">
                        ⚠️ Lives remaining: <span id="modal-lives-count"></span>
                    </div>
                </div>
            </div>
            
            <!-- Game Over Screen -->
            <div id="game-over-screen">
                <div class="game-over-title">Game Over</div>
                <div class="game-over-message">Time's up!</div>
                <button class="game-over-button" onclick="location.reload()">Play Again</button>
                <button class="game-over-button" id="game-over-quit" type="button">Quit to Game OS</button>
            </div>
        `;
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Update current time display
        setInterval(() => { if (!document.hidden) this.updateCurrentTime(); }, 1000);
        document.getElementById('game-over-quit').addEventListener('click', () => this.exitGame());
        document.getElementById('exit-game-btn').addEventListener('click', () => this.exitGame());
    }

    async exitGame() {
        if (!confirm('Quit Digital Abyss and return to Game OS? Your progress is saved.')) return;
        try { this.persistRun(); await Promise.race([GameOSSDK.flush(), new Promise(r => setTimeout(r, 4000))]); } catch (_) {}
        GameOSSDK.setRunning(false);
        if (window.gameOSDesktop) { window.gameOSDesktop.quit(); return; }
        location.href = '../../app.html';
    }
    
    setupEventListeners() {
        // App icon clicks
        document.querySelectorAll('.app-icon').forEach(icon => {
            icon.addEventListener('click', (e) => {
                const appName = icon.getAttribute('data-app');
                this.openApp(appName);
                this.playSound('tap');
            });
        });
        
        // Home button click
        document.getElementById('home-button').addEventListener('click', () => {
            this.goHome();
            this.playSound('tap');
        });
        
        // Solve mystery button
        const solveMysteryButton = document.getElementById('solve-mystery-button');
        if (solveMysteryButton) {
            solveMysteryButton.addEventListener('click', () => {
                this.showSolutionModal();
                this.playSound('tap');
            });
        }
        
        // Solution modal buttons
        document.getElementById('submit-solution').addEventListener('click', () => {
            this.submitSolution();
        });
        
        document.getElementById('cancel-solution').addEventListener('click', () => {
            this.hideSolutionModal();
            this.playSound('tap');
        });
        
        // Allow Enter key to submit solution
        document.getElementById('solution-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.submitSolution();
            }
        });
    }
    
    openApp(appName) {
        this.currentApp = appName;
        const appScreens = document.getElementById('app-screens');
        
        // Create app screen
        const appScreen = document.createElement('div');
        appScreen.className = 'app-screen';
        appScreen.id = `${appName}-screen`;
        
        switch(appName) {
            case 'messages':
                appScreen.innerHTML = this.renderMessagesApp();
                break;
            case 'email':
                appScreen.innerHTML = this.renderEmailApp();
                break;
            case 'phone':
                appScreen.innerHTML = this.renderPhoneApp();
                break;
            case 'notes':
                appScreen.innerHTML = this.renderNotesApp();
                break;
        }
        
        appScreens.appendChild(appScreen);
        
        // Trigger animation
        setTimeout(() => appScreen.classList.add('active'), 10);
        
        // Setup app-specific event listeners
        this.setupAppEventListeners(appName);
    }
    
    goHome() {
        const appScreen = document.querySelector('.app-screen.active');
        if (appScreen) {
            appScreen.classList.remove('active');
            setTimeout(() => appScreen.remove(), 300);
        }
        this.currentApp = null;
    }
    
    renderMessagesApp() {
        const conversations = this.currentScenario.messages || [];
        
        let conversationListHTML = conversations.map(conv => `
            <div class="conversation-item" data-conversation-id="${conv.id}">
                <div class="conversation-avatar">${conv.avatar}</div>
                <div class="conversation-info">
                    <div class="conversation-header">
                        <div class="conversation-name">${conv.contact}</div>
                        <div class="conversation-time">${conv.messages[conv.messages.length - 1].time}</div>
                    </div>
                    <div class="conversation-preview ${conv.unread ? 'unread' : ''}">
                        ${conv.messages[conv.messages.length - 1].text}
                    </div>
                </div>
            </div>
        `).join('');
        
        return `
            <div class="app-header">
                <div class="back-button" id="back-to-home">← Back</div>
                <div class="app-title">Messages</div>
                <div class="app-action">✎</div>
            </div>
            <div class="app-content">
                <div class="conversation-list">
                    ${conversationListHTML}
                </div>
            </div>
        `;
    }
    
    renderEmailApp() {
        const emails = this.currentScenario.emails || [];
        
        let emailListHTML = emails.map(email => `
            <div class="email-item ${email.unread ? 'unread' : ''}" data-email-id="${email.id}">
                <div class="email-header">
                    <div class="email-sender">${email.sender}</div>
                    <div class="email-date">${email.date}</div>
                </div>
                <div class="email-subject">${email.subject}</div>
                <div class="email-preview">${email.body.substring(0, 60)}...</div>
            </div>
        `).join('');
        
        return `
            <div class="app-header">
                <div class="back-button" id="back-to-home">← Mailboxes</div>
                <div class="app-title">All Inboxes</div>
                <div class="app-action">✎</div>
            </div>
            <div class="app-content">
                <div class="email-list">
                    ${emailListHTML}
                </div>
            </div>
        `;
    }
    
    renderPhoneApp() {
        const calls = this.currentScenario.calls || [];
        const voicemails = this.currentScenario.voicemails || [];
        
        let callsHTML = calls.map(call => `
            <div class="call-item">
                <div class="call-icon ${call.type}">
                    ${call.type === 'missed' ? '📵' : call.type === 'incoming' ? '📲' : '📞'}
                </div>
                <div class="call-info">
                    <div class="call-name">${call.name}</div>
                    <div class="call-details">${call.type} ${call.duration ? '• ' + call.duration : ''}</div>
                </div>
                <div class="call-time">${call.time}</div>
            </div>
        `).join('');
        
        let voicemailsHTML = voicemails.map(vm => `
            <div class="voicemail-item" data-voicemail-id="${vm.id}">
                <div class="voicemail-header">
                    <div class="voicemail-sender">${vm.sender}</div>
                    <div class="voicemail-duration">${vm.duration}</div>
                </div>
                <div class="voicemail-player">
                    <div class="play-button" data-voicemail-id="${vm.id}">▶</div>
                    <div class="voicemail-progress">
                        <div class="voicemail-progress-bar" style="width: 0%"></div>
                    </div>
                </div>
                <div class="voicemail-transcript" style="display: none; margin-top: 10px; color: #8e8e93; font-size: 13px; line-height: 1.5;">
                    ${vm.transcript}
                </div>
            </div>
        `).join('');
        
        return `
            <div class="app-header">
                <div class="back-button" id="back-to-home">← Back</div>
                <div class="app-title">Phone</div>
                <div class="app-action">+</div>
            </div>
            <div class="phone-tabs">
                <div class="phone-tab active" data-tab="recents">Recents</div>
                <div class="phone-tab" data-tab="voicemail">Voicemail</div>
            </div>
            <div class="app-content">
                <div class="phone-content" id="recents-tab">
                    ${callsHTML}
                </div>
                <div class="phone-content" id="voicemail-tab" style="display: none;">
                    ${voicemailsHTML}
                </div>
            </div>
        `;
    }
    
    renderNotesApp() {
        const notes = this.currentScenario.notes || [];
        
        let notesListHTML = notes.map(note => `
            <div class="note-item" data-note-id="${note.id}">
                <div class="note-title">${note.title}</div>
                <div class="note-preview">${note.content.substring(0, 60)}...</div>
            </div>
        `).join('');
        
        return `
            <div class="app-header">
                <div class="back-button" id="back-to-home">← Folders</div>
                <div class="app-title">Notes</div>
                <div class="app-action">✎</div>
            </div>
            <div class="app-content">
                <div class="notes-list">
                    ${notesListHTML}
                </div>
            </div>
        `;
    }
    
    setupAppEventListeners(appName) {
        // Back button
        const backButton = document.getElementById('back-to-home');
        if (backButton) {
            backButton.addEventListener('click', () => this.goHome());
        }
        
        switch(appName) {
            case 'messages':
                this.setupMessagesListeners();
                break;
            case 'email':
                this.setupEmailListeners();
                break;
            case 'phone':
                this.setupPhoneListeners();
                break;
            case 'notes':
                this.setupNotesListeners();
                break;
        }
    }
    
    setupMessagesListeners() {
        document.querySelectorAll('.conversation-item').forEach(item => {
            item.addEventListener('click', () => {
                const convId = parseInt(item.getAttribute('data-conversation-id'));
                this.openConversation(convId);
                this.playSound('tap');
            });
        });
    }
    
    openConversation(convId) {
        const conversation = this.currentScenario.messages.find(c => c.id === convId);
        if (!conversation) return;
        
        // Track that this message has been viewed
        this.viewedMessages.add(convId); this.persistRun();
        
        let messagesHTML = conversation.messages.map(msg => `
            <div class="message-bubble ${msg.type}">
                ${this.highlightClues(msg.text)}
            </div>
            <div class="message-time">${msg.time}</div>
        `).join('');
        
        const appContent = document.querySelector('#messages-screen .app-content');
        appContent.innerHTML = `
            <div class="message-thread">
                ${messagesHTML}
            </div>
        `;
        
        // Update header
        const header = document.querySelector('#messages-screen .app-header');
        header.innerHTML = `
            <div class="back-button" id="back-to-messages">← Messages</div>
            <div class="app-title">${conversation.contact}</div>
            <div class="app-action">ℹ️</div>
        `;
        
        document.getElementById('back-to-messages').addEventListener('click', () => {
            appContent.innerHTML = this.renderMessagesApp().match(/<div class="app-content">[\s\S]*<\/div>/)[0].replace(/<div class="app-content">|<\/div>$/g, '');
            header.innerHTML = this.renderMessagesApp().match(/<div class="app-header">[\s\S]*?<\/div>/)[0];
            this.setupMessagesListeners();
            document.getElementById('back-to-home').addEventListener('click', () => this.goHome());
        });
        
        // Scroll to bottom
        appContent.scrollTop = appContent.scrollHeight;
    }
    
    setupEmailListeners() {
        document.querySelectorAll('.email-item').forEach(item => {
            item.addEventListener('click', () => {
                const emailId = parseInt(item.getAttribute('data-email-id'));
                this.openEmail(emailId);
                this.playSound('tap');
            });
        });
    }
    
    openEmail(emailId) {
        const email = this.currentScenario.emails.find(e => e.id === emailId);
        if (!email) return;
        
        // Track that this email has been viewed
        this.viewedEmails.add(emailId); this.persistRun();
        
        const appContent = document.querySelector('#email-screen .app-content');
        appContent.innerHTML = `
            <div class="email-detail">
                <div class="email-sender">${email.sender}</div>
                <div class="email-subject">${email.subject}</div>
                <div class="email-date">${email.date}</div>
                <div class="email-body">${this.highlightClues(email.body.replace(/\n/g, '<br>'))}</div>
            </div>
        `;
        
        // Update header
        const header = document.querySelector('#email-screen .app-header');
        header.innerHTML = `
            <div class="back-button" id="back-to-emails">← Inbox</div>
            <div class="app-title">${email.subject}</div>
            <div class="app-action">🗑️</div>
        `;
        
        document.getElementById('back-to-emails').addEventListener('click', () => {
            appContent.innerHTML = this.renderEmailApp().match(/<div class="app-content">[\s\S]*<\/div>/)[0].replace(/<div class="app-content">|<\/div>$/g, '');
            header.innerHTML = this.renderEmailApp().match(/<div class="app-header">[\s\S]*?<\/div>/)[0];
            this.setupEmailListeners();
            document.getElementById('back-to-home').addEventListener('click', () => this.goHome());
        });
    }
    
    setupPhoneListeners() {
        // Tab switching
        document.querySelectorAll('.phone-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.getAttribute('data-tab');
                
                // Update active tab
                document.querySelectorAll('.phone-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                // Show corresponding content
                document.getElementById('recents-tab').style.display = tabName === 'recents' ? 'block' : 'none';
                document.getElementById('voicemail-tab').style.display = tabName === 'voicemail' ? 'block' : 'none';
                
                this.playSound('tap');
            });
        });
        
        // Voicemail play buttons
        document.querySelectorAll('.play-button').forEach(button => {
            button.addEventListener('click', (e) => {
                e.stopPropagation();
                const vmId = parseInt(button.getAttribute('data-voicemail-id'));
                this.playVoicemail(vmId);
            });
        });
    }
    
    playVoicemail(vmId) {
        const voicemail = this.currentScenario.voicemails.find(vm => vm.id === vmId);
        if (!voicemail) return;
        
        // Track that this voicemail has been viewed
        this.viewedVoicemails.add(vmId); this.persistRun();
        
        const vmItem = document.querySelector(`.voicemail-item[data-voicemail-id="${vmId}"]`);
        const playButton = vmItem.querySelector('.play-button');
        const progressBar = vmItem.querySelector('.voicemail-progress-bar');
        const transcript = vmItem.querySelector('.voicemail-transcript');
        
        // Simulate playing
        playButton.textContent = '⏸';
        this.playSound('voicemail');
        
        let progress = 0;
        const interval = setInterval(() => {
            progress += 2;
            progressBar.style.width = progress + '%';
            
            if (progress >= 100) {
                clearInterval(interval);
                playButton.textContent = '▶';
                // Show transcript
                transcript.style.display = 'block';
            }
        }, 50);
    }
    
    setupNotesListeners() {
        document.querySelectorAll('.note-item').forEach(item => {
            item.addEventListener('click', () => {
                const noteId = parseInt(item.getAttribute('data-note-id'));
                this.openNote(noteId);
                this.playSound('tap');
            });
        });
    }
    
    openNote(noteId) {
        const note = this.currentScenario.notes.find(n => n.id === noteId);
        if (!note) return;
        
        // Track that this note has been viewed
        this.viewedNotes.add(noteId); this.persistRun();
        
        const appContent = document.querySelector('#notes-screen .app-content');
        appContent.innerHTML = `
            <div class="note-detail">
                <div class="note-title">${note.title}</div>
                <div class="note-content">${this.highlightClues(note.content)}</div>
            </div>
        `;
        
        // Update header
        const header = document.querySelector('#notes-screen .app-header');
        header.innerHTML = `
            <div class="back-button" id="back-to-notes">← Notes</div>
            <div class="app-title">${note.title}</div>
            <div class="app-action">🗑️</div>
        `;
        
        document.getElementById('back-to-notes').addEventListener('click', () => {
            appContent.innerHTML = this.renderNotesApp().match(/<div class="app-content">[\s\S]*<\/div>/)[0].replace(/<div class="app-content">|<\/div>$/g, '');
            header.innerHTML = this.renderNotesApp().match(/<div class="app-header">[\s\S]*?<\/div>/)[0];
            this.setupNotesListeners();
            document.getElementById('back-to-home').addEventListener('click', () => this.goHome());
        });
    }
    
    highlightClues(text) {
        // Highlight important clues in text
        const clueKeywords = [
            'warehouse', 'basement', '5th and Main', 'locker 247', '8-15-23', 
            'Victor Ashford', 'Victor Kozlov', 'B3', 'midnight', 'evidence',
            '2491', '2496', 'east storage', 'west storage', 'Prague', 'forgery',
            'Midnight in Paris', 'employee ID', '6942', 'Dr. Porter', 'James Porter',
            'Project Phoenix', 'adverse reactions', '15%', 'safety data'
        ];
        
        let highlightedText = text;
        clueKeywords.forEach(keyword => {
            // Escape special regex characters
            const escapedKeyword = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const regex = new RegExp(`(${escapedKeyword})`, 'gi');
            highlightedText = highlightedText.replace(regex, '<span class="clue-text">$1</span>');
        });
        
        return highlightedText;
    }
    
    getUnreadCount(appType) {
        switch(appType) {
            case 'messages':
                return (this.currentScenario.messages || []).filter(m => m.unread).length;
            case 'email':
                return (this.currentScenario.emails || []).filter(e => e.unread).length;
            case 'phone':
                return (this.currentScenario.voicemails || []).length;
            default:
                return 0;
        }
    }
    
    startTimer() {
        this.gameStartTime = Date.now() - (this.resumeElapsed || 0);
        
        this.timerInterval = setInterval(() => {
            if (document.hidden) {
                if (Date.now() - this.gameStartTime >= this.gameDuration) this.endGame('timeout');
                return;
            }
            const elapsed = Date.now() - this.gameStartTime;
            const remaining = this.gameDuration - elapsed;
            
            if (remaining <= 0) {
                this.endGame('timeout');
            } else {
                if (Math.floor(elapsed / 1000) % 30 === 0) this.persistRun();
                this.updateTimerDisplay(remaining);
                this.checkTimeBasedTriggers(elapsed);
            }
        }, 1000);
    }
    
    checkTimeBasedTriggers(elapsed) {
        const elapsedMinutes = elapsed / 60000;
        
        // 5-minute trigger: Initial pressure message
        if (elapsedMinutes >= 5 && !this.timeBasedCluesRevealed.fiveMinutes) {
            this.timeBasedCluesRevealed.fiveMinutes = true;
            this.revealTimedClue('fiveMinutes');
        }
        
        // 10-minute trigger: Reveal additional clues
        if (elapsedMinutes >= 10 && !this.timeBasedCluesRevealed.tenMinutes) {
            this.timeBasedCluesRevealed.tenMinutes = true;
            this.revealTimedClue('tenMinutes');
        }
        
        // 15-minute trigger: Add time-sensitive challenge
        if (elapsedMinutes >= 15 && !this.timeBasedCluesRevealed.fifteenMinutes) {
            this.timeBasedCluesRevealed.fifteenMinutes = true;
            this.revealTimedClue('fifteenMinutes');
        }
        
        // 20-minute trigger: Final warning
        if (elapsedMinutes >= 20 && !this.timeBasedCluesRevealed.twentyMinutes) {
            this.timeBasedCluesRevealed.twentyMinutes = true;
            this.revealTimedClue('twentyMinutes');
        }
    }
    
    revealTimedClue(triggerType) {
        const scenarioId = this.currentScenario.id;
        
        // Add notification badge to relevant app
        if (triggerType === 'fiveMinutes') {
            // Early game hints
            if (scenarioId === 1) {
                // Art Gallery scenario
                this.addDynamicMessage('Marcus Chen', 'Remember: the solution has THREE parts - exact location, access code, and the person responsible. Don\'t miss any clues!');
                this.showNotification('💡 Hint: Multi-part solution required');
            } else if (scenarioId === 2) {
                // Research Lab scenario
                this.addDynamicMessage('Federal Investigator', 'Reminder: We need precise location, access code, AND the name of your key contact helping with evidence.');
                this.showNotification('💡 Hint: Three pieces of information needed');
            }
            this.playSound('tap');
        } else if (triggerType === 'tenMinutes') {
            // Scenario-specific messages
            if (scenarioId === 1) {
                // Art Gallery scenario
                this.addDynamicMessage('Detective Rivera', 'New intel: Victor Kozlov has a history in Prague (case #0847). This might be important for accessing his operation.');
                this.showNotification('📨 New message from Detective Rivera - Code hint!');
            } else if (scenarioId === 2) {
                // Research Lab scenario
                this.addDynamicMessage('Lisa Chen - Lab Tech', 'I just remembered - Dr. Porter kept emphasizing EAST wing before the spill. He seemed really insistent about it.');
                this.showNotification('📨 New message from Lisa Chen - Location clue!');
            }
            this.playSound('tap');
        } else if (triggerType === 'fifteenMinutes') {
            // Escalating pressure messages
            if (scenarioId === 1) {
                // Art Gallery scenario
                this.addDynamicEmail('Anonymous Tip', 'URGENT: Victor Kozlov is packing up the warehouse BASEMENT (not the main floor). He\'ll be gone within the hour. The person you need to stop is Victor Kozlov himself!');
                this.showNotification('⚠️ URGENT: Kozlov fleeing soon - Basement confirmed!');
            } else if (scenarioId === 2) {
                // Research Lab scenario  
                this.addDynamicEmail('Federal Investigator', 'CRITICAL: We need confirmation of Dr. James Porter\'s location and the exact room. Corporate is destroying evidence at midnight. Time is running out!');
                this.showNotification('⚠️ URGENT: Need location + person identification!');
            }
            this.playSound('tap');
        } else if (triggerType === 'twentyMinutes') {
            // Final pressure messages
            if (scenarioId === 1) {
                // Art Gallery scenario
                this.addDynamicMessage('Unknown', 'This is your last chance. Victor Kozlov, warehouse basement, code 0847. If you don\'t act now, he escapes forever.');
                this.showNotification('🚨 FINAL WARNING: All clues revealed!');
            } else if (scenarioId === 2) {
                // Research Lab scenario
                this.addDynamicMessage('Anonymous', 'FINAL WARNING: Dr. James Porter, east storage room, code 2496. Evidence will be destroyed in 40 minutes!');
                this.showNotification('🚨 FINAL WARNING: All clues revealed!');
            }
            this.playSound('tap');
        }
        
        // Refresh home screen to update badges
        this.refreshHomeScreen();
    }
    
    addDynamicMessage(contact, text) {
        if (!this.currentScenario.messages) return;
        
        // Find or create conversation with contact
        let conversation = this.currentScenario.messages.find(m => m.contact === contact);
        if (conversation) {
            conversation.messages.push({
                type: 'received',
                text: text,
                time: 'Just now'
            });
            conversation.unread = true;
        }
    }
    
    addDynamicEmail(sender, body) {
        if (!this.currentScenario.emails) return;
        
        const newEmail = {
            id: this.currentScenario.emails.length + 100,
            sender: sender,
            email: 'alert@system.com',
            subject: 'URGENT ALERT',
            date: 'Just now',
            body: body,
            unread: true
        };
        
        this.currentScenario.emails.unshift(newEmail);
    }
    
    showNotification(message) {
        const notification = document.createElement('div');
        notification.className = 'game-notification';
        notification.textContent = message;
        document.getElementById('screen').appendChild(notification);
        
        setTimeout(() => notification.classList.add('show'), 10);
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 4000);
    }
    
    refreshHomeScreen() {
        // Update badge counts if on home screen
        const messagesIcon = document.querySelector('.app-icon[data-app="messages"] .badge');
        const emailIcon = document.querySelector('.app-icon[data-app="email"] .badge');
        
        const messageCount = this.getUnreadCount('messages');
        const emailCount = this.getUnreadCount('email');
        
        if (messagesIcon && messageCount > 0) {
            messagesIcon.textContent = messageCount;
        } else if (messageCount > 0) {
            const icon = document.querySelector('.app-icon[data-app="messages"] .app-icon-image');
            if (icon && !icon.querySelector('.badge')) {
                icon.insertAdjacentHTML('beforeend', `<div class="badge">${messageCount}</div>`);
            }
        }
        
        if (emailIcon && emailCount > 0) {
            emailIcon.textContent = emailCount;
        } else if (emailCount > 0) {
            const icon = document.querySelector('.app-icon[data-app="email"] .app-icon-image');
            if (icon && !icon.querySelector('.badge')) {
                icon.insertAdjacentHTML('beforeend', `<div class="badge">${emailCount}</div>`);
            }
        }
    }
    
    updateTimerDisplay(remaining) {
        const minutes = Math.floor(remaining / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);
        const display = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        
        const timerElement = document.getElementById('timer-display');
        timerElement.textContent = display;
        
        // Add warning class if less than 5 minutes
        if (minutes < 5) {
            timerElement.classList.add('timer-warning');
        }
    }
    
    getCurrentTime() {
        const now = new Date();
        return now.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: false });
    }
    
    getCurrentDate() {
        const now = new Date();
        return now.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
    }
    
    updateCurrentTime() {
        const timeElement = document.getElementById('current-time');
        if (timeElement) {
            timeElement.textContent = this.getCurrentTime();
        }
    }
    
    endGame(reason) {
        if (this.finished) return;
        this.finished = true;
        clearInterval(this.timerInterval);
        GameOSSDK.setRunning(false);
        
        let ending;
        if (reason === 'gameover') {
            ending = {
                title: 'Game Over - Out of Lives',
                message: 'You\'ve run out of attempts. The antagonist has been alerted and fled with the evidence. Elena\'s whereabouts remain unknown.',
                success: false
            };
        } else {
            ending = this.currentScenario.endings[reason] || this.currentScenario.endings.timeout;
        }
        
        const gameOverScreen = document.getElementById('game-over-screen');
        gameOverScreen.querySelector('.game-over-title').textContent = ending.title;
        
        // Build the message with solution details if the player lost
        let fullMessage = ending.message;
        if (!ending.success) {
            fullMessage += '\n\n' + this.getCorrectSolutionExplanation();
        }
        
        gameOverScreen.querySelector('.game-over-message').innerHTML = fullMessage.replace(/\n/g, '<br>');
        gameOverScreen.classList.add('show');
        
        this.playSound(ending.success ? 'success' : 'failure');

        if (ending.success) GameOSSDK.report('solved', this.achievementContext());
        else GameOSSDK.report('lost', { reason });
        GameOSSDK.saveRun(null);
        GameOSSDK.flush();
    }
    
    getCorrectSolutionExplanation() {
        let explanation = '<div style="margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.1); border-radius: 10px; text-align: left;">';
        explanation += '<h3 style="color: #ff9500; margin-bottom: 10px;">🔍 Here\'s What You Missed:</h3>';
        
        if (this.currentScenario.requiresMultiPart && this.currentScenario.multiPartSolution) {
            const solution = this.currentScenario.multiPartSolution;
            explanation += '<div style="margin: 10px 0;"><strong>Location:</strong> ' + this.escapeHtml(this.capitalizeWords(solution.location)) + '</div>';
            explanation += '<div style="margin: 10px 0;"><strong>Access Code:</strong> ' + this.escapeHtml(solution.code) + '</div>';
            if (solution.person) {
                explanation += '<div style="margin: 10px 0;"><strong>Person Responsible:</strong> ' + this.escapeHtml(this.capitalizeWords(solution.person)) + '</div>';
            }
        } else {
            explanation += '<div style="margin: 10px 0;"><strong>Location:</strong> ' + this.escapeHtml(this.capitalizeWords(this.currentScenario.solution)) + '</div>';
        }
        
        explanation += '<div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.2);">';
        explanation += '<h4 style="color: #ff9500; margin-bottom: 8px;">📖 The Full Story:</h4>';
        explanation += '<p style="line-height: 1.6; font-size: 14px;">' + this.escapeHtml(this.getScenarioStoryExplanation()) + '</p>';
        explanation += '</div>';
        explanation += '</div>';
        
        return explanation;
    }
    
    getScenarioStoryExplanation() {
        // Return the full story explanation based on scenario
        if (this.currentScenario.id === 1) {
            return 'Elena was investigating an international art forgery ring run by Victor Kozlov (alias "Victor Ashford"). ' +
                   'The clues pointed to the warehouse basement at 5th and Main, where Kozlov stored stolen artwork. ' +
                   'The access code 0847 was hidden in references to the Prague case file throughout the messages and emails. ' +
                   'Marcus Chen was helping Elena gather evidence, but anonymous messages tried to mislead the investigation toward the Riverside gallery. ' +
                   'Elena needed to reach the warehouse basement with the correct code to expose the forgery ring before Kozlov could destroy the evidence and flee.';
        } else if (this.currentScenario.id === 2) {
            return 'Elena discovered that TechCorp was suppressing critical safety data about Project Phoenix. ' +
                   'She partnered with Dr. James Porter, a whistleblower scientist, to secure evidence in the east storage room of the basement lab. ' +
                   'The access code 2496 was Dr. Porter\'s employee ID (6942) reversed, a detail mentioned in the notes and emails. ' +
                   'Corporate security was trying to destroy evidence at midnight, and some contacts were deliberately misleading Elena toward the wrong location. ' +
                   'Only by finding the exact location, code, and trusting the right person could Elena successfully preserve the evidence and expose the cover-up.';
        } else {
            // Generic fallback for other scenarios
            return 'The clues scattered throughout Elena\'s phone revealed the truth about her disappearance. ' +
                   'By carefully analyzing messages, emails, call logs, and notes, you could have pieced together the exact location, ' +
                   'access codes, and key individuals involved. Time pressure and misdirection were part of the challenge.';
        }
    }
    
    capitalizeWords(str) {
        if (!str) return '';
        return str.split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
    }
    
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
    
    showSolutionModal() {
        const modal = document.getElementById('solution-modal');
        modal.classList.add('show');
        
        // Clear previous input and feedback
        const locationSelect = document.getElementById('solution-input');
        const codeInput = document.getElementById('solution-input-2');
        const personSelect = document.getElementById('solution-input-3');
        
        locationSelect.selectedIndex = 0;
        if (codeInput) codeInput.value = '';
        if (personSelect) personSelect.selectedIndex = 0;
        document.getElementById('solution-feedback').textContent = '';
        
        // Update stage info and prompt based on scenario
        this.updateSolutionModalContent();
        
        // Focus on select
        setTimeout(() => {
            locationSelect.focus();
        }, 100);
    }
    
    hasViewedRequiredClues(clueRequirements) {
        if (!clueRequirements) return true; // No requirements, always show
        
        const { messages = [], emails = [], notes = [], voicemails = [] } = clueRequirements;
        
        // Check if all required clues have been viewed using every()
        return messages.every(id => this.viewedMessages.has(id)) &&
               emails.every(id => this.viewedEmails.has(id)) &&
               notes.every(id => this.viewedNotes.has(id)) &&
               voicemails.every(id => this.viewedVoicemails.has(id));
    }
    
    updateSolutionModalContent() {
        const stageInfo = document.getElementById('stage-info');
        const prompt = document.getElementById('solution-prompt');
        const locationSelect = document.getElementById('solution-input');
        const codeInput = document.getElementById('solution-input-2');
        const personSelect = document.getElementById('solution-input-3');
        
        // Populate location dropdown from scenario endings (only if clues are viewed)
        locationSelect.innerHTML = '<option value="">-- Select Location --</option>';
        if (this.currentScenario.endings) {
            const locations = Object.keys(this.currentScenario.endings)
                .filter(key => !this.EXCLUDED_ENDINGS.includes(key))
                .filter(key => {
                    // Check if location has clue requirements
                    const ending = this.currentScenario.endings[key];
                    if (ending && ending.clueRequirements) {
                        return this.hasViewedRequiredClues(ending.clueRequirements);
                    }
                    return true; // No requirements, show by default
                })
                .sort();
            
            locations.forEach(location => {
                const option = document.createElement('option');
                option.value = location;
                option.textContent = this.capitalizeWords(location);
                locationSelect.appendChild(option);
            });
        }
        
        // Populate person dropdown from scenario personOptions or messages (only if clues are viewed)
        personSelect.innerHTML = '<option value="">-- Select Person --</option>';
        
        let persons = [];
        if (this.currentScenario.personOptions && this.currentScenario.personOptions.length > 0) {
            // Use predefined person options if available
            persons = this.currentScenario.personOptions
                .filter(person => {
                    // Check if person has clue requirements in personClueRequirements
                    const requirements = this.currentScenario.personClueRequirements?.[person];
                    return requirements ? this.hasViewedRequiredClues(requirements) : true;
                });
        } else if (this.currentScenario.messages) {
            // Fallback to extracting from messages
            persons = this.currentScenario.messages
                .map(msg => msg.contact)
                .filter(contact => contact && !this.EXCLUDED_CONTACTS.includes(contact));
        }
        
        // Add unique persons
        const uniquePersons = [...new Set(persons)].sort();
        uniquePersons.forEach(person => {
            const option = document.createElement('option');
            option.value = person.toLowerCase();
            option.textContent = person;
            personSelect.appendChild(option);
        });
        
        // Check if this scenario requires multi-part answer
        if (this.currentScenario.requiresMultiPart) {
            const totalStages = this.currentScenario.totalStages || 2;
            stageInfo.textContent = `Multi-part solution required (${totalStages} parts)`;
            
            if (totalStages >= 3) {
                prompt.textContent = 'Select the exact location, enter access code, and select the person involved:';
                codeInput.style.display = 'block';
                personSelect.style.display = 'block';
                codeInput.placeholder = 'Enter access code (e.g., 0847)';
            } else {
                prompt.textContent = 'Select the exact location and enter the access code:';
                codeInput.style.display = 'block';
                personSelect.style.display = 'none';
                codeInput.placeholder = 'Enter access code (e.g., 2496)';
            }
        } else {
            stageInfo.textContent = '';
            prompt.textContent = 'Where is Elena? Select the location based on the clues you\'ve gathered:';
            codeInput.style.display = 'none';
            personSelect.style.display = 'none';
        }
    }
    
    hideSolutionModal() {
        const modal = document.getElementById('solution-modal');
        modal.classList.remove('show');
    }
    
    submitSolution() {
        const locationSelect = document.getElementById('solution-input');
        const codeInput = document.getElementById('solution-input-2');
        const personSelect = document.getElementById('solution-input-3');
        const feedback = document.getElementById('solution-feedback');
        const livesWarning = document.getElementById('lives-warning');
        const livesCount = document.getElementById('modal-lives-count');
        
        const userAnswer = locationSelect.value.trim().toLowerCase();
        const userAnswer2 = codeInput.style.display !== 'none' ? codeInput.value.trim() : '';
        const userAnswer3 = personSelect && personSelect.style.display !== 'none' ? personSelect.value.trim().toLowerCase() : '';
        
        if (!userAnswer) {
            feedback.textContent = 'Please select a location.';
            feedback.style.color = '#ff3b30';
            this.playSound('tap');
            return;
        }
        
        // Check if answer is correct
        let isCorrect = false;
        
        if (this.currentScenario.requiresMultiPart && this.currentScenario.multiPartSolution) {
            // Multi-part solution check
            const solution = this.currentScenario.multiPartSolution;
            const normalizedLocation = solution.location.toLowerCase();
            const normalizedUserAnswer = userAnswer.toLowerCase();
            
            // Check if user answer contains the key location terms (requires at least 2 words match)
            const locationWords = normalizedLocation.split(' ');
            const matchedWords = locationWords.filter(word => normalizedUserAnswer.includes(word));
            const locationMatch = matchedWords.length >= Math.min(2, locationWords.length);
            
            // Code must match exactly
            const codeMatch = userAnswer2 === solution.code || userAnswer === solution.code;
            
            // Person check (if required) - check if user answer contains the person's key name parts
            let personMatch = true;
            if (solution.person && this.currentScenario.totalStages >= 3) {
                const normalizedPerson = solution.person.toLowerCase();
                const personWords = normalizedPerson.split(' ').filter(word => word.length > 2); // Ignore short words like "dr"
                const personMatchedWords = personWords.filter(word => userAnswer3.includes(word));
                // Require at least 50% of name words to match, with minimum of 1
                const requiredMatches = Math.max(1, Math.ceil(personWords.length * 0.5));
                personMatch = personMatchedWords.length >= requiredMatches;
            }
            
            isCorrect = locationMatch && codeMatch && personMatch;
        } else {
            // Simple solution check
            const correctSolution = this.currentScenario.solution.toLowerCase();
            const escapedSolution = correctSolution.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            isCorrect = userAnswer === correctSolution || 
                       new RegExp(`\\b${escapedSolution}\\b`).test(userAnswer);
        }
        
        if (isCorrect) {
            // Correct answer!
            feedback.textContent = '✓ Correct! Revealing what happened...';
            feedback.style.color = '#34c759';
            livesWarning.style.display = 'none';
            this.playSound('success');
            
            // End game with success
            setTimeout(() => {
                this.hideSolutionModal();
                this.endGame(this.currentScenario.solution);
            }, 1500);
        } else {
            // Wrong answer - decrease lives
            this.lives--;
            this.wrongAttempts++;
            this.updateLivesDisplay();
            GameOSSDK.report('wrong', { scenarioId: this.currentScenario.id, location: userAnswer });
            if (this.lives > 0) this.persistRun();
            
            if (this.lives <= 0) {
                // Game over - no more lives
                feedback.textContent = '✗ No more lives remaining. The antagonist has escaped!';
                feedback.style.color = '#ff3b30';
                this.playSound('failure');
                
                setTimeout(() => {
                    this.hideSolutionModal();
                    this.endGame('gameover');
                }, 2000);
            } else {
                // Show wrong answer feedback with lives warning
                const antagonistWarnings = [
                    'The antagonist has been alerted to your investigation!',
                    'You\'re running out of time - the antagonist is getting suspicious!',
                    'Final warning: One more wrong answer and they\'ll escape!'
                ];
                
                feedback.innerHTML = `✗ That's not correct. ${antagonistWarnings[this.wrongAttempts - 1] || 'Keep investigating the clues.'}`;
                feedback.style.color = '#ff3b30';
                livesWarning.style.display = 'block';
                livesCount.textContent = this.lives;
                this.playSound('tap');
                
                // Clear inputs for next attempt
                setTimeout(() => {
                    locationSelect.selectedIndex = 0;
                    if (codeInput.style.display !== 'none') codeInput.value = '';
                    if (personSelect && personSelect.style.display !== 'none') personSelect.selectedIndex = 0;
                    
                    // Trigger narrative relocation after first wrong answer
                    if (this.wrongAttempts === 1 && !this.narrativeShifted) {
                        this.triggerNarrativeRelocation();
                        this.persistRun();
                    }
                }, 1500);
            }
        }
    }
    
    triggerNarrativeRelocation() {
        // Add new dynamic hints/messages after wrong answer to shift narrative
        this.narrativeShifted = true;
        this.playSound('notification');
        
        // Create relocation hints based on scenario
        const relocationHints = this.getRelocationHints();
        
        if (relocationHints.messages) {
            // Add new messages to the scenario
            relocationHints.messages.forEach(msg => {
                this.currentScenario.messages.push(msg);
            });
        }
        
        // Update message badges to show new unread messages
        this.updateAppBadges();
        
        // Show notification
        this.showNotification('📱 New Messages: Timeline has shifted. Check for new clues!');
    }
    
    getRelocationHints() {
        // Return scenario-specific relocation hints that trigger after wrong answer
        const scenarioId = this.currentScenario.id;
        
        const relocationData = {
            1: { // Art Gallery
                messages: [{
                    id: 99,
                    contact: "Timeline Shift",
                    avatar: "⚡",
                    messages: [
                        { type: "received", text: "Your investigation has altered the timeline. The antagonist is aware of your pursuit.", time: "NOW", isClue: true },
                        { type: "received", text: "New intelligence: The warehouse basement remains the key location. Don't be misled by surface-level locations.", time: "NOW", isClue: true }
                    ],
                    unread: true
                }]
            },
            2: { // Research Lab
                messages: [{
                    id: 99,
                    contact: "Reality Shift",
                    avatar: "⚡",
                    messages: [
                        { type: "received", text: "The timeline has diverged. Your actions have consequences across different realities.", time: "NOW", isClue: true },
                        { type: "received", text: "Critical: Focus on the contamination chamber, not the storage areas. The truth lies where the experiment went wrong.", time: "NOW", isClue: true }
                    ],
                    unread: true
                }]
            },
            3: { // Quantum Lab Paradox
                messages: [{
                    id: 99,
                    contact: "Temporal Anomaly",
                    avatar: "⚡",
                    messages: [
                        { type: "received", text: "Temporal paradox detected. Your investigation has created a new timeline branch.", time: "NOW", isClue: true },
                        { type: "received", text: "The temporal chamber in Sector 7 is the anchor point. Building 3 is a temporal echo - a false memory.", time: "NOW", isClue: true }
                    ],
                    unread: true
                }]
            },
            4: { // Underground Network
                messages: [{
                    id: 99,
                    contact: "System Alert",
                    avatar: "⚡",
                    messages: [
                        { type: "received", text: "Network intrusion detected. Your investigation pattern has been logged.", time: "NOW", isClue: true },
                        { type: "received", text: "Secure communication: Server Room Delta in basement is the core. Alpha on 5th floor is a honeypot designed to trap investigators.", time: "NOW", isClue: true }
                    ],
                    unread: true
                }]
            },
            5: { // Museum Heist
                messages: [{
                    id: 99,
                    contact: "Shadow Witness",
                    avatar: "⚡",
                    messages: [
                        { type: "received", text: "Your investigation has forced the criminal to adjust their plan. New information has surfaced.", time: "NOW", isClue: true },
                        { type: "received", text: "Isabella's invitation to Vault 1 is a diversion. The stolen paintings never left Vault Room 3 in the West Wing. She needs to retrieve them tonight.", time: "NOW", isClue: true }
                    ],
                    unread: true
                }]
            }
        };
        
        return relocationData[scenarioId] || { messages: [] };
    }
    
    showNotification(message) {
        // Show notification banner at top of screen
        const notification = document.createElement('div');
        notification.className = 'game-notification';
        notification.innerHTML = `
            <div class="notification-content">
                <span>${message}</span>
            </div>
        `;
        notification.style.cssText = `
            position: fixed;
            top: 60px;
            left: 50%;
            transform: translateX(-50%);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 25px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            z-index: 9999;
            font-size: 14px;
            max-width: 80%;
            text-align: center;
            animation: slideDown 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            notification.style.animation = 'slideUp 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }
    
    updateAppBadges() {
        // Update unread message badges
        const messagesIcon = document.querySelector('.app-icon[data-app="messages"] .badge');
        if (messagesIcon) {
            const unreadCount = this.getUnreadCount('messages');
            messagesIcon.textContent = unreadCount;
            if (unreadCount > 0) {
                messagesIcon.style.display = 'flex';
            }
        }
    }
    
    updateLivesDisplay() {
        const livesDisplay = document.getElementById('lives-display');
        if (livesDisplay) {
            const hearts = '❤️'.repeat(this.lives) + '🖤'.repeat(this.maxLives - this.lives);
            livesDisplay.innerHTML = `${hearts}`;
        }
    }
    
    playSound(soundType) {
        if (!this.soundEnabled) return;
        
        // Create simple beep sounds using Web Audio API
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        switch(soundType) {
            case 'tap':
                oscillator.frequency.value = 800;
                gainNode.gain.value = 0.1;
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.05);
                break;
            case 'startup':
                oscillator.frequency.value = 523.25; // C5
                gainNode.gain.value = 0.2;
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.2);
                break;
            case 'voicemail':
                oscillator.frequency.value = 440;
                gainNode.gain.value = 0.15;
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.1);
                break;
            case 'success':
                // Success jingle
                oscillator.frequency.value = 659.25; // E5
                gainNode.gain.value = 0.2;
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.3);
                break;
            case 'failure':
                oscillator.frequency.value = 220;
                gainNode.gain.value = 0.2;
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.4);
                break;
        }
    }
}

// Initialize game when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.addEventListener('da-achievement', e => window.game && window.game.showAchievementToast(e.detail));
    window.game = new DigitalAbyssGame();
});