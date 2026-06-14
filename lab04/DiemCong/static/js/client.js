// Secure Socket Chat JS Client

document.addEventListener('DOMContentLoaded', () => {
    let socket = io({ transports: ['websocket'] });
    let currentUsername = "";
    let activeProtocol = "";
    let currentAesKey = "";
    let isAesKeyVisible = false;

    // --- DOM Elements ---
    // Login
    const loginContainer = document.getElementById('login-container');
    const loginBtn = document.getElementById('login-btn');
    const usernameInput = document.getElementById('username-input');
    const loginError = document.getElementById('login-error');
    const handshakeOverlay = document.getElementById('handshake-overlay');
    const handshakeStepsList = document.getElementById('handshake-steps-list');

    // App Layout
    const appContainer = document.getElementById('app-container');
    const currentHeading = document.getElementById('current-user-heading');
    const roomTitle = document.getElementById('room-title');
    const chatHeaderTitle = document.getElementById('chat-header-title');
    const activeProtocolBadge = document.getElementById('active-protocol-badge');
    const messagesWindow = document.getElementById('messages-window');
    const chatMessages = document.getElementById('chat-messages');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    const logoutBtn = document.getElementById('logout-btn');

    // Security Inspector
    const securitySidebar = document.getElementById('security-sidebar');
    const toggleSecurityBtn = document.getElementById('toggle-security-btn');
    const inspectorProtocolName = document.getElementById('inspector-protocol-name');
    const inspectorSocketPort = document.getElementById('inspector-socket-port');
    const aesKeyDisplay = document.getElementById('aes-key-display');
    const toggleAesVisibility = document.getElementById('toggle-aes-visibility');
    const aesEyeIcon = document.getElementById('aes-eye-icon');
    const dhInfoCard = document.getElementById('dh-info-card');
    const dhSecretDisplay = document.getElementById('dh-secret-display');
    const clientPubDisplay = document.getElementById('client-pub-display');
    const serverPubDisplay = document.getElementById('server-pub-display');
    const clientPrivDisplay = document.getElementById('client-priv-display');
    const snifferLog = document.getElementById('sniffer-log');
    const clearSnifferBtn = document.getElementById('clear-sniffer');

    // --- Accordion Logic ---
    document.querySelectorAll('.accordion-trigger').forEach(trigger => {
        trigger.addEventListener('click', function() {
            const item = this.parentElement;
            const isActive = item.classList.contains('active');
            
            // Close all items
            document.querySelectorAll('.accordion-item').forEach(i => {
                i.classList.remove('active');
                i.querySelector('.accordion-content').style.maxHeight = null;
            });

            // Toggle active item
            if (!isActive) {
                item.classList.add('active');
                const content = item.querySelector('.accordion-content');
                content.style.maxHeight = content.scrollHeight + "px";
            }
        });
    });

    // --- Accordion/Sidebar heights adjustments during dynamic content loading ---
    function adjustAccordionHeight(item) {
        if (item.classList.contains('active')) {
            const content = item.querySelector('.accordion-content');
            content.style.maxHeight = content.scrollHeight + "px";
        }
    }

    // --- Toggle Security Sidebar ---
    toggleSecurityBtn.addEventListener('click', () => {
        securitySidebar.classList.toggle('collapsed');
        toggleSecurityBtn.classList.toggle('active');
    });

    // --- Toggle AES Key Visibility ---
    toggleAesVisibility.addEventListener('click', () => {
        isAesKeyVisible = !isAesKeyVisible;
        if (isAesKeyVisible) {
            aesKeyDisplay.classList.remove('hidden-key');
            aesKeyDisplay.textContent = currentAesKey;
            aesEyeIcon.setAttribute('data-lucide', 'eye-off');
        } else {
            aesKeyDisplay.classList.add('hidden-key');
            aesKeyDisplay.textContent = "--------------------------------";
            aesEyeIcon.setAttribute('data-lucide', 'eye');
        }
        lucide.createIcons();
    });

    // --- Clear Sniffer ---
    clearSnifferBtn.addEventListener('click', () => {
        snifferLog.innerHTML = `<div class="sniffer-placeholder">Waiting for socket activity...</div>`;
    });

    // --- Log Packet to Sniffer Console ---
    function addSnifferLog(direction, rawHex, decryptedText) {
        // Remove placeholder
        const placeholder = snifferLog.querySelector('.sniffer-placeholder');
        if (placeholder) {
            placeholder.remove();
        }

        const timestamp = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = 'sniffer-entry';

        const isSent = direction === 'sent';
        const directionText = isSent ? 'TX (SENT)' : 'RX (RECV)';
        const metaClass = isSent ? 'sent' : 'recv';

        entry.innerHTML = `
            <div class="sniffer-meta ${metaClass}">
                [${timestamp}] ${directionText}
            </div>
            <div class="sniffer-cipher">
                Raw Ciphertext: ${rawHex}
            </div>
            <div class="sniffer-plain">
                Decrypted Plaintext: "${decryptedText}"
            </div>
        `;

        snifferLog.appendChild(entry);
        snifferLog.scrollTop = snifferLog.scrollHeight;
    }

    // --- Handshake steps mapping ---
    let handshakeSteps = [];

    function addHandshakeStep(id, text) {
        // Mark previous active step as completed
        const activeStep = handshakeStepsList.querySelector('.handshake-step-item.active');
        if (activeStep) {
            activeStep.className = 'handshake-step-item completed';
            activeStep.querySelector('.step-icon').setAttribute('data-lucide', 'check-circle-2');
        }

        // Create new active step
        const item = document.createElement('div');
        item.className = 'handshake-step-item active';
        item.id = `step-${id}`;
        item.innerHTML = `
            <i data-lucide="loader" class="step-icon"></i>
            <span>${text}</span>
        `;
        handshakeStepsList.appendChild(item);
        lucide.createIcons();
        handshakeStepsList.scrollTop = handshakeStepsList.scrollHeight;
    }

    // --- Connect & Handshake Emit ---
    loginBtn.addEventListener('click', performLogin);
    usernameInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            performLogin();
        }
    });

    function performLogin() {
        const username = usernameInput.value.trim();
        const protocolEl = document.querySelector('input[name="protocol"]:checked');
        const protocol = protocolEl ? protocolEl.value : 'aes_rsa';

        if (!username) {
            loginError.textContent = "Please enter a username.";
            loginError.style.display = 'block';
            return;
        }

        currentUsername = username;
        activeProtocol = protocol;
        loginError.style.display = 'none';

        // Clear previous handshake steps
        handshakeStepsList.innerHTML = "";
        handshakeOverlay.style.display = 'flex';

        // Connect/Re-connect socket if needed
        if (!socket.connected) {
            socket.connect();
        }

        // Emit Join
        socket.emit('join_chat', {
            username: username,
            protocol: protocol
        });
    }

    // --- Socket Event Listeners ---

    socket.on('handshake_step', (data) => {
        addHandshakeStep(data.step, data.text);
    });

    socket.on('handshake_error', (data) => {
        handshakeOverlay.style.display = 'none';
        loginError.textContent = data.message;
        loginError.style.display = 'block';
    });

    socket.on('handshake_complete', (data) => {
        // Complete last step
        const activeStep = handshakeStepsList.querySelector('.handshake-step-item.active');
        if (activeStep) {
            activeStep.className = 'handshake-step-item completed';
            activeStep.querySelector('.step-icon').setAttribute('data-lucide', 'check-circle-2');
        }

        // Update security panel
        currentAesKey = data.aes_key;
        inspectorProtocolName.textContent = data.protocol_name;
        
        const isRsa = activeProtocol === 'aes_rsa';
        inspectorSocketPort.textContent = isRsa ? '12345' : '12346';
        
        clientPubDisplay.textContent = data.client_pub;
        serverPubDisplay.textContent = data.server_pub;
        clientPrivDisplay.textContent = data.client_priv;

        // Shared secret for DH
        if (data.shared_secret) {
            dhInfoCard.style.display = 'block';
            dhSecretDisplay.textContent = data.shared_secret;
        } else {
            dhInfoCard.style.display = 'none';
        }

        // Reset visibility toggle
        isAesKeyVisible = false;
        aesKeyDisplay.classList.add('hidden-key');
        aesKeyDisplay.textContent = "--------------------------------";
        aesEyeIcon.setAttribute('data-lucide', 'eye');

        // Heading texts
        currentHeading.textContent = currentUsername;
        roomTitle.textContent = isRsa ? 'AES-RSA Channel' : 'DH-AES Channel';
        chatHeaderTitle.textContent = isRsa ? 'AES-RSA Secure Group' : 'DH-AES Secure Group';
        activeProtocolBadge.textContent = isRsa ? 'AES-128-RSA' : 'DH-AES-128';

        // Display dashboard
        setTimeout(() => {
            loginContainer.style.display = 'none';
            handshakeOverlay.style.display = 'none';
            appContainer.style.display = 'flex';
            
            // Dynamic heights update for accordion items
            document.querySelectorAll('.accordion-item').forEach(adjustAccordionHeight);
            
            // Scroll messages to bottom
            addStatusBubble("You joined the secure channel.");
            messagesWindow.scrollTop = messagesWindow.scrollHeight;
            lucide.createIcons();
        }, 800);
    });

    // --- Message Send Logic ---
    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    function sendMessage() {
        const text = messageInput.value.trim();
        if (!text) return;

        socket.emit('send_chat_message', { text: text });
        messageInput.value = "";
    }

    socket.on('message_sent', (data) => {
        const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        const row = document.createElement('div');
        row.className = 'message-row sent';
        row.innerHTML = `
            <div class="message-wrapper">
                <div class="message-bubble">
                    ${escapeHtml(data.text)}
                </div>
                <span class="message-time">${timestamp}</span>
            </div>
        `;
        chatMessages.appendChild(row);
        messagesWindow.scrollTop = messagesWindow.scrollHeight;

        // Sniffer log
        addSnifferLog('sent', data.raw_hex, currentUsername + ': ' + data.text);
    });

    socket.on('message_received', (data) => {
        const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        const row = document.createElement('div');
        row.className = 'message-row received';
        row.innerHTML = `
            <div class="message-wrapper">
                <span class="sender-tag">${escapeHtml(data.sender)}</span>
                <div class="message-bubble">
                    ${escapeHtml(data.text)}
                </div>
                <span class="message-time">${timestamp}</span>
            </div>
        `;
        chatMessages.appendChild(row);
        messagesWindow.scrollTop = messagesWindow.scrollHeight;

        // Sniffer log
        addSnifferLog('recv', data.raw_hex, data.sender + ': ' + data.text);
    });

    socket.on('status_message', (data) => {
        addStatusBubble(data.text);
        addSnifferLog('recv', data.raw_hex, "System: " + data.text);
    });

    // --- Disconnect / Connection Lost ---
    socket.on('connection_lost', () => {
        addStatusBubble("Secure TCP Socket connection was interrupted.");
    });

    function addStatusBubble(text) {
        const bubble = document.createElement('div');
        bubble.className = 'status-info-bubble';
        bubble.textContent = text;
        chatMessages.appendChild(bubble);
        messagesWindow.scrollTop = messagesWindow.scrollHeight;
    }

    // --- Log Out ---
    logoutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        socket.disconnect();
        
        // Reset app state
        chatMessages.innerHTML = "";
        snifferLog.innerHTML = `<div class="sniffer-placeholder">Waiting for socket activity...</div>`;
        usernameInput.value = "";
        
        appContainer.style.display = 'none';
        loginContainer.style.display = 'flex';
    });

    // Helper to escape HTML tags
    function escapeHtml(str) {
        return str.replace(/&/g, "&amp;")
                  .replace(/</g, "&lt;")
                  .replace(/>/g, "&gt;")
                  .replace(/"/g, "&quot;")
                  .replace(/'/g, "&#039;");
    }
});
