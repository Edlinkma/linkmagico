(function(window, document) {
    'use strict';

    // Prevent multiple initializations
    if (window.LinkMagicoWidget) {
        console.warn('LinkMagico Widget already initialized');
        return;
    }

    var LinkMagicoWidget = {
        version: '6.0.0',
        initialized: false,
        isOpen: false,
        messageCount: 0,
        conversationId: null,

        // Default configuration
        config: {
            position: 'bottom-right',
            primaryColor: '#667eea',
            secondaryColor: '#764ba2',
            successColor: '#10b981',
            robotName: 'Assistente IA',
            salesUrl: '',
            instructions: '',
            apiBase: window.location.origin,
            showBadge: true,
            autoOpen: false,
            openDelay: 5000,
            theme: 'light', // 'light' or 'dark'
            language: 'pt-BR',
            welcomeMessage: 'Olá! 👋 Como posso te ajudar hoje?',
            placeholder: 'Digite sua pergunta...',
            buttonIcon: 'fas fa-comments',
            zIndex: 999999,
            maxMessages: 50,
            typingDelay: 1000,
            animationSpeed: 300,
            mobileBreakpoint: 768,
            // Customization options
            borderRadius: '24px',
            boxShadow: '0 8px 32px rgba(0,0,0,0.12)',
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif'
        },

        // Initialize the widget
        init: function(userConfig) {
            if (this.initialized) {
                console.warn('LinkMagico Widget already initialized');
                return;
            }

            try {
                // Merge user configuration
                this.config = this.mergeConfig(this.config, userConfig || {});

                // Generate conversation ID
                this.conversationId = 'widget_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);

                // Wait for DOM to be ready
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', this.createWidget.bind(this));
                } else {
                    this.createWidget();
                }

                this.initialized = true;
                this.log('LinkMagico Widget v' + this.version + ' initialized');

            } catch (error) {
                console.error('LinkMagico Widget initialization failed:', error);
            }
        },

        // Deep merge configuration objects
        mergeConfig: function(defaultConfig, userConfig) {
            var merged = {};

            for (var key in defaultConfig) {
                merged[key] = defaultConfig[key];
            }

            for (var key in userConfig) {
                if (userConfig.hasOwnProperty(key)) {
                    merged[key] = userConfig[key];
                }
            }

            return merged;
        },

        // Create the widget HTML structure
        createWidget: function() {
            try {
                // Create main container
                var container = document.createElement('div');
                container.id = 'linkmagico-widget';
                container.className = 'lm-widget-container';

                // Create widget HTML
                container.innerHTML = this.getWidgetHTML();

                // Add widget styles
                this.injectStyles();

                // Append to body
                document.body.appendChild(container);

                // Bind events
                this.bindEvents();

                // Auto-open if configured
                if (this.config.autoOpen) {
                    setTimeout(this.openChat.bind(this), this.config.openDelay);
                }

                // Announce widget ready
                this.dispatchEvent('widgetReady');

            } catch (error) {
                console.error('LinkMagico Widget creation failed:', error);
            }
        },

        // Generate widget HTML
        getWidgetHTML: function() {
            var position = this.config.position;
            var positionClass = 'lm-position-' + position;

            return `
                <div class="lm-widget-button ${positionClass}" id="lm-widget-button">
                    <i class="${this.config.buttonIcon}"></i>
                    ${this.config.showBadge ? '<span class="lm-widget-badge" id="lm-widget-badge">1</span>' : ''}
                </div>

                <div class="lm-widget-chat ${positionClass}" id="lm-widget-chat">
                    <div class="lm-chat-header">
                        <div class="lm-chat-info">
                            <div class="lm-chat-avatar">
                                <i class="fas fa-robot"></i>
                            </div>
                            <div class="lm-chat-details">
                                <div class="lm-chat-title">${this.escapeHtml(this.config.robotName)}</div>
                                <div class="lm-chat-status">
                                    <span class="lm-status-dot"></span>
                                    <span class="lm-status-text">Online</span>
                                </div>
                            </div>
                        </div>
                        <div class="lm-chat-actions">
                            <button class="lm-chat-minimize" id="lm-chat-minimize" title="Minimizar">
                                <i class="fas fa-minus"></i>
                            </button>
                            <button class="lm-chat-close" id="lm-chat-close" title="Fechar">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    </div>

                    <div class="lm-chat-messages" id="lm-chat-messages">
                        <div class="lm-message lm-bot-message lm-welcome-message">
                            <div class="lm-message-avatar">
                                <i class="fas fa-robot"></i>
                            </div>
                            <div class="lm-message-content">
                                ${this.escapeHtml(this.config.welcomeMessage)}
                            </div>
                        </div>
                    </div>

                    <div class="lm-typing-indicator" id="lm-typing-indicator">
                        <div class="lm-typing-avatar">
                            <i class="fas fa-robot"></i>
                        </div>
                        <div class="lm-typing-content">
                            <div class="lm-typing-dots">
                                <span></span>
                                <span></span>
                                <span></span>
                            </div>
                            <span class="lm-typing-text">Digitando...</span>
                        </div>
                    </div>

                    <div class="lm-chat-input">
                        <div class="lm-input-group">
                            <textarea 
                                id="lm-message-input" 
                                class="lm-message-input"
                                placeholder="${this.escapeHtml(this.config.placeholder)}"
                                maxlength="500"
                                rows="1"></textarea>
                            <button id="lm-send-button" class="lm-send-button" title="Enviar">
                                <i class="fas fa-paper-plane"></i>
                            </button>
                        </div>
                        <div class="lm-input-footer">
                            <div class="lm-char-counter">
                                <span id="lm-char-count">0</span>/500
                            </div>
                            <div class="lm-powered-by">
                                Powered by <strong>LinkMágico</strong>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="lm-widget-overlay" id="lm-widget-overlay"></div>
            `;
        },

        // Inject CSS styles
        injectStyles: function() {
            if (document.getElementById('linkmagico-widget-styles')) {
                return; // Styles already injected
            }

            var styles = document.createElement('style');
            styles.id = 'linkmagico-widget-styles';
            styles.textContent = this.getWidgetCSS();
            document.head.appendChild(styles);
        },

        // Generate widget CSS
        getWidgetCSS: function() {
            var config = this.config;
            var primaryColor = config.primaryColor;
            var secondaryColor = config.secondaryColor;
            var successColor = config.successColor;
            var isDark = config.theme === 'dark';
            var isMobile = window.innerWidth <= config.mobileBreakpoint;

            return `
                /* LinkMagico Widget Styles v${this.version} */
                .lm-widget-container {
                    position: fixed;
                    z-index: ${config.zIndex};
                    font-family: ${config.fontFamily};
                    font-size: 14px;
                    line-height: 1.4;
                    color: #333;
                    box-sizing: border-box;
                }

                .lm-widget-container *,
                .lm-widget-container *::before,
                .lm-widget-container *::after {
                    box-sizing: border-box;
                }

                /* Position variants */
                .lm-position-bottom-right {
                    bottom: 20px;
                    right: 20px;
                }

                .lm-position-bottom-left {
                    bottom: 20px;
                    left: 20px;
                }

                .lm-position-top-right {
                    top: 20px;
                    right: 20px;
                }

                .lm-position-top-left {
                    top: 20px;
                    left: 20px;
                }

                /* Widget button */
                .lm-widget-button {
                    width: 64px;
                    height: 64px;
                    background: linear-gradient(135deg, ${primaryColor}
, ${secondaryColor});
                    border-radius: 50%;
                    display: flex; /* Widget button */
                .lm-widget-button {
                    width: 64px;
                    height: 64px;
                    background: linear-gradient(135deg, ${primaryColor}, ${secondaryColor});
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-size: 24px;
                    cursor: pointer;
                    box-shadow: ${config.boxShadow};
                    transition: all ${config.animationSpeed}ms ease;
                    position: relative;
                    border: none;
                    outline: none;
                }

                .lm-widget-button:hover {
                    transform: scale(1.05);
                    box-shadow: 0 12px 40px rgba(0,0,0,0.2);
                }

                .lm-widget-button:active {
                    transform: scale(0.95);
                }

                .lm-widget-badge {
                    position: absolute;
                    top: -6px;
                    right: -6px;
                    background: #ff4757;
                    color: white;
                    border-radius: 50%;
                    width: 24px;
                    height: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 12px;
                    font-weight: bold;
                    animation: lm-pulse 2s infinite;
                }

                @keyframes lm-pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.1); }
                }

                /* Chat window */
                .lm-widget-chat {
                    position: absolute;
                    width: 380px;
                    height: 550px;
                    background: ${isDark ? '#1f2937' : 'white'};
                    border-radius: ${config.borderRadius};
                    box-shadow: ${config.boxShadow};
                    display: none;
                    flex-direction: column;
                    overflow: hidden;
                    transform: scale(0.8) translateY(20px);
                    opacity: 0;
                    transition: all ${config.animationSpeed}ms ease;
                }

                .lm-widget-chat.lm-position-bottom-right,
                .lm-widget-chat.lm-position-bottom-left {
                    bottom: 84px;
                }

                .lm-widget-chat.lm-position-top-right,
                .lm-widget-chat.lm-position-top-left {
                    top: 84px;
                }

                .lm-widget-chat.lm-position-bottom-left,
                .lm-widget-chat.lm-position-top-left {
                    left: 0;
                }

                .lm-widget-chat.lm-position-bottom-right,
                .lm-widget-chat.lm-position-top-right {
                    right: 0;
                }

                .lm-widget-chat.lm-chat-open {
                    display: flex;
                    transform: scale(1) translateY(0);
                    opacity: 1;
                }

                /* Mobile responsive */
                @media (max-width: ${config.mobileBreakpoint}px) {
                    .lm-widget-chat {
                        position: fixed !important;
                        top: 0 !important;
                        left: 0 !important;
                        right: 0 !important;
                        bottom: 0 !important;
                        width: 100% !important;
                        height: 100% !important;
                        border-radius: 0 !important;
                        transform: translateY(100%);
                    }

                    .lm-widget-chat.lm-chat-open {
                        transform: translateY(0);
                    }

                    .lm-widget-overlay {
                        display: block !important;
                    }
                }

                /* Chat header */
                .lm-chat-header {
                    background: linear-gradient(135deg, ${primaryColor}, ${secondaryColor});
                    color: white;
                    padding: 16px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }

                .lm-chat-info {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }

                .lm-chat-avatar {
                    width: 40px;
                    height: 40px;
                    background: rgba(255,255,255,0.2);
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 18px;
                }

                .lm-chat-title {
                    font-weight: 600;
                    font-size: 16px;
                    margin-bottom: 2px;
                }

                .lm-chat-status {
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    font-size: 12px;
                    opacity: 0.9;
                }

                .lm-status-dot {
                    width: 8px;
                    height: 8px;
                    background: ${successColor};
                    border-radius: 50%;
                    animation: lm-status-pulse 2s infinite;
                }

                @keyframes lm-status-pulse {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.5; }
                }

                .lm-chat-actions {
                    display: flex;
                    gap: 8px;
                }

                .lm-chat-minimize,
                .lm-chat-close {
                    background: rgba(255,255,255,0.1);
                    border: none;
                    color: white;
                    width: 32px;
                    height: 32px;
                    border-radius: 6px;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    transition: all 0.2s ease;
                }

                .lm-chat-minimize:hover,
                .lm-chat-close:hover {
                    background: rgba(255,255,255,0.2);
                }

                /* Messages area */
                .lm-chat-messages {
                    flex: 1;
                    padding: 20px;
                    overflow-y: auto;
                    background: ${isDark ? '#111827' : 'linear-gradient(to bottom, #f9fafb, white)'};
                    display: flex;
                    flex-direction: column;
                    gap: 16px;
                }

                .lm-chat-messages::-webkit-scrollbar {
                    width: 6px;
                }

                .lm-chat-messages::-webkit-scrollbar-track {
                    background: transparent;
                }

                .lm-chat-messages::-webkit-scrollbar-thumb {
                    background: rgba(0,0,0,0.1);
                    border-radius: 3px;
                }

                .lm-message {
                    display: flex;
                    align-items: flex-end;
                    gap: 10px;
                    max-width: 85%;
                    animation: lm-message-appear 0.3s ease;
                }

                @keyframes lm-message-appear {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }

                .lm-user-message {
                    align-self: flex-end;
                    flex-direction: row-reverse;
                }

                .lm-bot-message {
                    align-self: flex-start;
                }

                .lm-message-avatar {
                    width: 32px;
                    height: 32px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 14px;
                    color: white;
                    flex-shrink: 0;
                }

                .lm-bot-message .lm-message-avatar {
                    background: linear-gradient(135deg, ${primaryColor}, ${secondaryColor});
                }

                .lm-user-message .lm-message-avatar {
                    background: linear-gradient(135deg, ${successColor}, #059669);
                }

                .lm-message-content {
                    padding: 12px 16px;
                    border-radius: 18px;
                    font-size: 14px;
                    line-height: 1.5;
                    word-wrap: break-word;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    position: relative;
                }

                .lm-user-message .lm-message-content {
                    background: linear-gradient(135deg, ${primaryColor}, ${secondaryColor});
                    color: white;
                }

                .lm-bot-message .lm-message-content {
                    background: ${isDark ? '#374151' : 'white'};
                    color: ${isDark ? '#e5e7eb' : '#374151'};
                    border: 1px solid ${isDark ? '#4b5563' : '#e5e7eb'};
                }

                /* CTA buttons in messages */
                .lm-cta-button {
                    display: inline-block;
                    background: ${successColor};
                    color: white;
                    padding: 8px 16px;
                    border-radius: 20px;
                    text-decoration: none;
                    font-weight: 600;
                    font-size: 13px;
                    margin-top: 8px;
                    transition: all 0.3s ease;
                    box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
                }

                .lm-cta-button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 16px rgba(16, 185, 129, 0.4);
                    text-decoration: none;
                    color: white;
                }

                /* Typing indicator */
                .lm-typing-indicator {
                    display: none;
                    padding: 0 20px 16px;
                    align-items: flex-end;
                    gap: 10px;
                }

                .lm-typing-avatar {
                    width: 32px;
                    height: 32px;
                    background: linear-gradient(135deg, ${primaryColor}, ${secondaryColor});
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 14px;
                    color: white;
                    flex-shrink: 0;
                }

                .lm-typing-content {
                    background: ${isDark ? '#374151' : 'white'};
                    border: 1px solid ${isDark ? '#4b5563' : '#e5e7eb'};
                    padding: 12px 16px;
                    border-radius: 18px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }

                .lm-typing-dots {
                    display: flex;
                    gap: 4px;
                }

                .lm-typing-dots span {
                    width: 6px;
                    height: 6px;
                    background: ${primaryColor};
                    border-radius: 50%;
                    animation: lm-typing 1.4s infinite ease-in-out;
                }

                .lm-typing-dots span:nth-child(1) { animation-delay: -0.32s; }
                .lm-typing-dots span:nth-child(2) { animation-delay: -0.16s; }
                .lm-typing-dots span:nth-child(3) { animation-delay: 0s; }

                @keyframes lm-typing {
                    0%, 80%, 100% {
                        transform: scale(0.8);
                        opacity: 0.5;
                    }
                    40% {
                        transform: scale(1.2);
                        opacity: 1;
                    }
                }

                .lm-typing-text {
                    font-size: 12px;
                    color: ${isDark ? '#9ca3af' : '#6b7280'};
                    font-style: italic;
                }

                /* Chat input */
                .lm-chat-input {
                    padding: 16px 20px;
                    background: ${isDark ? '#1f2937' : 'white'};
                    border-top: 1px solid ${isDark ? '#374151' : '#e5e7eb'};
                }

                .lm-input-group {
                    display: flex;
                    gap: 12px;
                    align-items: flex-end;
                }

                .lm-message-input {
                    flex: 1;
                    min-height: 44px;
                    max-height: 120px;
                    padding: 12px 16px;
                    border: 2px solid ${isDark ? '#374151' : '#e5e7eb'};
                    border-radius: 22px;
                    font-size: 14px;
                    line-height: 1.4;
                    font-family: inherit;
                    background: ${isDark ? '#374151' : '#f9fafb'};
                    color: ${isDark ? '#e5e7eb' : '#374151'};
                    resize: none;
                    outline: none;
                    transition: all 0.3s ease;
                }

                .lm-message-input:focus {
                    border-color: ${primaryColor};
                    background: ${isDark ? '#4b5563' : 'white'};
                    box-shadow: 0 0 0 3px ${primaryColor}20;
                }

                .lm-message-input::placeholder {
                    color: ${isDark ? '#9ca3af' : '#6b7280'};
                }

                .lm-send-button {
                    width: 44px;
                    height: 44px;
                    border: none;
                    border-radius: 50%;
                    background: linear-gradient(135deg, ${primaryColor}, ${secondaryColor});
                    color: white;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 16px;
                    transition: all 0.3s ease;
                    flex-shrink: 0;
                }

                .lm-send-button:hover:not(:disabled) {
                    transform: scale(1.05);
                    box-shadow: 0 4px 16px ${primaryColor}40;
                }

                .lm-send-button:disabled {
                    opacity: 0.5;
                    cursor: not-allowed;
                    transform: none;
                }

                .lm-input-footer {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-top: 8px;
                    font-size: 11px;
                    color: ${isDark ? '#6b7280' : '#9ca3af'};
                }

                .lm-char-counter {
                    font-variant-numeric: tabular-nums;
                }

                .lm-powered-by {
                    font-size: 10px;
                }

                /* Overlay for mobile */
                .lm-widget-overlay {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.5);
                    z-index: ${config.zIndex - 1};
                }

                /* Dark theme adjustments */
                ${isDark ? `
                .lm-widget-chat {
                    border: 1px solid #374151;
                }
                .lm-chat-messages {
                    background: linear-gradient(to bottom, #111827, #1f2937);
                }
                ` : ''}

                /* Accessibility */
                .lm-widget-button:focus,
                .lm-send-button:focus,
                .lm-message-input:focus,
                .lm-chat-minimize:focus,
                .lm-chat-close:focus {
                    outline: 2px solid ${primaryColor};
                    outline-offset: 2px;
                }

                /* High contrast mode */
                @media (prefers-contrast: high) {
                    .lm-message-content {
                        border: 2px solid currentColor;
                    }
                }

                /* Reduced motion */
                @media (prefers-reduced-motion: reduce) {
                    .lm-widget-chat,
                    .lm-widget-button,
                    .lm-message,
                    .lm-send-button,
                    .lm-chat-minimize,
                    .lm-chat-close {
                        transition: none;
                        animation: none;
                    }

                    .lm-widget-badge,
                    .lm-status-dot,
                    .lm-typing-dots span {
                        animation: none;
                    }
                }
            `;
        },

        // Bind all event listeners
        bindEvents: function() {
            var self = this;

            try {
                // Widget button click
                var button = document.getElementById('lm-widget-button');
                if (button) {
                    button.addEventListener('click', function() {
                        self.toggleChat();
                    });
                }

                // Close button
                var closeBtn = document.getElementById('lm-chat-close');
                if (closeBtn) {
                    closeBtn.addEventListener('click', function() {
                        self.closeChat();
                    });
                }

                // Minimize button
                var minimizeBtn = document.getElementById('lm-chat-minimize');
                if (minimizeBtn) {
                    minimizeBtn.addEventListener('click', function() {
                        self.minimizeChat();
                    });
                }

                // Send button
                var sendBtn = document.getElementById('lm-send-button');
                if (sendBtn) {
                    sendBtn.addEventListener('click', function() {
                        self.sendMessage();
                    });
                }

                // Input events
                var input = document.getElementById('lm-message-input');
                if (input) {
                    // Enter key to send
                    input.addEventListener('keydown', function(e) {
                        if (e.key === 'Enter' && !e.shiftKey) {
                            e.preventDefault();
                            self.sendMessage();
                        }
                    });

                    // Auto-resize textarea
                    input.addEventListener('input', function() {
                        self.autoResizeInput(this);
                        self.updateCharCounter(this);
                    });

                    // Focus handling
                    input.addEventListener('focus', function() {
                        self.hideBadge();
                    });
                }

                // Overlay click to close on mobile
                var overlay = document.getElementById('lm-widget-overlay');
                if (overlay) {
                    overlay.addEventListener('click', function() {
                        self.closeChat();
                    });
                }

                // Window resize handler
                window.addEventListener('resize', function() {
                    self.handleResize();
                });

                // Handle visibility change
                document.addEventListener('visibilitychange', function() {
                    if (!document.hidden && self.isOpen) {
                        self.hideBadge();
                    }
                });

            } catch (error) {
                console.error('LinkMagico Widget event binding failed:', error);
            }
        },

        // Toggle chat window
        toggleChat: function() {
            if (this.isOpen) {
                this.closeChat();
            } else {
                this.openChat();
            }
        },

        // Open chat window
        openChat: function() {
            try {
                var chat = document.getElementById('lm-widget-chat');
                var overlay = document.getElementById('lm-widget-overlay');

                if (chat) {
                    chat.classList.add('lm-chat-open');
                    this.isOpen = true;
                    this.hideBadge();

                    // Show overlay on mobile
                    if (this.isMobile()) {
                        overlay.style.display = 'block';
                    }

                    // Focus input after animation
                    setTimeout(function() {
                        var input = document.getElementById('lm-message-input');
                        if (input) {
                            input.focus();
                        }
                    }, this.config.animationSpeed);

                    this.dispatchEvent('chatOpened');
                }
            } catch (error) {
                console.error('Failed to open chat:', error);
            }
        },

        // Close chat window
        closeChat: function() {
            try {
                var chat = document.getElementById('lm-widget-chat');
                var overlay = document.getElementById('lm-widget-overlay');

                if (chat) {
                    chat.classList.remove('lm-chat-open');
                    this.isOpen = false;

                    if (overlay) {
                        overlay.style.display = 'none';
                    }

                    this.dispatchEvent('chatClosed');
                }
            } catch (error) {
                console.error('Failed to close chat:', error);
            }
        },

        // Minimize chat (same as close for now)
        minimizeChat: function() {
            this.closeChat();
        },

        // Send message
        sendMessage: function() {
            var input = document.getElementById('lm-message-input');
            var message = input ? input.value.trim() : '';

            if (!message) return;

            try {
                // Disable input during sending
                this.setInputState(false);

                // Add user message to chat
                this.addMessage(message, true);

                // Clear input
                input.value = '';
                this.autoResizeInput(input);
                this.updateCharCounter(input);

                // Show typing indicator
                this.showTyping();

                // Send to API
                this.callAPI(message);

            } catch (error) {
                console.error('Failed to send message:', error);
                this.setInputState(true);
                this.hideTyping();
            }
        },

        // Call the LinkMagico API
        callAPI: function(message) {
            var self = this;

            var payload = {
                message: message,
                robotName: this.config.robotName,
                instructions: this.config.instructions,
                salesUrl: this.config.salesUrl,
                conversationId: this.conversationId
            };

            // Add page data if available
            if (this.config.salesUrl) {
                payload.url = this.config.salesUrl;
            }

            fetch(this.config.apiBase + '/chat-universal', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            })
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('API request failed: ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                self.hideTyping();
                self.setInputState(true);

                if (data.success && data.response) {
                    self.addMessage(data.response, false);

                    // Handle bonuses if present
                    if (data.bonuses_detected && data.bonuses_detected.length > 0) {
                        var bonusText = "🎁 Bônus inclusos: " + data.bonuses_detected.slice(0, 3).join(", ");
                        setTimeout(function() {
                            self.addMessage(bonusText, false);
                        }, 500);
                    }
                } else {
                    self.addMessage('Desculpe, ocorreu um erro. Tente novamente.', false);
                }
            })
            .catch(function(error) {
                self.hideTyping();
                self.setInputState(true);
                self.log('API call failed:', error);
                self.addMessage('Erro de conexão. Tente novamente em instantes.', false);
            });
        },

        // Add message to chat
        addMessage: function(content, isUser) {
            try {
                var messagesContainer = document.getElementById('lm-chat-messages');
                if (!messagesContainer) return;

                // Limit message history
                this.limitMessages();

                var messageDiv = document.createElement('div');
                messageDiv.className = 'lm-message ' + (isUser ? 'lm-user-message' : 'lm-bot-message');

                var avatar = document.createElement('div');
                avatar.className = 'lm-message-avatar';
                avatar.innerHTML = isUser ? '<i class="fas fa-user"></i>' : '<i class="fas fa-robot"></i>';

                var contentDiv = document.createElement('div');
                contentDiv.className = 'lm-message-content';

                // Process content for URLs and CTAs
                if (!isUser && this.containsURL(content)) {
                    contentDiv.appendChild(this.processMessageContent(content));
                } else {
                    contentDiv.textContent = content;
                }

                messageDiv.appendChild(avatar);
                messageDiv.appendChild(contentDiv);
                messagesContainer.appendChild(messageDiv);

                // Scroll to bottom
                this.scrollToBottom();

                this.messageCount++;
                this.dispatchEvent('messageAdded', { content: content, isUser: isUser });

            } catch (error) {
                console.error('Failed to add message:', error);
            }
        },

        // Process message content with URLs
        processMessageContent: function(content) {
            var container = document.createElement('div');
            var urlRegex = /(https?:\/\/[^\s]+)/g;
            var parts = content.split(urlRegex);

            for (var i = 0; i < parts.length; i++) {
                var part = parts[i];

                if (urlRegex.test(part)) {
                    // Create CTA button for URL
                    var ctaLink = document.createElement('a');
                    ctaLink.href = part;
                    ctaLink.target = '_blank';
                    ctaLink.rel = 'noopener noreferrer';
                    ctaLink.className = 'lm-cta-button';
                    ctaLink.innerHTML = 'Quero me inscrever agora <i class="fas fa-external-link-alt"></i>';
                    container.appendChild(ctaLink);
                } else if (part.trim()) {
                    // Add text content
                    var textNode = document.createTextNode(part);
                    container.appendChild(textNode);
                    if (i < parts.length - 1) {
                        container.appendChild(document.createElement('br'));
                    }
                }
            }

            return container;
        },

        // Show typing indicator
        showTyping: function() {
            var typingIndicator = document.getElementById('lm-typing-indicator');
            if (typingIndicator) {
                typingIndicator.style.display = 'flex';
                this.scrollToBottom();
            }
        },

        // Hide typing indicator
        hideTyping: function() {
            var typingIndicator = document.getElementById('lm-typing-indicator');
            if (typingIndicator) {
                typingIndicator.style.display = 'none';
            }
        },

        // Utility functions
        autoResizeInput: function(input) {
            if (input) {
                input.style.height = 'auto';
                input.style.height = Math.min(input.scrollHeight, 120) + 'px';
            }
        },

        updateCharCounter: function(input) {
            var counter = document.getElementById('lm-char-count');
            if (counter && input) {
                counter.textContent = input.value.length;
            }
        },

        setInputState: function(enabled) {
            var input = document.getElementById('lm-message-input');
            var button = document.getElementById('lm-send-button');

            if (input) input.disabled = !enabled;
            if (button) button.disabled = !enabled;
        },

        scrollToBottom: function() {
            var messagesContainer = document.getElementById('lm-chat-messages');
            if (messagesContainer) {
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            }
        },

        hideBadge: function() {
            var badge = document.getElementById('lm-widget-badge');
            if (badge) {
                badge.style.display = 'none';
            }
        },

        limitMessages: function() {
            var messagesContainer = document.getElementById('lm-chat-messages');
            if (!messagesContainer) return;

            var messages = messagesContainer.querySelectorAll('.lm-message:not(.lm-welcome-message)');
            if (messages.length >= this.config.maxMessages) {
                // Remove oldest messages
                var toRemove = messages.length - this.config.maxMessages + 1;
                for (var i = 0; i < toRemove; i++) {
                    if (messages[i]) {
                        messages[i].remove();
                    }
                }
            }
        },

        containsURL: function(text) {
            return /https?:\/\/[^\s]+/.test(text);
        },

        isMobile: function() {
            return window.innerWidth <= this.config.mobileBreakpoint;
        },

        handleResize: function() {
            // Handle responsive behavior on resize
            if (this.isOpen && this.isMobile()) {
                var overlay = document.getElementById('lm-widget-overlay');
                if (overlay) {
                    overlay.style.display = 'block';
                }
            }
        },

        escapeHtml: function(text) {
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        log: function() {
            try {
                if (!this.config || !this.config.debug) return;
                var args = Array.prototype.slice.call(arguments);
                if (window && window.console && console.log) {
                    console.log.apply(console, args);
                }
            } catch (e) {
                // ignore logging errors
            }
        },
        ,

        // Event system
        dispatchEvent: function(eventName, data) {
            try {
                var event = new CustomEvent('linkmagico:' + eventName, {
                    detail: data || {}
                });
                window.dispatchEvent(event);
            } catch (error) {
                // Fallback for older browsers
                var event = document.createEvent('CustomEvent');
                event.initCustomEvent('linkmagico:' + eventName, false, false, data || {});
                window.dispatchEvent(event);
            }
        },

        // Public API methods
        open: function() {
            this.openChat();
        },

        close: function() {
            this.closeChat();
        },

        toggle: function() {
            this.toggleChat();
        },

        sendMessage: function(message) {
            if (message && typeof message === 'string') {
                var input = document.getElementById('lm-message-input');
                if (input) {
                    input.value = message;
                    this.sendMessage();
                }
            }
        },

        updateConfig: function(newConfig) {
            this.config = this.mergeConfig(this.config, newConfig);
            // Re-inject styles with new config
            var existingStyles = document.getElementById('linkmagico-widget-styles');
            if (existingStyles) {
                existingStyles.textContent = this.getWidgetCSS();
            }
        },

        destroy: function() {
            try {
                // Remove widget elements
                var container = document.getElementById('linkmagico-widget');
                if (container) {
                    container.remove();
                }

                // Remove styles
                var styles = document.getElementById('linkmagico-widget-styles');
                if (styles) {
                    styles.remove();
                }

                // Reset state
                this.initialized = false;
                this.isOpen = false;
                this.messageCount = 0;

                this.dispatchEvent('widgetDestroyed');

            } catch (error) {
                console.error('Failed to destroy widget:', error);
            }
        },

        // Get widget state
        getState: function() {
            return {
                initialized: this.initialized,
                isOpen: this.isOpen,
                messageCount: this.messageCount,
                conversationId: this.conversationId,
                version: this.version
            };
        }
    };

    // Expose widget to global scope
    window.LinkMagicoWidget = LinkMagicoWidget;

    // Auto-initialize if config is provided via data attributes
    document.addEventListener('DOMContentLoaded', function() {
        var scripts = document.querySelectorAll('script[data-linkmagico-config]');
        if (scripts.length > 0) {
            try {
                var configScript = scripts[0];
                var config = JSON.parse(configScript.getAttribute('data-linkmagico-config'));
                LinkMagicoWidget.init(config);
            } catch (error) {
                console.error('Failed to auto-initialize LinkMagico Widget:', error);
            }
        }
    });

    // AMD/CommonJS compatibility
    if (typeof define === 'function' && define.amd) {
        define(function() {
            return LinkMagicoWidget;
        });
    } else if (typeof module !== 'undefined' && module.exports) {
        module.exports = LinkMagicoWidget;
    }

})(window, document);
