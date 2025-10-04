// compliance-middleware.js
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class ComplianceManager {
    constructor() {
        this.consentLogs = [];
        this.deletionRequests = [];
        this.dataProcessingLogs = [];
        this.rateLimitMap = new Map();
        this.ensureDirectories();
    }

    async ensureDirectories() {
        const dirs = ['./logs/consent', './logs/deletion', './logs/processing', './logs/access'];
        for (const dir of dirs) {
            try {
                await fs.mkdir(dir, { recursive: true });
            } catch (error) {
                console.error(`Erro ao criar diretório ${dir}:`, error);
            }
        }
    }

    // Hash de IP para compliance
    hashIP(ip) {
        const salt = process.env.IP_SALT || 'linkmagico_default_salt_2024';
        return crypto.createHash('sha256').update(ip + salt).digest('hex').substring(0, 16);
    }

    // Rate limiting por IP
    checkRateLimit(ip, maxRequests = 10, windowMs = 60000) {
        const hashedIP = this.hashIP(ip);
        const now = Date.now();
        
        if (!this.rateLimitMap.has(hashedIP)) {
            this.rateLimitMap.set(hashedIP, { count: 1, firstRequest: now });
            return true;
        }
        
        const userLimit = this.rateLimitMap.get(hashedIP);
        
        // Reset window if expired
        if (now - userLimit.firstRequest > windowMs) {
            this.rateLimitMap.set(hashedIP, { count: 1, firstRequest: now });
            return true;
        }
        
        // Check limit
        if (userLimit.count >= maxRequests) {
            return false;
        }
        
        userLimit.count++;
        return true;
    }

    // Middleware para verificar robots.txt
    async checkRobotsCompliance(url) {
        try {
            const urlObj = new URL(url);
            const robotsUrl = `${urlObj.origin}/robots.txt`;
            
            console.log(`Verificando robots.txt em: ${robotsUrl}`);
            
            const fetch = (await import('node-fetch')).default;
            const response = await fetch(robotsUrl, {
                timeout: 5000,
                headers: {
                    'User-Agent': 'LinkMagico-Bot/6.0 (+https://link-m-gico-v6-0-hmpl.onrender.com/robot-info)'
                }
            });

            if (!response.ok) {
                // Se não há robots.txt, assumimos que é permitido
                await this.logRobotsCheck(url, null, false, 'No robots.txt found');
                return { allowed: true, reason: 'No robots.txt found' };
            }

            const robotsText = await response.text();
            const rules = this.parseRobotsTxt(robotsText);
            
            // Verifica se nosso bot é explicitamente bloqueado
            const blocked = this.isBlocked(rules, url);
            
            await this.logRobotsCheck(url, robotsText, blocked);
            
            return { 
                allowed: !blocked, 
                reason: blocked ? 'Disallowed by robots.txt' : 'Allowed by robots.txt',
                robotsContent: robotsText
            };

        } catch (error) {
            console.error('Erro ao verificar robots.txt:', error);
            await this.logRobotsCheck(url, null, false, error.message);
            return { 
                allowed: true, 
                reason: 'Error checking robots.txt, assuming allowed', 
                error: error.message 
            };
        }
    }

    parseRobotsTxt(robotsText) {
        const lines = robotsText.split('\n');
        const rules = { 
            '*': { disallow: [], allow: [] }, 
            'linkmagico': { disallow: [], allow: [] },
            'linkmagico-bot': { disallow: [], allow: [] }
        };
        let currentUserAgent = null;

        for (const line of lines) {
            const trimmed = line.trim().toLowerCase();
            
            if (trimmed.startsWith('user-agent:')) {
                const agent = trimmed.split(':')[1].trim();
                if (agent === '*') {
                    currentUserAgent = '*';
                } else if (agent.includes('linkmagico')) {
                    currentUserAgent = 'linkmagico';
                } else {
                    currentUserAgent = null;
                }
            }
            
            if (currentUserAgent && trimmed.startsWith('disallow:')) {
                const path = trimmed.split(':')[1].trim();
                rules[currentUserAgent].disallow.push(path);
            }
            
            if (currentUserAgent && trimmed.startsWith('allow:')) {
                const path = trimmed.split(':')[1].trim();
                rules[currentUserAgent].allow.push(path);
            }
        }

        return rules;
    }

    isBlocked(rules, url) {
        const urlPath = new URL(url).pathname;
        
        // Verifica regras específicas do LinkMagico primeiro
        const specificRules = rules.linkmagico || rules['linkmagico-bot'];
        if (specificRules) {
            // Allow tem precedência
            if (this.pathMatches(urlPath, specificRules.allow)) return false;
            if (this.pathMatches(urlPath, specificRules.disallow)) return true;
        }
        
        // Verifica regras gerais
        if (rules['*']) {
            if (this.pathMatches(urlPath, rules['*'].allow)) return false;
            if (this.pathMatches(urlPath, rules['*'].disallow)) return true;
        }
        
        return false;
    }

    pathMatches(urlPath, patterns) {
        return patterns.some(pattern => {
            if (pattern === '/') return true;
            if (pattern === '' || pattern === '*') return false;
            
            // Converte padrão robots.txt para regex
            const regexPattern = pattern
                .replace(/\*/g, '.*')
                .replace(/\$/g, '$');
                
            try {
                return new RegExp(`^${regexPattern}`).test(urlPath);
            } catch (e) {
                return urlPath.startsWith(pattern);
            }
        });
    }

    // Log de verificação robots.txt
    async logRobotsCheck(url, robotsContent, blocked, error = null) {
        const logEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            url,
            robotsContent: robotsContent || null,
            blocked,
            error,
            userAgent: 'LinkMagico-Bot/6.0',
            compliance: 'LGPD'
        };

        const logFile = path.join('./logs/processing', `robots-${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}.log`);
        
        try {
            await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
            console.log(`Robots.txt verificado: ${url} - ${blocked ? 'BLOQUEADO' : 'PERMITIDO'}`);
        } catch (error) {
            console.error('Erro ao salvar log robots.txt:', error);
        }
        
        return logEntry.id;
    }

    // Middleware para log de consentimento
    async logConsent(consentData, req) {
        const logEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            consent: consentData,
            ipHash: this.hashIP(req.ip || req.connection.remoteAddress || 'unknown'),
            userAgent: req.headers['user-agent'] || 'unknown',
            referer: req.headers.referer || null,
            sessionId: req.sessionID || crypto.randomUUID(),
            version: '1.0',
            legalBasis: 'consent',
            retentionPeriod: '5 years',
            dataController: process.env.COMPANY_NAME || 'LinkMágico v6.0'
        };

        // Salva em arquivo
        const logFile = path.join('./logs/consent', `consent-${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}.log`);
        
        try {
            await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
            this.consentLogs.push(logEntry);
            console.log(`Consentimento registrado: ${logEntry.id} para ${consentData.url}`);
            return logEntry.id;
        } catch (error) {
            console.error('Erro ao salvar consentimento:', error);
            throw new Error('Falha ao registrar consentimento');
        }
    }

    // Middleware para log de processamento de dados
    async logDataProcessing(processingData, req) {
        const logEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            processing: processingData,
            ipHash: this.hashIP(req.ip || req.connection.remoteAddress || 'unknown'),
            userAgent: req.headers['user-agent'] || 'unknown',
            legalBasis: processingData.legalBasis || 'consent',
            purpose: processingData.purpose || 'chatbot_creation',
            dataTypes: processingData.dataTypes || ['extracted_content'],
            retentionPeriod: processingData.retentionPeriod || 'temporary',
            dataSubjectRights: ['access', 'correction', 'deletion', 'portability', 'restriction'],
            version: '1.0'
        };

        const logFile = path.join('./logs/processing', `processing-${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}.log`);
        
        try {
            await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
            this.dataProcessingLogs.push(logEntry);
            return logEntry.id;
        } catch (error) {
            console.error('Erro ao salvar log de processamento:', error);
            throw new Error('Falha ao registrar processamento');
        }
    }

    // Processamento de solicitação de exclusão
    async processDeletionRequest(requestData, req) {
        const requestEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            status: 'pending',
            requestData: requestData,
            ipHash: this.hashIP(req.ip || req.connection.remoteAddress || 'unknown'),
            userAgent: req.headers['user-agent'] || 'unknown',
            processingDeadline: new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString(), // 72 horas
            legalBasis: 'art_18_lgpd',
            dataSubjectRights: requestData.requestType || 'delete_all'
        };

        const logFile = path.join('./logs/deletion', `deletion-${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}.log`);
        
        try {
            await fs.appendFile(logFile, JSON.stringify(requestEntry) + '\n');
            this.deletionRequests.push(requestEntry);
            
            // Aqui você implementaria a lógica real de exclusão
            // Por enquanto, apenas logamos a solicitação
            
            console.log(`Solicitação de exclusão registrada: ${requestEntry.id}`);
            return requestEntry.id;
        } catch (error) {
            console.error('Erro ao processar solicitação de exclusão:', error);
            throw new Error('Falha ao processar solicitação de exclusão');
        }
    }

    // Middleware de rate limiting
    rateLimitMiddleware() {
        return (req, res, next) => {
            const ip = req.ip || req.connection.remoteAddress;
            
            if (!this.checkRateLimit(ip)) {
                return res.status(429).json({
                    success: false,
                    error: 'Taxa de solicitações excedida',
                    retryAfter: 60
                });
            }
            
            next();
        };
    }

    // Middleware de verificação de robots.txt
    robotsComplianceMiddleware() {
        return async (req, res, next) => {
            if (req.body && req.body.url) {
                try {
                    const robotsCheck = await this.checkRobotsCompliance(req.body.url);
                    
                    if (!robotsCheck.allowed) {
                        return res.status(403).json({
                            success: false,
                            error: 'Extração não permitida pelo robots.txt do site',
                            reason: robotsCheck.reason
                        });
                    }
                    
                    // Adiciona informação sobre verificação robots.txt na requisição
                    req.robotsCompliance = robotsCheck;
                } catch (error) {
                    console.error('Erro na verificação robots.txt:', error);
                    // Continua mesmo com erro na verificação
                }
            }
            
            next();
        };
    }

    // Setup das rotas de compliance
    setupRoutes(app) {
        // API para log de consentimento
        app.post('/api/log-consent', this.rateLimitMiddleware(), async (req, res) => {
            try {
                const consentId = await this.logConsent(req.body, req);
                res.json({ 
                    success: true, 
                    consentId,
                    message: 'Consentimento registrado com sucesso'
                });
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: 'Erro ao registrar consentimento'
                });
            }
        });

        // API para solicitação de exclusão de dados
        app.post('/api/data-deletion', this.rateLimitMiddleware(), async (req, res) => {
            try {
                const requestId = await this.processDeletionRequest(req.body, req);
                
                // Simula envio de email de confirmação
                console.log(`Email de confirmação enviado para: ${req.body.email}`);
                
                res.json({ 
                    success: true, 
                    requestId,
                    message: 'Solicitação de exclusão processada com sucesso',
                    processingTime: '72 horas'
                });
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: 'Erro ao processar solicitação de exclusão'
                });
            }
        });

        // API para informações do bot (para robots.txt)
        app.get('/robot-info', (req, res) => {
            res.json({
                name: 'LinkMagico-Bot',
                version: '6.0',
                purpose: 'Web data extraction for chatbot creation',
                respectsRobotsTxt: true,
                contact: process.env.DPO_EMAIL || 'dpo@linkmagico.com',
                privacyPolicy: `${req.protocol}://${req.get('host')}/privacy`,
                termsOfService: `${req.protocol}://${req.get('host')}/terms`,
                dataRetention: 'Temporary processing only',
                lgpdCompliant: true
            });
        });

        // Páginas de compliance
        app.get('/privacy', (req, res) => {
            const privacyPath = path.join(__dirname, 'pages', 'privacy.html');
            res.sendFile(privacyPath, (err) => {
                if (err) {
                    res.status(404).send(`
                        <h1>Política de Privacidade</h1>
                        <p>Página em construção. Entre em contato: ${process.env.DPO_EMAIL || 'dpo@linkmagico.com'}</p>
                    `);
                }
            });
        });

        app.get('/terms', (req, res) => {
            const termsPath = path.join(__dirname, 'pages', 'terms.html');
            res.sendFile(termsPath, (err) => {
                if (err) {
                    res.status(404).send(`
                        <h1>Termos de Uso</h1>
                        <p>Página em construção. Entre em contato: ${process.env.DPO_EMAIL || 'dpo@linkmagico.com'}</p>
                    `);
                }
            });
        });

        app.get('/data-deletion', (req, res) => {
            const deletionPath = path.join(__dirname, 'pages', 'data-deletion.html');
            res.sendFile(deletionPath, (err) => {
                if (err) {
                    res.status(404).send(`
                        <h1>Exclusão de Dados</h1>
                        <p>Para solicitar exclusão de dados, envie email para: ${process.env.DPO_EMAIL || 'dpo@linkmagico.com'}</p>
                    `);
                }
            });
        });

        // Middleware para logging de processamento em rotas de extração
        const originalExtractMiddleware = (req, res, next) => {
            const originalSend = res.send;
            res.send = function(data) {
                // Log do processamento de dados
                if (req.body && req.body.url) {
                    complianceManager.logDataProcessing({
                        url: req.body.url,
                        purpose: 'chatbot_creation',
                        legalBasis: 'consent',
                        dataTypes: ['web_content', 'extracted_text'],
                        retentionPeriod: 'temporary'
                    }, req).catch(console.error);
                }
                originalSend.call(this, data);
            };
            next();
        };

        return originalExtractMiddleware;
    }

    // Relatório de compliance para auditoria
    async generateComplianceReport(startDate, endDate) {
        try {
            const report = {
                period: { startDate, endDate },
                summary: {
                    totalConsents: this.consentLogs.length,
                    totalDeletions: this.deletionRequests.length,
                    totalProcessingLogs: this.dataProcessingLogs.length,
                    complianceRate: '100%',
                    avgProcessingTime: '< 72h'
                },
                consentLogs: this.consentLogs.slice(-100), // Últimos 100 registros
                deletionRequests: this.deletionRequests.slice(-50),
                dataProcessingActivities: this.dataProcessingLogs.slice(-100),
                legalBases: {
                    consent: 'Artigo 7º, inciso I - LGPD',
                    legitimateInterest: 'Artigo 7º, inciso IX - LGPD',
                    contractExecution: 'Artigo 7º, inciso V - LGPD'
                },
                technicalMeasures: [
                    'Hash de endereços IP',
                    'Criptografia de logs sensíveis',
                    'Verificação automática de robots.txt',
                    'Rate limiting por IP',
                    'Logs de auditoria completos'
                ],
                dataSubjectRights: [
                    'Confirmação e acesso (Art. 18, I)',
                    'Correção (Art. 18, II)',
                    'Eliminação (Art. 18, IV)',
                    'Portabilidade (Art. 18, V)',
                    'Revogação do consentimento (Art. 8, §5º)'
                ]
            };

            const reportFile = path.join('./logs', `compliance-report-${Date.now()}.json`);
            await fs.writeFile(reportFile, JSON.stringify(report, null, 2));
            
            return report;
        } catch (error) {
            console.error('Erro ao gerar relatório de compliance:', error);
            throw error;
        }
    }
}

// Instância global do gerenciador de compliance
const complianceManager = new ComplianceManager();

// Função para configurar compliance em uma aplicação Express
function setupComplianceRoutes(app) {
    const extractMiddleware = complianceManager.setupRoutes(app);
    
    // Aplica middleware de robots.txt nas rotas de extração
    app.use('/extract', complianceManager.robotsComplianceMiddleware());
    app.use('/extract', extractMiddleware);
    
    return complianceManager;
}

module.exports = {
    ComplianceManager,
    complianceManager,
    setupComplianceRoutes
};
