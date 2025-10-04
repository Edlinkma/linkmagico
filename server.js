require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const winston = require("winston");
const axios = require("axios");
const cheerio = require("cheerio");
const path = require("path");
const fs = require("fs");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const session = require("express-session");

// Optional dependencies with graceful fallback
let puppeteer = null;
try {
    puppeteer = require("puppeteer");
    console.log("✅ Puppeteer loaded - Dynamic rendering available");
} catch (e) {
    console.log("⚠️ Puppeteer not installed - Using basic extraction only");
}

const app = express();

// Declarando conversationHistories no escopo global ou adequado
const conversationHistories = new Map();

// ===== Enhanced Logger =====
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Trust proxy for accurate IP addresses
app.set("trust proxy", true);

// ===== Session Configuration =====
app.use(session({
    secret: process.env.SESSION_SECRET || "linkmagico-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true in production with HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// ===== Middleware =====
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: ["https://linkmagico-comercial.onrender.com", "https://link-m-gico-v6-0-hmpl.onrender.com", "http://localhost:3000", "http://localhost:8080"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"]
}));

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(bodyParser.json({ limit: "10mb" }));

app.use(morgan("combined"));

// ===== API Key Validation Functions =====
function loadApiKeys() {
    try {
        // Primeiro, tenta carregar da variável de ambiente (para Render)
        if (process.env.API_KEYS_JSON) {
            logger.info("Loading API keys from environment variable");
            return JSON.parse(process.env.API_KEYS_JSON);
        }
        
        // Se não houver variável de ambiente, tenta carregar do arquivo
        const dataFile = path.join(__dirname, "data", "api_keys.json");
        if (fs.existsSync(dataFile)) {
            logger.info("Loading API keys from file");
            const raw = fs.readFileSync(dataFile, "utf8");
            return JSON.parse(raw);
        }
        
        logger.warn("No API keys found - neither in environment variable nor in file");
    } catch (error) {
        logger.error("Error loading API keys:", error.message);
    }
    return {};
}

function validateApiKey(apiKey) {
    const apiKeys = loadApiKeys();
    const keyData = apiKeys[apiKey];
    
    if (keyData && keyData.active !== false) {
        return {
            success: true,
            client: {
                nome: keyData.nome || "API Client",
                plano: keyData.plano || "basic",
                apiKey: apiKey
            }
        };
    }
    
    return { success: false };
}

// ===== API Key Middleware =====
function requireApiKey(req, res, next) {
    logger.info(`[requireApiKey] Path: ${req.path}, Session Validated: ${!!(req.session && req.session.validatedApiKey)}`);
    
    // Allow access to root and validation endpoint without API Key
    if (req.path === "/" || req.path === "/validate-api-key" || req.path.startsWith("/public/") || req.path === "/chat.html") {
        return next();
    }

    // Check if API key is already validated in session
    if (req.session && req.session.validatedApiKey) {
        req.cliente = req.session.clientData;
        return next();
    }

    // For all other routes, redirect to the validation page if no key is present
    return res.redirect("/");
}

// Apply API Key middleware to all routes
app.use(requireApiKey);

// ===== Static Files with API Key Protection =====
// Serve API key validation page without protection
app.get("/", (req, res) => {
    logger.info(`[GET /] Session Validated: ${!!(req.session && req.session.validatedApiKey)}`);
    // Check if API key is already validated
    if (req.session && req.session.validatedApiKey) {
        return res.redirect("/app");
    }
    res.sendFile(path.join(__dirname, "public", "api_key_validation.html"));
});

// API Key validation endpoint
app.post("/validate-api-key", (req, res) => {
    const { apiKey } = req.body;
    
    if (!apiKey) {
        return res.status(400).json({ 
            success: false, 
            error: "API Key é obrigatória" 
        });
    }

    const validation = validateApiKey(apiKey);
    if (!validation.success) {
        return res.status(401).json({ 
            success: false, 
            error: "API Key inválida" 
        });
    }

    // Store validated API key in session
    req.session.validatedApiKey = apiKey;
    req.session.clientData = validation.client;
    
    res.json({ 
        success: true, 
        message: "API Key validada com sucesso" 
    });
});

// Protected route for the main application
app.get("/app", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index_app.html"));
});

// Rotas para as páginas LGPD
app.get("/privacy.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "privacy.html"));
});

app.get("/excluir-dados", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "excluir-dados.html"));
});

// ROTA CHAT.HTML - Que o frontend espera
app.get("/chat.html", (req, res) => {
    const robotName = req.query.name || "Assistente IA";
    const url = req.query.url || "";
    const instructions = req.query.instructions || "";
    
    // Gera o HTML do chatbot dinamicamente
    const chatbotHTML = generateChatbotHTML({ robotName, url, instructions });
    res.send(chatbotHTML);
});

// Serve other static files from public directory
app.use("/public", express.static(path.join(__dirname, "public"), {
    maxAge: "1d",
    etag: true,
    lastModified: true
}));

// Serve static files from public directory
app.use(express.static("public", {
    maxAge: "1d",
    etag: true,
    lastModified: true
}));

// ===== Analytics & Cache =====
const analytics = {
    totalRequests: 0,
    chatRequests: 0,
    extractRequests: 0,
    errors: 0,
    activeChats: new Set(),
    startTime: Date.now(),
    responseTimeHistory: [],
    successfulExtractions: 0,
    failedExtractions: 0
};

app.use((req, res, next) => {
    const start = Date.now();
    analytics.totalRequests++;

    res.on("finish", () => {
        const responseTime = Date.now() - start;
        analytics.responseTimeHistory.push(responseTime);
        if (analytics.responseTimeHistory.length > 100) analytics.responseTimeHistory.shift();
        if (res.statusCode >= 400) analytics.errors++;
    });

    next();
});

const dataCache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes

function setCacheData(key, data) {
    dataCache.set(key, { data, timestamp: Date.now() });
}

function getCacheData(key) {
    const cached = dataCache.get(key);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
        return cached.data;
    }
    dataCache.delete(key);
    return null;
}

// ===== Utility functions =====
function normalizeText(text) {
    return (text || "").replace(/\s+/g, " ").trim();
}

function uniqueLines(text) {
    if (!text) return "";
    const seen = new Set();
    return text.split("\n")
        .map(line => line.trim())
        .filter(Boolean)
        .filter(line => {
            if (seen.has(line)) return false;
            seen.add(line);
            return true;
        })
        .join("\n");
}

function clampSentences(text, maxSentences = 2) {
    if (!text) return "";
    const sentences = normalizeText(text).split(/(?<=[.!?])\s+/);
    return sentences.slice(0, maxSentences).join(" ");
}

function extractBonuses(text) {
    if (!text) return [];
    const bonusKeywords = /(bônus|bonus|brinde|extra|grátis|template|planilha|checklist|e-book|ebook)/gi;
    const lines = String(text).split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const bonuses = [];

    for (const line of lines) {
        if (bonusKeywords.test(line) && line.length > 10 && line.length < 200) {
            bonuses.push(line);
            if (bonuses.length >= 5) break;
        }
    }
    return Array.from(new Set(bonuses));
}

// ===== Content extraction =====
function extractCleanTextFromHTML(html) {
    try {
        const $ = cheerio.load(html || "");
        $("script, style, noscript, iframe, nav, footer, aside").remove();

        const textBlocks = [];
        const selectors = ["h1", "h2", "h3", "p", "li", "span", "div"];

        for (const selector of selectors) {
            $(selector).each((i, element) => {
                const text = normalizeText($(element).text() || "");
                if (text && text.length > 15 && text.length < 1000) {
                    textBlocks.push(text);
                }
            });
        }

        const metaDesc = $("meta[name=\"description\"]").attr("content") ||
            $("meta[property=\"og:description\"]").attr("content") || "";
        if (metaDesc && metaDesc.trim().length > 20) {
            textBlocks.unshift(normalizeText(metaDesc.trim()));
        }

        const uniqueBlocks = [...new Set(textBlocks.map(b => b.trim()).filter(Boolean))];
        return uniqueBlocks.join("\n");
    } catch (error) {
        logger.warn("extractCleanTextFromHTML error:", error.message || error);
        return "";
    }
}

// ===== Page extraction =====
async function extractPageData(url) {
    const startTime = Date.now();
    try {
        if (!url) throw new Error("URL is required");

        const cacheKey = url;
        const cached = getCacheData(cacheKey);
        if (cached) {
            logger.info(`Cache hit for ${url}`);
            return cached;
        }
        
        logger.info(`Starting extraction for: ${url}`);

        const extractedData = {
            title: "",
            description: "",
            benefits: [],
            testimonials: [],
            cta: "",
            summary: "",
            cleanText: "",
            imagesText: [],
            url: url,
            extractionTime: 0,
            method: "unknown",
            bonuses_detected: [],
            price_detected: []
        };

        let html = "";
        try {
            logger.info("Attempting Axios + Cheerio extraction...");
            const response = await axios.get(url, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (compatible; LinkMagico-Bot/6.0; +https://linkmagico-comercial.onrender.com)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"
                },
                timeout: 15000,
                maxRedirects: 5,
                validateStatus: status => status >= 200 && status < 400
            });
            html = response.data || "";
            const finalUrl = response.request?.res?.responseUrl || url;
            if (finalUrl && finalUrl !== url) extractedData.url = finalUrl;
            extractedData.method = "axios-cheerio";
            logger.info(`Axios extraction successful, HTML length: ${String(html).length}`);
        } catch (axiosError) {
            logger.warn(`Axios extraction failed for ${url}: ${axiosError.message || axiosError}`);
        }

        if (html && html.length > 100) {
            try {
                const $ = cheerio.load(html);
                $("script, style, noscript, iframe").remove();

                // Title
                const titleSelectors = ["h1", "meta[property=\"og:title\"]", "meta[name=\"twitter:title\"]", "title"];
                for (const selector of titleSelectors) {
                    const el = $(selector).first();
                    const title = (el.attr && (el.attr("content") || el.text) ? (el.attr("content") || el.text()) : el.text ? el.text() : "").toString().trim();
                    if (title && title.length > 5 && title.length < 200) {
                        extractedData.title = title;
                        break;
                    }
                }

                // Description
                const descSelectors = ["meta[name=\"description\"]", "meta[property=\"og:description\"]", ".description", "article p", "main p"];
                for (const selector of descSelectors) {
                    const el = $(selector).first();
                    const desc = (el.attr && (el.attr("content") || el.text) ? (el.attr("content") || el.text()) : el.text ? el.text() : "").toString().trim();
                    if (desc && desc.length > 50 && desc.length < 1000) {
                        extractedData.description = desc;
                        break;
                    }
                }

                extractedData.cleanText = extractCleanTextFromHTML(html);

                const bodyText = $("body").text() || "";
                const summaryText = bodyText.replace(/\s+/g, " ").trim();
                const sentences = summaryText.split(/[.!?]+/).map(s => s.trim()).filter(Boolean);
                extractedData.summary = sentences.slice(0, 3).join(". ").substring(0, 400) + (sentences.length > 3 ? "..." : "");

                extractedData.bonuses_detected = extractBonuses(bodyText);

                logger.info(`Cheerio extraction completed for ${url}`);
                analytics.successfulExtractions++;
            } catch (cheerioError) {
                logger.warn(`Cheerio parsing failed: ${cheerioError.message || cheerioError}`);
                analytics.failedExtractions++;
            }
        }

        // Puppeteer fallback
        const minAcceptableLength = 200;
        if ((!extractedData.cleanText || extractedData.cleanText.length < minAcceptableLength) && puppeteer) {
            logger.info("Trying Puppeteer for dynamic rendering...");
            let browser = null;
            try {
                browser = await puppeteer.launch({
                    headless: true,
                    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
                    defaultViewport: { width: 1200, height: 800 },
                    timeout: 20000
                });
                const page = await browser.newPage();
                await page.setUserAgent("Mozilla/5.0 (compatible; LinkMagico-Bot/6.0)");
                await page.setRequestInterception(true);
                page.on("request", (req) => {
                    const rt = req.resourceType();
                    if (["stylesheet", "font", "image", "media"].includes(rt)) req.abort();
                    else req.continue();
                });

                try {
                    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
                } catch (gotoErr) {
                    logger.warn("Puppeteer goto failed:", gotoErr.message || gotoErr);
                }

                // Quick scroll for dynamic content
                try {
                    await page.evaluate(async () => {
                        await new Promise((resolve) => {
                            let totalHeight = 0;
                            const distance = 100;
                            const timer = setInterval(() => {
                                const scrollHeight = document.body.scrollHeight;
                                window.scrollBy(0, distance);
                                totalHeight += distance;

                                if (totalHeight >= scrollHeight || totalHeight > 3000) { // Limit scroll to 3000px
                                    clearInterval(timer);
                                    resolve();
                                }
                            }, 100);
                        });
                    });
                } catch (scrollErr) {
                    logger.warn("Puppeteer scroll failed:", scrollErr.message || scrollErr);
                }

                const content = await page.content();
                const puppeteerData = await page.evaluate(() => {
                    const metaDescription = document.querySelector("meta[name=\"description\"]")?.content ||
                                            document.querySelector("meta[property=\"og:description\"]")?.content || "";
                    const title = document.querySelector("title")?.textContent ||
                                  document.querySelector("h1")?.textContent || "";
                    return { metaDescription, title };
                });

                const finalText = extractCleanTextFromHTML(content);

                if (finalText && finalText.length > extractedData.cleanText.length) {
                    extractedData.cleanText = finalText;
                    extractedData.method = "puppeteer";
                    if (!extractedData.title && puppeteerData.title) extractedData.title = puppeteerData.title.slice(0, 200);
                    if (!extractedData.description && puppeteerData.metaDescription) extractedData.description = puppeteerData.metaDescription.slice(0, 500);
                    const sents = finalText.split(/[.!?]+/).map(s => s.trim()).filter(Boolean);
                    if (!extractedData.summary && sents.length) extractedData.summary = sents.slice(0, 3).join(". ").substring(0, 400) + (sents.length > 3 ? "..." : "");
                    extractedData.bonuses_detected = extractBonuses(finalText);
                    analytics.successfulExtractions++;
                }

            } catch (puppeteerErr) {
                logger.warn("Puppeteer extraction failed:", puppeteerErr.message || puppeteerErr);
                analytics.failedExtractions++;
            } finally {
                try { if (browser) await browser.close(); } catch (e) {}
            }
        }

        // Final processing
        try {
            if (extractedData.cleanText) extractedData.cleanText = uniqueLines(extractedData.cleanText);
            if (!extractedData.title && extractedData.cleanText) {
                const firstLine = extractedData.cleanText.split("\n").find(l => l && l.length > 10 && l.length < 150);
                if (firstLine) extractedData.title = firstLine.slice(0, 150);
            }
            if (!extractedData.summary && extractedData.cleanText) {
                const sents = extractedData.cleanText.split(/(?<=[.!?])\s+/).filter(Boolean);
                extractedData.summary = sents.slice(0, 3).join(". ").slice(0, 400) + (sents.length > 3 ? "..." : "");
            }
        } catch (procErr) {
            logger.warn("Final processing failed:", procErr.message || procErr);
        }

        extractedData.extractionTime = Date.now() - startTime;
        
        setCacheData(cacheKey, extractedData);
        logger.info(`Extraction completed for ${url} in ${extractedData.extractionTime}ms using ${extractedData.method}`);
        return extractedData;

    } catch (error) {
        analytics.failedExtractions++;
        logger.error(`Page extraction failed for ${url}:`, error.message || error);
        return {
            title: "",
            description: "",
            benefits: [],
            testimonials: [],
            cta: "",
            summary: "Erro ao extrair dados da página. Verifique se a URL está acessível.",
            cleanText: "",
            imagesText: [],
            url: url || "",
            extractionTime: Date.now() - startTime,
            method: "failed",
            error: error.message || String(error),
            bonuses_detected: [],
            price_detected: []
        };
    }
}

// ===== LLM Integration =====
async function callGroq(messages, temperature = 0.4, maxTokens = 300) {
    if (!process.env.GROQ_API_KEY) throw new Error("GROQ_API_KEY missing");

    const payload = {
        model: process.env.GROQ_MODEL || "llama-3.1-70b-versatile",
        messages,
        temperature,
        max_tokens: maxTokens
    };

    const url = process.env.GROQ_API_BASE || "https://api.groq.com/openai/v1/chat/completions";
    const headers = { "Authorization": `Bearer ${process.env.GROQ_API_KEY}`, "Content-Type": "application/json" };

    try {
        const response = await axios.post(url, payload, { headers });
        return response.data.choices[0].message.content;
    } catch (error) {
        logger.error("Groq API call failed:", error.response ? error.response.data : error.message);
        throw new Error("Failed to get response from Groq API");
    }
}

async function callOpenRouter(messages, temperature = 0.4, maxTokens = 300) {
    if (!process.env.OPENROUTER_API_KEY) throw new Error("OPENROUTER_API_KEY missing");

    const payload = {
        model: process.env.OPENROUTER_MODEL || "mistralai/mistral-7b-instruct",
        messages,
        temperature,
        max_tokens: maxTokens
    };

    const url = process.env.OPENROUTER_API_BASE || "https://openrouter.ai/api/v1/chat/completions";
    const headers = { "Authorization": `Bearer ${process.env.OPENROUTER_API_KEY}`, "Content-Type": "application/json" };

    try {
        const response = await axios.post(url, payload, { headers });
        return response.data.choices[0].message.content;
    } catch (error) {
        logger.error("OpenRouter API call failed:", error.response ? error.response.data : error.message);
        throw new Error("Failed to get response from OpenRouter API");
    }
}

async function callOpenAI(messages, temperature = 0.4, maxTokens = 300) {
    if (!process.env.OPENAI_API_KEY) throw new Error("OPENAI_API_KEY missing");

    const payload = {
        model: process.env.OPENAI_MODEL || "gpt-3.5-turbo",
        messages,
        temperature,
        max_tokens: maxTokens
    };

    const url = process.env.OPENAI_API_BASE || "https://api.openai.com/v1/chat/completions";
    const headers = { "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`, "Content-Type": "application/json" };

    try {
        const response = await axios.post(url, payload, { headers });
        return response.data.choices[0].message.content;
    } catch (error) {
        logger.error("OpenAI API call failed:", error.response ? error.response.data : error.message);
        throw new Error("Failed to get response from OpenAI API");
    }
}

// ===== AI Response Generation =====
const NOT_FOUND_MSG = "Desculpe, não encontrei informações específicas sobre isso. Posso ajudar com outras dúvidas?";

function shouldActivateSalesMode(instructions) {
    if (!instructions) return false;
    const salesKeywords = /(venda|vendas|compra|comprar|adquirir|produto|oferta|promoção|desconto)/i;
    return salesKeywords.test(instructions);
}

async function generateAIResponse(userMessage, pageData = {}, conversationHistory = [], instructions = "") {
    const startTime = Date.now();
    try {
        if (!userMessage || !String(userMessage).trim()) {
            return NOT_FOUND_MSG;
        }

        const messages = [
            {
                role: "system",
                content: `Você é um assistente de vendas inteligente. Use os dados da página: ${JSON.stringify(pageData)}. Instruções: ${instructions}. Seja útil e direto.`
            },
            ...conversationHistory,
            { role: "user", content: userMessage }
        ];

        let response = "";
        let usedProvider = "none";

        // Try Groq first
        if (process.env.GROQ_API_KEY) {
            try {
                response = await callGroq(messages, 0.4, 300);
                usedProvider = "groq";
                logger.info("Groq API call successful");
            } catch (groqError) {
                logger.warn(`Groq failed: ${groqError.message || groqError}`);
            }
        }

        // Try OpenRouter if Groq failed
        if (!response && process.env.OPENROUTER_API_KEY) {
            try {
                response = await callOpenRouter(messages, 0.3, 250);
                usedProvider = "openrouter";
                logger.info("OpenRouter API call successful");
            } catch (openrouterError) {
                logger.warn(`OpenRouter failed: ${openrouterError.message || openrouterError}`);
            }
        }

        // Try OpenAI if others failed
        if (!response && process.env.OPENAI_API_KEY) {
            try {
                response = await callOpenAI(messages, 0.2, 250);
                usedProvider = "openai";
                logger.info("OpenAI API call successful");
            } catch (openaiError) {
                logger.warn(`OpenAI failed: ${openaiError.message || openaiError}`);
            }
        }

        if (!response || !String(response).trim()) {
            response = generateLocalResponse(userMessage, pageData, instructions);
            usedProvider = "local";
        }

        const finalResponse = clampSentences(String(response).trim(), 3);
        const responseTime = Date.now() - startTime;
        logger.info(`AI response generated in ${responseTime}ms using ${usedProvider}`);
        return finalResponse;

    } catch (error) {
        logger.error("AI response generation failed:", error.message || error);
        return NOT_FOUND_MSG;
    }
}

function generateLocalResponse(userMessage, pageData = {}, instructions = "") {
    const question = (userMessage || "").toLowerCase();
    const salesMode = shouldActivateSalesMode(instructions);

    if (/preço|valor|quanto custa/.test(question)) {
        return "Para informações sobre preços, consulte diretamente a página do produto.";
    }

    if (/como funciona|funcionamento/.test(question)) {
        const summary = pageData.summary || pageData.description;
        if (summary) {
            const shortSummary = clampSentences(summary, 2);
            return salesMode ? `${shortSummary} Quer saber mais detalhes?` : shortSummary;
        }
    }

    if (/bônus|bonus/.test(question)) {
        if (pageData.bonuses_detected && pageData.bonuses_detected.length > 0) {
            const bonuses = pageData.bonuses_detected.slice(0, 2).join(", ");
            return salesMode ? `Inclui: ${bonuses}. Quer garantir todos os bônus?` : `Bônus: ${bonuses}`;
        }
        return "Informações sobre bônus não encontradas.";
    }

    if (pageData.summary) {
        const summary = clampSentences(pageData.summary, 2);
        return salesMode ? `${summary} Posso te ajudar com mais alguma dúvida?` : summary;
    }

    return NOT_FOUND_MSG;
}

// ===== API Routes =====
app.get("/health", (req, res) => {
    const uptime = process.uptime();
    const avgResponseTime = analytics.responseTimeHistory.length > 0 ?
        Math.round(analytics.responseTimeHistory.reduce((a, b) => a + b, 0) / analytics.responseTimeHistory.length) : 0;

    res.json({
        status: "healthy",
        uptime: Math.floor(uptime),
        timestamp: new Date().toISOString(),
        version: "7.0.0",
        analytics: {
            totalRequests: analytics.totalRequests,
            chatRequests: analytics.chatRequests,
            extractRequests: analytics.extractRequests,
            errors: analytics.errors,
            activeChats: analytics.activeChats.size,
            avgResponseTime,
            successfulExtractions: analytics.successfulExtractions,
            failedExtractions: analytics.failedExtractions,
            cacheSize: dataCache.size
        },
        services: {
            groq: !!process.env.GROQ_API_KEY,
            openai: !!process.env.OPENAI_API_KEY,
            openrouter: !!process.env.OPENROUTER_API_KEY,
            puppeteer: !!puppeteer
        }
    });
});

// /api/extract endpoint
app.post("/api/extract", async (req, res) => {
    analytics.extractRequests++;
    try {
        const { url, instructions, robotName } = req.body || {};
        
        console.log("📥 Recebendo requisição para extrair:", url);
        
        if (!url) {
            return res.status(400).json({ 
                success: false, 
                error: "URL é obrigatório" 
            });
        }

        // Validação básica de URL
        try { 
            new URL(url); 
        } catch (urlErr) { 
            return res.status(400).json({ 
                success: false, 
                error: "URL inválido" 
            }); 
        }

        logger.info(`Starting extraction for URL: ${url}`);
        
        const extractedData = await extractPageData(url);
        
        if (instructions) extractedData.custom_instructions = instructions;
        if (robotName) extractedData.robot_name = robotName;

        console.log("✅ Extração concluída com sucesso");
        
        return res.json({ 
            success: true, 
            data: extractedData 
        });

    } catch (error) {
        analytics.errors++;
        console.error("❌ Erro no endpoint /api/extract:", error);
        logger.error("Extract endpoint error:", error.message || error);
        
        return res.status(500).json({ 
            success: false, 
            error: "Erro interno ao extrair página: " + (error.message || "Erro desconhecido"),
            details: error.message
        });
    }
});

// /api/chat-universal endpoint
app.post("/api/chat-universal", async (req, res) => {
    analytics.chatRequests++;
    try {
        const { message, pageData, url, conversationId, instructions = "", robotName } = req.body || {};
        
        if (!message) {
            return res.status(400).json({ 
                success: false, 
                error: "Mensagem é obrigatória" 
            });
        }

        if (conversationId) {
            analytics.activeChats.add(conversationId);
            setTimeout(() => analytics.activeChats.delete(conversationId), 30 * 60 * 1000);
        }

        let processedPageData = pageData;
        if (!processedPageData && url) {
            processedPageData = await extractPageData(url);
        }

        const aiResponse = await generateAIResponse(message, processedPageData || {}, [], instructions);

        let finalResponse = aiResponse;
        if (processedPageData?.url && !String(finalResponse).includes(processedPageData.url)) {
            finalResponse = `${finalResponse}\n\n${processedPageData.url}`;
        }

        return res.json({
            success: true,
            response: finalResponse,
            bonuses_detected: processedPageData?.bonuses_detected || [],
            metadata: {
                hasPageData: !!processedPageData,
                contentLength: processedPageData?.cleanText?.length || 0,
                method: processedPageData?.method || "none"
            }
        });

    } catch (error) {
        analytics.errors++;
        logger.error("Chat endpoint error:", error.message || error);
        return res.status(500).json({ 
            success: false, 
            error: "Erro interno ao gerar resposta: " + (error.message || "Erro desconhecido"),
            details: error.message
        });
    }
});

// Widget JS
app.get("/public/widget.js", (req, res) => {
    res.set("Content-Type", "application/javascript");
    res.send(`// LinkMágico Widget v7.0\n(function() {\n    'use strict';\n    if (window.LinkMagicoWidget) return;\n    \n    var LinkMagicoWidget = {\n        config: {\n            position: 'bottom-right',\n            primaryColor: '#3b82f6',\n            robotName: 'Assistente IA',\n            salesUrl: '',\n            instructions: '',\n            apiBase: window.location.origin\n        },\n        \n        init: function(userConfig) {\n            this.config = Object.assign(this.config, userConfig || {});\n            if (document.readyState === 'loading') {\n                document.addEventListener('DOMContentLoaded', this.createWidget.bind(this));\n            } else {\n                this.createWidget();\n            }\n        },\n        \n        createWidget: function() {\n            var container = document.createElement('div');\n            container.id = 'linkmagico-widget';\n            container.innerHTML = this.getHTML();\n            this.addStyles();\n            document.body.appendChild(container);\n            this.bindEvents();\n        },\n        \n        getHTML: function() {\n            return '<div class="lm-button" id="lm-button"><i class="fas fa-comments"></i></div>' +\n                   '<div class="lm-chat" id="lm-chat" style="display:none;">' +\n                   '<div class="lm-header"><span>' + this.config.robotName + '</span><button id="lm-close">×</button></div>' +\n                   '<div class="lm-messages" id="lm-messages">' +\n                   '<div class="lm-msg lm-bot">Olá! Como posso ajudar?</div></div>' +\n                   '<div class="lm-input"><input id="lm-input" placeholder="Digite..."><button id="lm-send">➤</button></div></div>';\n        },\n        \n        addStyles: function() {\n            if (document.getElementById('lm-styles')) return;\n            var css = '#linkmagico-widget{position:fixed;right:20px;bottom:20px;z-index:999999;font-family:sans-serif}' +\n                     '.lm-button{width:60px;height:60px;background:' + this.config.primaryColor + ';border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:1.8em;cursor:pointer;box-shadow:0 4px 8px rgba(0,0,0,0.2);transition:all 0.3s ease}' +\n                     '.lm-button:hover{transform:scale(1.1)}' +\n                     '.lm-chat{position:fixed;right:20px;bottom:90px;width:350px;height:500px;background:white;border-radius:10px;box-shadow:0 8px 16px rgba(0,0,0,0.2);display:flex;flex-direction:column;overflow:hidden}' +\n                     '.lm-header{background:' + this.config.primaryColor + ';color:white;padding:10px;display:flex;justify-content:space-between;align-items:center;font-weight:bold}' +\n                     '.lm-header button{background:none;border:none;color:white;font-size:1.2em;cursor:pointer}' +\n                     '.lm-messages{flex:1;padding:10px;overflow-y:auto;display:flex;flex-direction:column;gap:10px}' +\n                     '.lm-msg{padding:8px 12px;border-radius:15px;max-width:80%}' +\n                     '.lm-bot{background:#e0e0e0;align-self:flex-start}' +\n                     '.lm-user{background:' + this.config.primaryColor + ';color:white;align-self:flex-end}' +\n                     '.lm-input{display:flex;padding:10px;border-top:1px solid #eee}' +\n                     '.lm-input input{flex:1;border:1px solid #ddd;border-radius:20px;padding:8px 12px;outline:none}' +\n                     '.lm-input button{background:' + this.config.primaryColor + ';border:none;color:white;border-radius:50%;width:35px;height:35px;margin-left:10px;cursor:pointer}' +\n                     '@media (max-width: 480px){.lm-chat{width:90%;height:80%;right:5%;bottom:5%}}';\n            var styleSheet = document.createElement('style');\n            styleSheet.id = 'lm-styles';\n            styleSheet.type = 'text/css';\n            styleSheet.innerText = css;\n            document.head.appendChild(styleSheet);\n        },\n        \n        bindEvents: function() {\n            var button = document.getElementById('lm-button');\n            var chat = document.getElementById('lm-chat');\n            var close = document.getElementById('lm-close');\n            var send = document.getElementById('lm-send');\n            var input = document.getElementById('lm-input');\n            var messages = document.getElementById('lm-messages');\n\n            button.addEventListener('click', function() {\n                chat.style.display = chat.style.display === 'none' ? 'flex' : 'none';\n            });\n\n            close.addEventListener('click', function() {\n                chat.style.display = 'none';\n            });\n\n            send.addEventListener('click', this.sendMessage.bind(this));\n            input.addEventListener('keypress', function(e) {\n                if (e.key === 'Enter') {\n                    this.sendMessage();\n                }\n            }.bind(this));\n        },\n\n        sendMessage: async function() {\n            var input = document.getElementById('lm-input');\n            var messages = document.getElementById('lm-messages');\n            var message = input.value.trim();\n            if (!message) return;\n\n            var userMsg = document.createElement('div');\n            userMsg.className = 'lm-msg lm-user';\n            userMsg.textContent = message;\n            messages.appendChild(userMsg);\n            input.value = '';\n            messages.scrollTop = messages.scrollHeight;\n\n            try {\n                const response = await fetch(this.config.apiBase + '/api/chat-universal', {\n                    method: 'POST',\n                    headers: {\n                        'Content-Type': 'application/json'\n                    },\n                    body: JSON.stringify({\n                        message: message,\n                        url: this.config.salesUrl,\n                        instructions: this.config.instructions,\n                        robotName: this.config.robotName,\n                        conversationId: this.config.conversationId\n                    })\n                });\n                const data = await response.json();\n\n                var botMsg = document.createElement('div');\n                botMsg.className = 'lm-msg lm-bot';\n                botMsg.textContent = data.response || 'Desculpe, ocorreu um erro.';\n                messages.appendChild(botMsg);\n                messages.scrollTop = messages.scrollHeight;\n\n            } catch (error) {\n                console.error('Widget chat error:', error);\n                var errorMsg = document.createElement('div');\n                errorMsg.className = 'lm-msg lm-bot';\n                errorMsg.textContent = 'Erro de conexão. Tente novamente.';\n                messages.appendChild(errorMsg);\n                messages.scrollTop = messages.scrollHeight;\n            }\n        }\n    };\n\n    window.LinkMagicoWidget = LinkMagicoWidget;\n    if (window.LinkMagicoWidgetConfig) {\n        window.LinkMagicoWidget.init(window.LinkMagicoWidgetConfig);\n    }\n})();\n`);
});

function generateChatbotHTML({ robotName, url, instructions }) {
    const escapedRobotName = String(robotName).replace(/"/g, "&quot;");
    const escapedUrl = String(url).replace(/"/g, "&quot;");
    const escapedInstructions = String(instructions).replace(/"/g, "&quot;");

    return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>LinkMágico Chatbot - ${escapedRobotName}</title>
<meta name="description" content="Chatbot IA - ${escapedRobotName}"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.chat-container{width:100%;max-width:800px;height:90vh;background:white;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,0.15);display:flex;flex-direction:column;overflow:hidden}
.chat-header{background:linear-gradient(135deg,#3b82f6 0%,#1e40af 100%);color:white;padding:20px;text-align:center;position:relative}
.chat-header h1{font-size:1.5rem;font-weight:600}
.chat-header .subtitle{font-size:0.9rem;opacity:0.9;margin-top:5px}
.chat-messages{flex:1;padding:20px;overflow-y:auto;display:flex;flex-direction:column;gap:15px;background:#f8fafc}
.chat-message{max-width:70%;padding:15px;border-radius:15px;font-size:0.95rem;line-height:1.4}
.chat-message.user{background:linear-gradient(135deg,#3b82f6 0%,#1e40af 100%);color:white;align-self:flex-end;border-bottom-right-radius:5px}
.chat-message.bot{background:#f1f5f9;color:#334155;align-self:flex-start;border-bottom-left-radius:5px}
.chat-input-container{padding:20px;background:white;border-top:1px solid#e2e8f0;display:flex;gap:10px}
.chat-input{flex:1;border:1px solid#e2e8f0;border-radius:25px;padding:12px 20px;font-size:0.95rem;outline:none;transition:all 0.3s}
.chat-input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
.send-button{background:linear-gradient(135deg,#3b82f6 0%,#1e40af 100%);border:none;border-radius:50%;width:50px;height:50px;color:white;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all 0.3s}
.send-button:hover{transform:scale(1.05);box-shadow:0 5px 15px rgba(59,130,246,0.4)}
.send-button:disabled{opacity:0.6;cursor:not-allowed;transform:none}
.typing-indicator{display:none;align-items:center;gap:5px;color:#64748b;font-size:0.9rem;margin-top:10px}
.typing-dot{width:8px;height:8px;background:#64748b;border-radius:50%;animation:typing 1.4s infinite}
.typing-dot:nth-child(2){animation-delay:0.2s}
.typing-dot:nth-child(3){animation-delay:0.4s}
@keyframes typing{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-10px)}}
.status-online{position:absolute;top:15px;right:15px;background:rgba(16,185,129,0.2);color:#10b981;padding:5px 10px;border-radius:15px;font-size:0.75rem;font-weight:600}
</style>
</head>
<body>
<div class="chat-container">
<div class="chat-header">
<h1>${escapedRobotName}</h1>
<div class="subtitle">Assistente Inteligente para Vendas</div>
<div class="status-online">Online</div>
</div>
<div class="chat-messages" id="chatMessages">
<div class="chat-message bot">
Olá! Sou seu assistente especializado. Como posso ajudar hoje?
</div>
</div>
<div class="typing-indicator" id="typingIndicator">
<span class="typing-dot"></span>
<span class="typing-dot"></span>
<span class="typing-dot"></span>
<span>Digitando...</span>
</div>
<div class="chat-input-container">
<input type="text" class="chat-input" id="chatInput" placeholder="Digite sua pergunta..." maxlength="500">
<button class="send-button" id="sendButton">
<i class="fas fa-paper-plane"></i>
</button>
</div>
</div>

<script>
const chatMessages = document.getElementById('chatMessages');
const chatInput = document.getElementById('chatInput');
const sendButton = document.getElementById('sendButton');
const typingIndicator = document.getElementById('typingIndicator');

const config = {
    robotName: "${escapedRobotName}",
    url: "${escapedUrl}",
    instructions: "${escapedInstructions}",
    conversationId: 'chat_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9)
};

let isTyping = false;

function addMessage(content, isUser = false) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message ' + (isUser ? 'user' : 'bot');
    messageDiv.textContent = content;
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function showTyping() {
    isTyping = true;
    typingIndicator.style.display = 'flex';
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function hideTyping() {
    isTyping = false;
    typingIndicator.style.display = 'none';
}

async function sendMessage() {
    const message = chatInput.value.trim();
    if (!message || isTyping) return;

    addMessage(message, true);
    chatInput.value = '';
    sendButton.disabled = true;
    showTyping();

    try {
        const response = await fetch('/api/chat-universal', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: message,
                url: config.url,
                instructions: config.instructions,
                robotName: config.robotName,
                conversationId: config.conversationId
            })
        });

        const data = await response.json();
        
        hideTyping();
        
        if (data.success) {
            addMessage(data.response);
        } else {
            addMessage('Desculpe, ocorreu um erro. Tente novamente em alguns minutos.');
        }
    } catch (error) {
        hideTyping();
        addMessage('Erro de conexão. Verifique sua internet e tente novamente.');
    } finally {
        sendButton.disabled = false;
        chatInput.focus();
    }
}

sendButton.addEventListener('click', sendMessage);
chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

// Auto-focus input
chatInput.focus();
</script>
</body>
</html>`;
}

// ===== Server Initialization =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
    console.log(`🚀 LinkMágico v7.0 Server running on http://localhost:${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

