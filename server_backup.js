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
    origin: ["https://link-m-gico-v6-0-hmpl.onrender.com", "http://localhost:3000", "http://localhost:8080"],
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
    logger.info(`[requireApiKey] req.session: ${JSON.stringify(req.session)}`);
    // Allow access to root and validation endpoint without API Key
    if (req.path === "/" || req.path === "/validate-api-key" || req.path.startsWith("/public/")) {
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

app.get("/chat.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "chat.html"));
});

// Rotas para as páginas LGPD
app.get("/privacy.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "privacy.html"));
});

app.get("/excluir-dados", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "excluir-dados.html"));
});

// Serve other static files from public directory
app.use("/public", express.static(path.join(__dirname, "public"), {
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
                    "User-Agent": "Mozilla/5.0 (compatible; LinkMagico-Bot/6.0; +https://link-m-gico-v6-0-hmpl.onrender.com)",
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
                            let total = 0;
                            const dist = 300;
                            const timer = setInterval(() => {
                                window.scrollBy(0, dist);
                                total += dist;
                                if (total >= document.body.scrollHeight || total > 3000) {
                                    clearInterval(timer);
                                    resolve();
                                }
                            }, 100);
                        });
                    });
                    await page.waitForTimeout(500);
                } catch (scrollErr) {
                    logger.warn("Puppeteer scroll failed:", scrollErr.message || scrollErr);
                }

                const puppeteerData = await page.evaluate(() => {
                    const clone = document.cloneNode(true);
                    const removeEls = clone.querySelectorAll("script, style, noscript, iframe");
                    removeEls.forEach(e => e.remove());
                    return {
                        bodyText: clone.body ? clone.body.innerText : "",
                        title: document.title || "",
                        metaDescription: document.querySelector("meta[name=\"description\"]")?.content || ""
                    };
                });

                const cleanedText = normalizeText(puppeteerData.bodyText || "").replace(/\s{2,}/g, " ");
                const lines = cleanedText.split("\n").map(l => l.trim()).filter(Boolean);
                const uniq = [...new Set(lines)];
                const finalText = uniq.join("\n");

                if (finalText && finalText.length > (extractedData.cleanText || "").length) {
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
async function callGroq(messages, temperature = 0.4, maxTokens = 300, apiKey) {
    const finalApiKey = apiKey || process.env.GROQ_API_KEY;
    if (!finalApiKey) throw new Error("GROQ_API_KEY missing");

    const payload = {
        model: process.env.GROQ_MODEL || "llama-3.1-70b-versatile",
        messages,
        temperature,
        max_tokens: maxTokens
    };

    const url = process.env.GROQ_API_BASE || "https://api.groq.com/openai/v1/chat/completions";
    const headers = { "Authorization": `Bearer ${finalApiKey}`, "Content-Type": "application/json" };

    try {
        const response = await axios.post(url, payload, { headers });
        return response.data.choices[0].message.content;
    } catch (error) {
        logger.error("Groq API call failed:", error.response ? error.response.data : error.message);
        throw new Error("Failed to get response from Groq API");
    }
}

async function callOpenRouter(messages, temperature = 0.4, maxTokens = 300, apiKey) {
    const finalApiKey = apiKey || process.env.OPENROUTER_API_KEY;
    if (!finalApiKey) throw new Error("OPENROUTER_API_KEY missing");

    const payload = {
        model: process.env.OPENROUTER_MODEL || "mistralai/mistral-7b-instruct",
        messages,
        temperature,
        max_tokens: maxTokens
    };

    const url = process.env.OPENROUTER_API_BASE || "https://openrouter.ai/api/v1/chat/completions";
    const headers = { "Authorization": `Bearer ${finalApiKey}`, "Content-Type": "application/json" };

    try {
        const response = await axios.post(url, payload, { headers });
        return response.data.choices[0].message.content;
    } catch (error) {
        logger.error("OpenRouter API call failed:", error.response ? error.response.data : error.message);
        throw new Error("Failed to get response from OpenRouter API");
    }
}

async function callOpenAI(messages, temperature = 0.4, maxTokens = 300, apiKey) {
    const finalApiKey = apiKey || process.env.OPENAI_API_KEY;
    if (!finalApiKey) throw new Error("OPENAI_API_KEY missing");

    const payload = {
        model: process.env.OPENAI_MODEL || "gpt-3.5-turbo",
        messages,
        temperature,
        max_tokens: maxTokens
    };

    const url = process.env.OPENAI_API_BASE || "https://api.openai.com/v1/chat/completions";
    const headers = { "Authorization": `Bearer ${finalApiKey}`, "Content-Type": "application/json" };

    try {
        const response = await axios.post(url, payload, { headers });
        return response.data.choices[0].message.content;
    } catch (error) {
        logger.error("OpenAI API call failed:", error.response ? error.response.data : error.message);
        throw new Error("Failed to get response from OpenAI API");
    }
}

// ===== API Routes =====
app.get("/api/analytics", (req, res) => {
    const uptime = (Date.now() - analytics.startTime) / 1000;
    const avgResponseTime = analytics.responseTimeHistory.reduce((a, b) => a + b, 0) / (analytics.responseTimeHistory.length || 1);
    res.json({
        ...analytics,
        uptime,
        avgResponseTime: avgResponseTime.toFixed(2)
    });
});

app.post("/api/extract", async (req, res) => {
    analytics.extractRequests++;
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ success: false, error: "URL is required" });
    }
    try {
        const data = await extractPageData(url);
        res.json({ success: true, data });
    } catch (error) {
        logger.error("Extract API error:", error.message);
        res.status(500).json({ success: false, error: "Failed to extract page data" });
    }
});

app.post("/api/chat-universal", async (req, res) => {
    analytics.chatRequests++;
    const { message, pageData, instructions, robotName, conversationId, provider, model } = req.body;
    const selectedApiKey = req.session.validatedApiKey; // Obtém a API Key validada da sessão

    if (!message) {
        return res.status(400).json({ success: false, error: "Message is required" });
    }

    if (!selectedApiKey) {
        return res.status(401).json({ success: false, error: "API Key não fornecida ou inválida na sessão." });
    }

    const history = conversationHistories.get(conversationId) || [];
    history.push({ role: "user", content: message });

    const systemPrompt = `Você é ${robotName}, um assistente de IA. Use os seguintes dados da página para responder: ${JSON.stringify(pageData)}. Instruções adicionais: ${instructions}.`;
    const messages = [{ role: "system", content: systemPrompt }, ...history];

    try {
        let responseText;
        const selectedProvider = provider || process.env.DEFAULT_PROVIDER || "groq";
        const selectedModel = model || process.env.DEFAULT_MODEL || "llama3-8b-8192";
        const temperature = 0.4;
        const maxTokens = 300;

        switch (selectedProvider) {
            case "groq":
                responseText = await callGroq(messages, temperature, maxTokens, selectedApiKey);
                break;
            case "openrouter":
                responseText = await callOpenRouter(messages, temperature, maxTokens, selectedApiKey);
                break;
            case "openai":
                responseText = await callOpenAI(messages, temperature, maxTokens, selectedApiKey);
                break;
            default:
                throw new Error("Invalid provider specified");
        }

        history.push({ role: "assistant", content: responseText });
        conversationHistories.set(conversationId, history);

        res.json({ success: true, response: responseText });
    } catch (error) {
        analytics.errors++;
        logger.error("Chat API error:", error.message);
        res.status(500).json({ success: false, error: "Failed to get response from LLM API", details: error.message });
    }
});

function generateChatbotHTML(config) {
    return `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${config.title}</title>
    <style>
        /* Estilos do chatbot aqui */
    </style>
</head>
<body>
    <div id="chatbot-container"></div>
    <script>
        // Lógica do chatbot aqui
    </script>
</body>
</html>
`;
}

app.post("/api/generate-chatbot", async (req, res) => {
    const { config } = req.body;
    if (!config) {
        return res.status(400).json({ success: false, error: "Config is required" });
    }

    try {
        const chatbotHTML = generateChatbotHTML(config);
        res.json({ success: true, html: chatbotHTML });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ===== Server Initialization =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
    console.log(`Server running on http://localhost:${PORT}`);
});

