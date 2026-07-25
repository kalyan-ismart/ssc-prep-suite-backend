const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const dns = require('dns');

// Use Google Public DNS to resolve MongoDB Atlas SRV records
// (fixes ECONNREFUSED on systems where the default DNS resolver blocks SRV queries)
dns.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);

// Auto-load environment variables from backend/.env or root .env file
function loadEnvFile() {
  const envPaths = [
    path.join(__dirname, '.env'),
    path.join(__dirname, '../.env')
  ];

  for (const envPath of envPaths) {
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf8');
        content.split('\n').forEach(line => {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) {
            const eqIndex = trimmed.indexOf('=');
            if (eqIndex !== -1) {
              const key = trimmed.substring(0, eqIndex).trim();
              let val = trimmed.substring(eqIndex + 1).trim();
              if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                val = val.slice(1, -1);
              }
              if (val) {
                process.env[key] = val;
              }
            }
          }
        });
        console.log(`📄 Environment configuration loaded from: ${envPath}`);
      } catch (e) {
        console.warn(`⚠️ Warning reading env file at ${envPath}:`, e.message);
      }
    }
  }
}
loadEnvFile();

function getApiKey(req) {
  let key = (req && (req.headers['x-api-key'] || req.body?._apiKey)) || '';
  if (key && key.trim()) return key.trim();

  if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim()) {
    return process.env.GEMINI_API_KEY.trim();
  }
  if (process.env.API_KEY && process.env.API_KEY.trim()) {
    return process.env.API_KEY.trim();
  }
  return '';
}

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Connection with Auto-Retry
const mongoURI = process.env.ATLAS_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ssc-prep-suite';
const MONGO_MAX_RETRIES = 5;
const MONGO_RETRY_BASE_MS = 3000;

async function connectWithRetry(attempt = 1) {
  try {
    await mongoose.connect(mongoURI, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      heartbeatFrequencyMS: 10000,
    });
    console.log('🍃 MongoDB connection established successfully');
  } catch (err) {
    if (attempt < MONGO_MAX_RETRIES) {
      const delay = MONGO_RETRY_BASE_MS * Math.pow(2, attempt - 1);
      console.warn(`⚠️ MongoDB connection attempt ${attempt}/${MONGO_MAX_RETRIES} failed: ${err.message}`);
      console.warn(`🔄 Retrying in ${delay / 1000}s...`);
      await new Promise(r => setTimeout(r, delay));
      return connectWithRetry(attempt + 1);
    }
    console.error(`❌ MongoDB connection failed after ${MONGO_MAX_RETRIES} attempts: ${err.message}`);
    console.warn('💡 Tip: Ensure MongoDB service is running or set ATLAS_URI in .env');
    console.warn('⚡ Server will continue without database — DB routes will return 503');
  }
}

// Listen for connection events to auto-reconnect on disconnect
mongoose.connection.on('disconnected', () => {
  console.warn('⚠️ MongoDB disconnected. Attempting to reconnect...');
  setTimeout(() => connectWithRetry(1), 5000);
});
mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err.message);
});

connectWithRetry();

// CORS — allow known frontend origins and localhost for development
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5000',
  process.env.FRONTEND_URL,         // e.g. https://your-app.netlify.app
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, server-to-server)
    if (!origin) return callback(null, true);
    if (allowedOrigins.some(allowed => origin.startsWith(allowed))) {
      return callback(null, true);
    }
    // In production, also allow any .netlify.app or .onrender.com origin
    if (/\.(netlify\.app|onrender\.com)$/.test(origin)) {
      return callback(null, true);
    }
    return callback(null, true); // Fallback: allow all (safe for public APIs)
  },
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Request timeout middleware — prevent hanging requests (30 seconds)
app.use((req, res, next) => {
  // Longer timeout for AI generation endpoints
  const timeout = req.path.startsWith('/api/flow') || req.path.startsWith('/api/chat') ? 120000 : 30000;
  req.setTimeout(timeout);
  res.setTimeout(timeout, () => {
    if (!res.headersSent) {
      console.error(`⏱️ Request timeout: ${req.method} ${req.originalUrl}`);
      res.status(408).json({ error: 'Request timed out. Please try again.' });
    }
  });
  next();
});

// Request logger middleware — prints every incoming request and response status to terminal
app.use((req, res, next) => {
  const start = Date.now();
  const timeStr = new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' });
  res.on('finish', () => {
    const duration = Date.now() - start;
    const status = res.statusCode;
    const statusIcon = status >= 500 ? '❌' : status >= 400 ? '⚠️' : '✅';
    console.log(`[${timeStr}] ${statusIcon} ${req.method} ${req.originalUrl} ${status} (${duration}ms)`);
  });
  next();
});

// Import and mount module, user, and progress routes
const modulesRouter = require('./routes/modules');
const usersRouter = require('./routes/users');
const progressRouter = require('./routes/progress');

app.use('/modules', modulesRouter);
app.use('/users', usersRouter);
app.use('/progress', progressRouter);

// Serve static frontend assets (prefer public folder for live asset serving)
const frontendBuildPath = path.join(__dirname, '../frontend/build');
const frontendPublicPath = path.join(__dirname, '../frontend/public');

// Force browsers to disable stale caching of static assets
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

app.use(express.static(frontendPublicPath, { etag: false, maxAge: 0 }));
if (fs.existsSync(frontendBuildPath)) {
  app.use(express.static(frontendBuildPath, { etag: false, maxAge: 0 }));
}

// In-Memory API Cache to prevent repeated rate-limit hits (TTL: 30 minutes)
const apiCache = new Map();
const CACHE_TTL_MS = 30 * 60 * 1000;
const CACHE_MAX_SIZE = 200;

function getCachedResponse(key) {
  const item = apiCache.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > CACHE_TTL_MS) {
    apiCache.delete(key);
    return null;
  }
  return item.data;
}

function setCachedResponse(key, data) {
  if (apiCache.size > CACHE_MAX_SIZE) {
    const oldestKey = apiCache.keys().next().value;
    apiCache.delete(oldestKey);
  }
  apiCache.set(key, { data, timestamp: Date.now() });
}

// Periodic cache cleanup — remove expired entries every 10 minutes to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [key, item] of apiCache) {
    if (now - item.timestamp > CACHE_TTL_MS) {
      apiCache.delete(key);
      cleaned++;
    }
  }
  // Also clean stale rate-limit entries (older than 5 minutes)
  for (const [model, timestamp] of rateLimitedModelsCache) {
    if (now - timestamp > 300000) {
      rateLimitedModelsCache.delete(model);
    }
  }
  // Clean stale model caches (older than 1 hour)
  // userAvailableModelsCache doesn't have timestamps, but limit its size
  if (userAvailableModelsCache.size > 50) {
    const firstKey = userAvailableModelsCache.keys().next().value;
    userAvailableModelsCache.delete(firstKey);
  }
  if (cleaned > 0) console.log(`🧹 Cache cleanup: removed ${cleaned} expired entries`);
}, 10 * 60 * 1000);

// Health check endpoint with MongoDB status
app.get('/api/health', (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStatus = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
  res.status(200).json({
    status: 'UP',
    message: 'Server is healthy',
    uptime: Math.floor(process.uptime()),
    database: dbStatus[dbState] || 'unknown',
    memoryMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    cacheSize: apiCache.size,
    timestamp: new Date().toISOString()
  });
});

// GET /api/today — Returns live IST date
app.get('/api/today', (req, res) => {
  const now = new Date();
  const options = { timeZone: 'Asia/Kolkata' };
  const isoDate = now.toLocaleDateString('en-CA', options); // YYYY-MM-DD
  const fullDate = now.toLocaleDateString('en-IN', { ...options, day: 'numeric', month: 'long', year: 'numeric' });
  const dayName = now.toLocaleDateString('en-IN', { ...options, weekday: 'long' });
  
  res.json({
    iso: isoDate,
    full: fullDate,
    day: dayName
  });
});

let cachedWorkingModel = null;
const userAvailableModelsCache = new Map();
const rateLimitedModelsCache = new Map(); // model -> timestamp

// Dynamically fetch supported models for the user's API Key via Google's ModelService.ListModels
async function fetchAvailableModels(apiKey) {
  if (userAvailableModelsCache.has(apiKey)) {
    return userAvailableModelsCache.get(apiKey);
  }

  const preferredDefaults = ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-flash-8b', 'gemini-2.0-flash-lite', 'gemini-1.5-pro'];

  try {
    const listUrl = `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`;
    const res = await fetch(listUrl);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.models)) {
        const validModels = data.models
          .filter(m => m.supportedGenerationMethods && m.supportedGenerationMethods.includes('generateContent'))
          .map(m => m.name.replace(/^models\//, ''))
          .filter(name => !/tts|lyria|image|nano|robotics|computer-use|deep-research|gemma/i.test(name));
        
        if (validModels.length > 0) {
          const sorted = [...new Set([...preferredDefaults.filter(p => validModels.includes(p)), ...validModels])];
          console.log(`✨ Discovered ${sorted.length} valid text models for API Key:`, sorted);
          userAvailableModelsCache.set(apiKey, sorted);
          return sorted;
        }
      }
    }
  } catch (e) {
    console.warn('⚠️ Could not query ListModels API, using default model candidates.');
  }

  userAvailableModelsCache.set(apiKey, preferredDefaults);
  return preferredDefaults;
}

// Helper function to call Google Gemini REST API directly with automatic model fallback
async function callGeminiAPI(apiKey, prompt, systemInstruction = '', isJson = false, enableSearch = true) {
  const effectiveKey = apiKey || getApiKey();
  if (!effectiveKey) {
    const err = new Error('No API key found in backend folder. Please set GEMINI_API_KEY in the backend/.env file.');
    err.status = 400;
    throw err;
  }

  const discoveredModels = await fetchAvailableModels(effectiveKey);
  
  // Exclude models rate-limited in the last 2 minutes to decrease loading time
  const now = Date.now();
  const availableCandidates = discoveredModels.filter(m => {
    const limitedAt = rateLimitedModelsCache.get(m);
    return !limitedAt || (now - limitedAt > 120000);
  });

  const candidatesList = availableCandidates.length > 0 ? availableCandidates : discoveredModels;
  const modelCandidates = cachedWorkingModel 
    ? [cachedWorkingModel, ...candidatesList]
    : candidatesList;

  const modelsToTry = [...new Set(modelCandidates)];
  let lastError = null;

  for (const model of modelsToTry) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${effectiveKey}`;

      const payload = {
        contents: [{
          parts: [{ text: prompt }]
        }]
      };

      // Enable Google Search Engine Grounding for live real-time search across all tools
      if (enableSearch && !isJson) {
        payload.tools = [{ googleSearch: {} }];
      }

      if (systemInstruction) {
        payload.systemInstruction = {
          parts: [{ text: systemInstruction }]
        };
      }

      payload.generationConfig = {
        ...(isJson ? { responseMimeType: 'application/json' } : {}),
        temperature: 0.95,
        topP: 0.95,
        topK: 40
      };

      // Abort controller for fetch timeout (60 seconds)
      const controller = new AbortController();
      const fetchTimeout = setTimeout(() => controller.abort(), 60000);

      let response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal
        });
      } catch (fetchErr) {
        clearTimeout(fetchTimeout);
        if (fetchErr.name === 'AbortError') {
          const timeoutErr = new Error(`Gemini API request timed out for model "${model}"`);
          timeoutErr.status = 408;
          lastError = timeoutErr;
          continue;
        }
        throw fetchErr;
      }
      clearTimeout(fetchTimeout);

      // If Google Search tool is unsupported by a specific fallback model, retry without tools
      if (!response.ok && payload.tools) {
        delete payload.tools;
        const retryController = new AbortController();
        const retryTimeout = setTimeout(() => retryController.abort(), 60000);
        try {
          response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: retryController.signal
          });
        } catch (fetchErr) {
          clearTimeout(retryTimeout);
          if (fetchErr.name === 'AbortError') {
            const timeoutErr = new Error(`Gemini API retry timed out for model "${model}"`);
            timeoutErr.status = 408;
            lastError = timeoutErr;
            continue;
          }
          throw fetchErr;
        }
        clearTimeout(retryTimeout);
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        const msg = errData?.error?.message || `Gemini API returned status ${response.status}`;
        
        const isNotFound = response.status === 404 || msg.includes('not found') || msg.includes('not supported') || msg.includes('Call ModelService.ListModels');
        const isQuotaExceeded = response.status === 429 || msg.includes('Quota exceeded') || msg.includes('rate limit') || msg.includes('RESOURCE_EXHAUSTED');

        if (isQuotaExceeded) {
          rateLimitedModelsCache.set(model, Date.now());
        }

        if (isNotFound || isQuotaExceeded) {
          console.warn(`⚠️ Model "${model}" unavailable (${isQuotaExceeded ? 'Quota Limit 429' : 'Model 404'}). Trying next candidate...`);
          lastError = new Error(msg);
          lastError.status = response.status;
          continue;
        }

        const apiErr = new Error(msg);
        apiErr.status = response.status;
        throw apiErr;
      }

      const data = await response.json();
      const candidateText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!candidateText) {
        const err = new Error('Empty response received from Gemini API.');
        err.status = 500;
        throw err;
      }

      cachedWorkingModel = model;
      let clean = candidateText.trim();

      // 1. Strip markdown code block wrappers (```html ... ```)
      clean = clean.replace(/^```(html|json)?\s*/gi, '').replace(/```\s*$/gi, '').trim();

      // 2. Remove internal model meta-thinking, self-checks, checklists, and draft preambles
      if (/Clean HTML\?|Check for raw LaTeX|Check for Markdown|Final Structure Check|Wait, let's|Target Audience:|Calculation check|Verification:|Draft/i.test(clean)) {
        const contentStartRegex = /(?:<h[1-6]\b|<p\b|<div\b|<table\b|<ul\b|<ol\b|<strong\b|^\s*#{1,6}\s+|(?:<p>)?\s*<strong>(?:Question|Problem|Solution|Concept|Topic|Overview|Shortcuts):)/i;
        const match = clean.match(contentStartRegex);
        if (match && match.index > 0) {
          clean = clean.slice(match.index);
        }
      }
      clean = clean.replace(/(?:^|\n)[^\n]*?(?:Clean HTML\?|Check for raw LaTeX|Check for Markdown|Final Structure Check|Wait, let's|Target Audience:|Calculation check|Verification:)[^\n]*/gi, '');
      clean = clean.replace(/^(?:Let's try|Wait, let's|Final Question Selection|Calculation check|Target Audience:|Okay, let's|Here is|Sure, here|First, let's)[^\n]*\n+/gi, '');
      clean = clean.replace(/^\s*(?:\.\.\.|\---|[*]{3,})\s*/gim, '').trim();

      // 3. Clean out mixed Markdown+HTML syntax artifacts
      clean = clean.replace(/(?:^|\n)\s*(?:---|[*]{3,})\s*(?:#{1,6}\s*)?(?=<h[1-6]|<p|<div|<section|<article|<table)/gi, '\n');
      clean = clean.replace(/(?:#{1,6}\s*)(?=<h[1-6]|<p|<div|<section|<article|<table)/gi, '');
      clean = clean.replace(/(?:---|[*]{3,})\s*(?=<h[1-6])/gi, '');

      // 4. Convert raw LaTeX symbols to standard math symbols
      clean = clean
        .replace(/\\times/g, '×')
        .replace(/\\div/g, '÷')
        .replace(/\\sqrt\{([^}]+)\}/g, '√$1')
        .replace(/\\frac\{([^}]+)\}\{([^}]+)\}/g, '($1/$2)')
        .replace(/\$([^$]+)\$/g, '$1')
        .replace(/\\\((.*?)\\\)/g, '$1');

      // 5. Strip trailing code block fences or backticks
      clean = clean.replace(/```\s*$/gi, '').replace(/^`+|`+$/g, '').trim();

      return clean;
    } catch (err) {
      if (err.status === 404 || (err.message && (err.message.includes('not found') || err.message.includes('not supported') || err.message.includes('Call ModelService.ListModels')))) {
        lastError = err;
        continue;
      }
      throw err;
    }
  }

  throw lastError || new Error('Failed to find a supported Gemini model for your API key.');
}

const SYSTEM_INSTRUCTION = `You are the core AI engine powering CGL Prep Pro. Your sole purpose is to deliver production-ready, clean, high-utility educational content for SSC CGL aspirants.

CRITICAL FORMATTING AND BEHAVIORAL CONSTRAINTS:
1. ABSOLUTELY NO META-THINKING, CHECKLISTS, OR SELF-REFLECTIONS: Never output internal checklists, self-verification text, brainstorming, or phrases such as "Clean HTML? Yes", "Check for raw LaTeX", "Check for Markdown", "Verify math", "Final Structure Check", "Wait, let's", "Question Selection", or "Target Audience". Start your response IMMEDIATELY with the final educational content element.
2. NO DRAFTING STAGES: Do not display "Drafts", "Initial versions", or "Improved versions". Provide only the final, highest-quality output immediately.
3. CLEAN MATH & TEXT RENDERING: Do NOT use raw LaTeX syntax (e.g. \\sqrt{}, \\frac{}{}, \\times, \\Rightarrow). Do NOT use raw markdown math delimiters ($x$ or \\(...\\)). Use clean, standard, universally rendered symbols (+, -, ×, ÷, =, %, √x, a/b, x², π, θ, °). Express fractions plainly (e.g., 41/6 days = 6 5/6 days).
4. ZERO CODE LEAKAGE: Never output trailing backticks (\`\`\`), structural notes (e.g., "HTML Structure:"), or loose punctuation marks at the bottom of the response. Ensure your string terminates perfectly after the final educational sentence.
5. IMMEDIATE START: Begin your response directly with the core heading or answer. Do not use conversational introductions or filler like "Hey there! Here is a detailed breakdown: ---".
6. PURE HTML OUTPUT ONLY: Return standard HTML elements (<h2>, <h3>, <h4>, <p>, <ul>, <ol>, <li>, <table>, <tr>, <th>, <td>, <b>, <i>, <em>, <strong>, <hr>, <div>). NEVER mix Markdown syntax (such as ###, ##, #, ---, ***, **, *) with HTML tags. Never place Markdown header symbols before HTML tags.
7. NO REPETITION: Generate novel, fresh, unique questions and content every time. Never output identical or repeated questions across tool calls.

OUTPUT FORMAT: Provide clean, semantic, well-structured HTML optimized for immediate rendering on a dark-themed user interface.`;

// POST /api/flow/:type
app.post('/api/flow/:type', async (req, res) => {
  try {
    const apiKey = getApiKey(req);
    const type = req.params.type;
    const enableSearch = req.body.enableSearch !== undefined ? req.body.enableSearch : true;

    // Bypass cache for flow calls to ensure fresh AI response on every execution
    const bypassCache = req.body.bypassCache !== undefined ? req.body.bypassCache : true;
    const cacheKey = `${type}:${JSON.stringify(req.body)}`;
    if (!bypassCache) {
      const cached = getCachedResponse(cacheKey);
      if (cached) {
        console.log(`⚡ [CACHE HIT] Serving cached response for flow "${type}"`);
        return res.json(cached);
      }
    }

    let responseData;

    if (type === 'generic') {
      const prompt = req.body.prompt || '';
      const mode = req.body.mode || 'html';
      const isJson = mode === 'json';
      const text = await callGeminiAPI(apiKey, prompt, SYSTEM_INSTRUCTION, isJson, enableSearch);
      responseData = { result: text };
    } else if (type === 'questions') {
      const topic = req.body.topic || 'SSC CGL';
      const count = req.body.count || 5;
      const uniqueSeed = `${Date.now()}_${Math.random()}`;
      const prompt = `[UNIQUE_SEED:${uniqueSeed}] Generate ${count} BRAND-NEW, HIGH-QUALITY, UNIQUE SSC CGL multiple choice questions (MCQs) for topic: "${topic}".
DO NOT repeat standard or previously generated questions. Provide creative, diverse questions covering different subtopics.
Return a JSON object matching this schema:
{
  "questions": [
    {
      "question": "string",
      "options": ["string", "string", "string", "string"],
      "answer": "exact string matching one of the options",
      "explanation": "detailed step-by-step solution"
    }
  ]
}`;
      const text = await callGeminiAPI(apiKey, prompt, SYSTEM_INSTRUCTION, true, enableSearch);
      try { responseData = JSON.parse(text); } catch(e) { responseData = { questions: [] }; }
    } else if (type === 'explain') {
      const concept = req.body.concept || '';
      const prompt = `Explain the concept "${concept}" in deep detail for an SSC CGL candidate. Include definitions, key formulas, shortcuts, and examples. Output in clean HTML.`;
      const text = await callGeminiAPI(apiKey, prompt, SYSTEM_INSTRUCTION, false, enableSearch);
      responseData = { explanation: text };
    } else if (type === 'summarize') {
      const textInput = req.body.text || '';
      const prompt = `Summarize the following document into key bullet points and high-yield notes for SSC CGL revision:\n\n${textInput}\n\nOutput in clean HTML.`;
      const text = await callGeminiAPI(apiKey, prompt, SYSTEM_INSTRUCTION, false, enableSearch);
      responseData = { summary: text };
    } else {
      const prompt = req.body.prompt || JSON.stringify(req.body);
      const text = await callGeminiAPI(apiKey, prompt, SYSTEM_INSTRUCTION, false, enableSearch);
      responseData = { result: text };
    }

    if (!bypassCache) {
      setCachedResponse(cacheKey, responseData);
    }
    return res.json(responseData);
  } catch (err) {
    const statusCode = err.status || 500;
    console.error(`\n❌ [SERVER ERROR] POST /api/flow/${req.params.type} (Status ${statusCode})`);
    console.error(`ErrorMessage: ${err.message}`);
    if (err.stack) console.error(`Stack:\n${err.stack}\n`);
    res.status(statusCode).json({ error: err.message });
  }
});

// POST /api/chat/:type
app.post('/api/chat/:type', async (req, res) => {
  try {
    const apiKey = getApiKey(req);
    const type = req.params.type;
    const history = req.body.history || [];

    const systemPrompts = {
      tutor: 'You are an expert, encouraging SSC CGL tutor. Explain concepts clearly, provide exam shortcuts, and answer questions thoroughly using simple markdown text, bold headings, and bullet points. Do NOT use custom colored boxes, callout cards, HTML containers, or inline style colors.',
      buddy: 'You are a supportive, friendly study buddy for an SSC CGL candidate. Keep morale high, share study strategies, and give motivation using simple markdown text, bold headings, and bullet points. Do NOT use custom colored boxes, callout cards, HTML containers, or inline style colors.',
      debate: 'You are a sharp debate partner for reasoning practice. Politely challenge user statements and argue the counter-perspective using simple markdown text, bold headings, and bullet points. Do NOT use custom colored boxes, callout cards, HTML containers, or inline style colors.',
      interview: 'You are Mr. Sharma, a senior government officer interviewing candidates for SSC CGL positions. Ask professional, realistic interview questions and evaluate their answers using simple markdown text, bold headings, and bullet points. Do NOT use custom colored boxes, callout cards, HTML containers, or inline style colors.'
    };

    const sysInstruction = systemPrompts[type] || 'You are an AI assistant for SSC CGL preparation. Provide responses using simple markdown text, bold headings, and bullet points without custom colored boxes or HTML containers.';
    const conversation = history.map(h => `${h.role === 'user' ? 'Student' : 'Assistant'}: ${h.content?.[0]?.text || ''}`).join('\n');
    const prompt = `Conversation history:\n${conversation}\n\nRespond to the latest student input using simple plain markdown text with bold headings and bullet points. Do NOT use custom colored boxes, background cards, or HTML container elements. Ensure the text format is clean, high-contrast, and easy to read in both dark and light modes.`;

    const text = await callGeminiAPI(apiKey, prompt, sysInstruction, false, true);
    res.send(text);
  } catch (err) {
    const statusCode = err.status || 500;
    console.error(`\n❌ [SERVER ERROR] POST /api/chat/${req.params.type} (Status ${statusCode})`);
    console.error(`ErrorMessage: ${err.message}`);
    if (err.stack) console.error(`Stack:\n${err.stack}\n`);
    res.status(statusCode).json({ error: err.message });
  }
});

// POST /api/tts
app.post('/api/tts', (req, res) => {
  res.json({ useBrowserTTS: true });
});

// Wildcard route to serve index.html for Single Page Application routing history fallbacks
app.get('*', (req, res) => {
  const buildIndex = path.join(frontendBuildPath, 'index.html');
  const publicIndex = path.join(frontendPublicPath, 'index.html');

  if (fs.existsSync(buildIndex)) {
    return res.sendFile(buildIndex);
  }
  if (fs.existsSync(publicIndex)) {
    return res.sendFile(publicIndex);
  }
  res.status(404).send('Not Found');
});

// Global Process Error Handlers to log crashes to terminal (NEVER crash the process)
process.on('uncaughtException', (err) => {
  console.error('\n🔥 [CRITICAL UNCAUGHT EXCEPTION]:', err.message);
  console.error(err.stack);
  // Don't exit — keep the server running
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('\n🔥 [UNHANDLED PROMISE REJECTION]:', reason);
  // Don't exit — keep the server running
});

// Graceful shutdown handler for Render (sends SIGTERM on redeploy)
let isShuttingDown = false;
function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\n🛑 ${signal} received. Shutting down gracefully...`);

  // Stop accepting new connections
  server.close(() => {
    console.log('✅ HTTP server closed');
    // Close MongoDB connection
    mongoose.connection.close(false).then(() => {
      console.log('✅ MongoDB connection closed');
      process.exit(0);
    }).catch(() => {
      process.exit(0);
    });
  });

  // Force exit after 10 seconds if graceful shutdown hangs
  setTimeout(() => {
    console.error('⚠️ Forced shutdown after 10s timeout');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n======================================================`);
  console.log(`🚀 CGL Prep Pro Server Live: http://localhost:${PORT}`);
  console.log(`📡 Full Terminal Logging Enabled (Requests & Errors)`);
  console.log(`======================================================\n`);
});

// Keep-alive settings to prevent premature connection drops
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
