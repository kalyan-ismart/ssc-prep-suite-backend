require('dotenv').config();

console.log("--- DEPLOYMENT TEST: RUNNING LATEST server.js at", new Date().toISOString(), "---");

// Add debugging logs for environment variables
console.log('🔍 PORT from environment:', process.env.PORT);
const PORT = process.env.PORT || 10000;
console.log('🔍 Using PORT:', PORT);
console.log('🔍 ATLAS_URI:', process.env.ATLAS_URI ? 'Set ✅' : 'Missing ❌');
console.log('🔍 OPENAI_API_KEY:', process.env.OPENAI_API_KEY ? 'Set ✅' : 'Missing ❌');
console.log('🔍 JWT_SECRET:', process.env.JWT_SECRET ? 'Set ✅' : 'Missing ❌');
console.log('🔍 JWT_REFRESH_SECRET:', process.env.JWT_REFRESH_SECRET ? 'Set ✅' : 'Missing ❌');

// Validate critical environment variables at startup
const requiredEnvVars = ['ATLAS_URI', 'JWT_SECRET', 'JWT_REFRESH_SECRET'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error(`FATAL ERROR: Missing required environment variables: ${missingVars.join(', ')}`);
    process.exit(1);
}

// Check JWT_SECRET length for security - FIXED SYNTAX ERROR
if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    console.error('FATAL ERROR: JWT_SECRET must be at least 32 characters long for security.');
    process.exit(1);
}

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const expressWinston = require('express-winston');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

// Graceful error handling for module loading
let userRoutes, aiRoutes;
try {
    userRoutes = require('./routes/users');
    aiRoutes = require('./routes/ai');
    console.log('✅ All route modules loaded successfully');
} catch (moduleError) {
    console.error('❌ Error loading route modules:', moduleError.message);
    console.log('⚠️ Running server without custom routes');
    // Create dummy routes to prevent crashes
    userRoutes = require('express').Router();
    aiRoutes = require('express').Router();
    
    userRoutes.get('/', (req, res) => {
        res.status(503).json({ 
            success: false, 
            message: 'User routes temporarily unavailable' 
        });
    });
    
    aiRoutes.get('/', (req, res) => {
        res.status(503).json({ 
            success: false, 
            message: 'AI routes temporarily unavailable' 
        });
    });
}

const app = express();

// Enhanced error handling for startup errors
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit immediately, let the app attempt to start
    setTimeout(() => {
        console.error('❌ Forced shutdown due to unhandled rejection');
        process.exit(1);
    }, 5000);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    // Don't exit immediately, let the app attempt to start
    setTimeout(() => {
        console.error('❌ Forced shutdown due to uncaught exception');
        process.exit(1);
    }, 5000);
});

// --- Enhanced Security Middleware Setup ---
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['https://sarkarisuccess.netlify.app'];

if (process.env.NODE_ENV !== 'production') {
    allowedOrigins.push('http://localhost:3000', 'http://localhost:5173', 'http://localhost:8080');
}

console.log('🌐 CORS Allowed Origins:', allowedOrigins);

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) {
            if (process.env.NODE_ENV === 'production') {
                console.warn('🚫 CORS blocked no-origin request in production');
                return callback(new Error('No-origin requests not allowed in production'));
            }
            return callback(null, true);
        }
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.warn('🚫 CORS blocked origin:', origin);
            callback(new Error(`Origin ${origin} not allowed by CORS policy`));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID'],
    exposedHeaders: ['X-Request-ID']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            manifestSrc: ["'self'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: 'same-origin' }
}));

app.use(compression());

app.use((req, res, next) => {
    req.id = Date.now().toString(36) + Math.random().toString(36).substr(2);
    res.setHeader('X-Request-ID', req.id);
    next();
});

app.use(express.json({
    limit: '10mb',
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(mongoSanitize({
    replaceWith: '_',
    onSanitize: ({ key, req }) => {
        console.warn(`⚠️ Sanitized input detected: ${key} in request ${req.id}`);
    }
}));

app.use(xss());

if (process.env.NODE_ENV !== 'test' && process.env.NODE_ENV !== 'production') {
    app.use(morgan('dev'));
}

if (process.env.NODE_ENV === 'production') {
    const logger = winston.createLogger({
        level: process.env.LOG_LEVEL || 'info',
        transports: [
            new winston.transports.Console({
                format: winston.format.simple()
            })
        ],
        format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.errors({ stack: true }),
            winston.format.json()
        )
    });

    app.use(expressWinston.logger({
        winstonInstance: logger,
        meta: true,
        msg: 'HTTP {{req.method}} {{req.url}} {{res.statusCode}} {{res.responseTime}}ms',
        expressFormat: true,
        colorize: false,
        skip: (req, res) => res.statusCode < 400
    }));
}

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again after 15 minutes',
        code: 'RATE_LIMIT_ERROR',
        retryAfter: '15 minutes'
    },
    skip: (req) => req.url === '/health' || req.url === '/'
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again in 15 minutes',
        code: 'AUTH_RATE_LIMIT_ERROR',
        retryAfter: '15 minutes'
    }
});

app.use('/api/', generalLimiter);

// --- Enhanced MongoDB Database Connection with Retry Logic ---
const connectDB = async () => {
    const maxRetries = 5;
    const retryDelay = 5000; // 5 seconds
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            console.log(`🔄 MongoDB connection attempt ${attempt}/${maxRetries}...`);
            
            const options = {
                maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
                minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || 5,
                serverSelectionTimeoutMS: 10000, // Increased timeout
                socketTimeoutMS: 45000,
                connectTimeoutMS: 30000,
                retryWrites: true,
                w: 'majority',
                monitorCommands: process.env.NODE_ENV !== 'production'
            };
            
            await mongoose.connect(process.env.ATLAS_URI, options);
            console.log('✅ MongoDB database connection established successfully');
            return; // Exit the retry loop on success
            
        } catch (err) {
            console.error(`❌ MongoDB connection attempt ${attempt} failed:`, err.message);
            
            if (attempt === maxRetries) {
                console.error('❌ All MongoDB connection attempts failed. Starting server without database.');
                // Don't exit - let the server start without database
                break;
            }
            
            console.log(`⏳ Retrying in ${retryDelay / 1000} seconds...`);
            await new Promise(resolve => setTimeout(resolve, retryDelay));
        }
    }
};

// Initialize database connection
connectDB().catch(err => {
    console.error('❌ Database connection initialization failed:', err);
    // Don't exit - continue with server startup
});

// MongoDB event listeners
mongoose.connection.on('error', err => {
    console.error('❌ MongoDB runtime error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('⚠️ Mongoose disconnected from MongoDB');
});

mongoose.connection.on('reconnected', () => {
    console.log('✅ Mongoose reconnected to MongoDB');
});

// --- API Routes ---
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'SarkariSuccess-Hub API is running!',
        version: '2.2',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        requestId: req.id
    });
});

app.get('/health', (req, res) => {
    const dbState = mongoose.connection.readyState;
    const dbStatus = dbState === 1 ? 'connected' : 'disconnected';
    
    const healthStatus = {
        success: true,
        status: dbState === 1 ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        version: '2.2',
        requestId: req.id,
        services: {
            database: {
                status: dbStatus,
                readyState: dbState,
                host: process.env.ATLAS_URI ? 'configured' : 'not configured'
            },
            server: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                environment: process.env.NODE_ENV || 'development'
            }
        }
    };
    
    const statusCode = dbState === 1 ? 200 : 503;
    res.status(statusCode).json(healthStatus);
});

// Rate limiting for auth routes
app.use('/api/users/login', authLimiter);
app.use('/api/users/register', authLimiter);
app.use('/api/users/refresh', authLimiter);

// Mount routes
app.use('/api/users', userRoutes);
app.use('/api/ai', aiRoutes);

console.log('🚀 API Routes mounted:');
console.log(' - /api/users (authentication & user management)');
console.log(' - /api/ai (AI-powered features)');

// --- Enhanced Error Handling Middleware ---
app.use((req, res) => {
    console.log(`❌ 404 Not Found: ${req.method} ${req.url} [${req.id}]`);
    res.status(404).json({
        success: false,
        message: 'Route not found. Please check the API documentation for valid endpoints.',
        timestamp: new Date().toISOString(),
        requestId: req.id,
        availableRoutes: [
            'GET /',
            'GET /health',
            'POST /api/users/register',
            'POST /api/users/login',
            'GET /api/ai/health',
            'POST /api/ai/chat',
            'POST /api/ai/summarize'
        ]
    });
});

app.use((err, req, res, next) => {
    const errorId = `${req.id || Date.now().toString(36)}-${Math.random().toString(36).substr(2)}`;
    
    console.error(`❌ Error [${errorId}]:`, {
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.id,
        timestamp: new Date().toISOString(),
        userId: req.user?.id || 'anonymous'
    });
    
    const status = err.status || err.statusCode || 500;
    let message;
    
    if (status >= 500) {
        message = process.env.NODE_ENV === 'production'
            ? 'Internal Server Error'
            : err.message;
    } else {
        message = err.message || 'Bad Request';
        // Sanitize sensitive information from error messages
        message = message.replace(/mongodb|mongoose|database|connection/gi, 'system');
        message = message.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, 'server');
    }
    
    res.status(status).json({
        success: false,
        message,
        timestamp: new Date().toISOString(),
        requestId: req.id,
        ...(process.env.NODE_ENV !== 'production' && { errorId })
    });
});

// --- Server Startup with Enhanced Error Handling ---
const startServer = async () => {
    try {
        const server = app.listen(PORT, () => {
            console.log(`🚀 SarkariSuccess-Hub API running on port ${PORT}`);
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔗 Health Check: http://localhost:${PORT}/health`);
            
            const hasOpenAIKey = !!process.env.OPENAI_API_KEY;
            console.log(`🤖 OpenAI Integration: ${hasOpenAIKey ? '✅ Configured' : '❌ Missing API Key'}`);
            
            // Test database connection status
            const dbState = mongoose.connection.readyState;
            console.log(`💾 Database Status: ${dbState === 1 ? '✅ Connected' : '⚠️ Disconnected'}`);
        });

        const gracefulShutdown = (signal) => {
            console.log(`⚠️ ${signal} received. Shutting down gracefully...`);
            
            server.close((err) => {
                if (err) {
                    console.error('❌ Error during server shutdown:', err);
                } else {
                    console.log('✅ Server closed successfully');
                }
                
                mongoose.connection.close(false, () => {
                    console.log('✅ MongoDB connection closed');
                    process.exit(err ? 1 : 0);
                });
            });
            
            // Force shutdown after 10 seconds
            setTimeout(() => {
                console.error('❌ Forced shutdown after 10 seconds');
                process.exit(1);
            }, 10000);
        };

        // Graceful shutdown handlers
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));
        
    } catch (startupError) {
        console.error('❌ Failed to start server:', startupError);
        process.exit(1);
    }
};

// Start the server
startServer();