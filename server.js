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

// ENHANCED: Validate JWT secret strength
if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 64) {
    console.error('FATAL ERROR: JWT_SECRET must be at least 64 characters long for security');
    process.exit(1);
} // FIXED: Added missing closing brace

if (process.env.JWT_REFRESH_SECRET && process.env.JWT_REFRESH_SECRET.length < 64) {
    console.error('FATAL ERROR: JWT_REFRESH_SECRET must be at least 64 characters long for security');
    process.exit(1);
}

console.log('✅ All environment variables validated');

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

// Import routes
const usersRoutes = require('./routes/users');
const quizzesRoutes = require('./routes/quizzes');
const progressRoutes = require('./routes/progress');
const toolsRoutes = require('./routes/tools');

const app = express();

// ENHANCED: Configure comprehensive logger
const logger = winston.createLogger({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            maxsize: 10485760, // 10MB
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            maxsize: 10485760,
            maxFiles: 5
        })
    ]
});

// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

// ENHANCED: Request ID middleware
app.use((req, res, next) => {
    req.id = uuidv4();
    req.timestamp = new Date().toISOString();
    res.setHeader('X-Request-ID', req.id);
    next();
});

// ENHANCED: Comprehensive security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// ENHANCED: Dynamic CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = process.env.ALLOWED_ORIGINS 
            ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
            : ['http://localhost:3000', 'http://localhost:3001', 'https://testtitans.netlify.app'];
        
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked origin: ${origin}`, { 
                origin, 
                allowedOrigins,
                requestId: 'cors-check'
            });
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
    exposedHeaders: ['X-Request-ID']
};

app.use(cors(corsOptions));

// ENHANCED: Tiered rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again later',
        retryAfter: Math.ceil(15 * 60 * 1000 / 1000) // seconds
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for authentication', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            endpoint: req.path,
            requestId: req.id
        });
        res.status(429).json({
            success: false,
            message: 'Too many authentication attempts, please try again later',
            retryAfter: Math.ceil(15 * 60 * 1000 / 1000)
        });
    }
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: {
        success: false,
        message: 'Too many requests, please try again later'
    },
    standardHeaders: true,
    legacyHeaders: false
});

// ENHANCED: Body parsing with size limits
app.use(express.json({ 
    limit: '50mb',
    verify: (req, res, buf, encoding) => {
        // Store raw body for signature verification if needed
        req.rawBody = buf;
    }
}));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ENHANCED: Security middleware stack
app.use(mongoSanitize()); // Prevent NoSQL injection
app.use(xss()); // Clean user input from malicious HTML
app.use(hpp()); // Prevent HTTP Parameter Pollution
app.use(compression()); // Compress responses

// Apply rate limiting
app.use('/api/users/login', authLimiter);
app.use('/api/users/register', authLimiter);
app.use('/api/users/refresh-token', authLimiter);
app.use(generalLimiter);

// ENHANCED: Request logging middleware
app.use((req, res, next) => {
    const startTime = Date.now();
    
    // Log request
    logger.info('Incoming request', {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.id,
        timestamp: req.timestamp
    });

    // Override res.end to log response
    const originalEnd = res.end;
    res.end = function(chunk, encoding) {
        const responseTime = Date.now() - startTime;
        
        logger.info('Outgoing response', {
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            responseTime: `${responseTime}ms`,
            requestId: req.id
        });

        // Call the original end method
        originalEnd.call(this, chunk, encoding);
    };

    next();
});

// ENHANCED: Database connection with retry logic and monitoring
const connectDB = async () => {
    const maxRetries = 5;
    const retryDelay = 5000; // 5 seconds
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            console.log(`🔄 Database connection attempt ${attempt}/${maxRetries}...`);
            
            await mongoose.connect(process.env.ATLAS_URI, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                maxPoolSize: parseInt(process.env.DB_POOL_SIZE) || 10,
                serverSelectionTimeoutMS: 15000, // 15 seconds
                socketTimeoutMS: 45000, // 45 seconds
                bufferCommands: false,
                bufferMaxEntries: 0
            });
            
            console.log('✅ MongoDB Connected Successfully');
            logger.info('Database connected successfully', {
                attempt,
                maxRetries,
                poolSize: parseInt(process.env.DB_POOL_SIZE) || 10
            });
            
            // Monitor connection events
            mongoose.connection.on('error', (err) => {
                logger.error('MongoDB connection error:', err);
            });
            
            mongoose.connection.on('disconnected', () => {
                logger.warn('MongoDB disconnected');
            });
            
            mongoose.connection.on('reconnected', () => {
                logger.info('MongoDB reconnected');
            });
            
            return;
        } catch (error) {
            console.error(`❌ Database connection attempt ${attempt} failed:`, error.message);
            logger.error('Database connection failed', {
                attempt,
                maxRetries,
                error: error.message,
                stack: error.stack
            });
            
            if (attempt === maxRetries) {
                console.error('🚨 FATAL: Could not connect to database after maximum retries');
                process.exit(1);
            }
            
            console.log(`⏳ Retrying in ${retryDelay / 1000} seconds...`);
            await new Promise(resolve => setTimeout(resolve, retryDelay));
        }
    }
};

// ENHANCED: Health check endpoint
app.get('/health', async (req, res) => {
    const healthCheck = {
        uptime: process.uptime(),
        message: 'OK',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        version: process.env.npm_package_version || '1.0.0',
        requestId: req.id
    };

    try {
        // Check database connection
        if (mongoose.connection.readyState === 1) {
            healthCheck.database = 'Connected';
        } else {
            healthCheck.database = 'Disconnected';
            healthCheck.message = 'Partial Service';
        }

        // Check external dependencies
        healthCheck.dependencies = {
            mongodb: mongoose.connection.readyState === 1 ? 'OK' : 'ERROR',
            openai: process.env.OPENAI_API_KEY ? 'Configured' : 'Missing'
        };

        const status = healthCheck.message === 'OK' ? 200 : 503;
        res.status(status).json(healthCheck);
    } catch (error) {
        healthCheck.message = 'ERROR';
        healthCheck.error = error.message;
        res.status(503).json(healthCheck);
    }
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'SarkariSuccess Hub API',
        version: '2.0.0',
        environment: process.env.NODE_ENV || 'development',
        timestamp: new Date().toISOString(),
        requestId: req.id,
        endpoints: {
            health: '/health',
            users: '/api/users',
            quizzes: '/api/quizzes',
            progress: '/api/progress',
            tools: '/api/tools'
        }
    });
});

// API Routes
app.use('/api/users', usersRoutes);
app.use('/api/quizzes', quizzesRoutes);
app.use('/api/progress', progressRoutes);
app.use('/api/tools', toolsRoutes);

// ENHANCED: 404 handler
app.use('*', (req, res) => {
    logger.warn('404 Not Found', {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.id
    });
    
    res.status(404).json({
        success: false,
        message: 'Endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
        requestId: req.id
    });
});

// ENHANCED: Global error handler
app.use((error, req, res, next) => {
    const errorId = uuidv4();
    
    // Log error with context
    logger.error('Unhandled error', {
        errorId,
        message: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.id,
        body: req.body,
        params: req.params,
        query: req.query
    });

    // Don't expose internal errors in production
    const isDevelopment = process.env.NODE_ENV !== 'production';
    
    res.status(error.status || 500).json({
        success: false,
        message: isDevelopment ? error.message : 'Internal server error',
        errorId,
        requestId: req.id,
        timestamp: new Date().toISOString(),
        ...(isDevelopment && { 
            stack: error.stack,
            details: error 
        })
    });
});

// ENHANCED: Graceful shutdown handlers
const gracefulShutdown = async (signal) => {
    console.log(`\n📡 Received ${signal}. Starting graceful shutdown...`);
    logger.info(`Graceful shutdown initiated by ${signal}`);
    
    try {
        // Close server
        if (server) {
            await new Promise((resolve) => {
                server.close(resolve);
            });
            console.log('✅ HTTP server closed');
        }
        
        // Close database connection
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.close();
            console.log('✅ Database connection closed');
        }
        
        console.log('✅ Graceful shutdown completed');
        logger.info('Graceful shutdown completed successfully');
        process.exit(0);
    } catch (error) {
        console.error('❌ Error during shutdown:', error);
        logger.error('Error during graceful shutdown', { error: error.message, stack: error.stack });
        process.exit(1);
    }
};

// Register shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Promise Rejection', {
        reason: reason?.message || reason,
        stack: reason?.stack,
        promise: promise.toString()
    });
    
    console.error('🚨 Unhandled Promise Rejection:', reason);
    gracefulShutdown('unhandledRejection');
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', {
        message: error.message,
        stack: error.stack
    });
    
    console.error('🚨 Uncaught Exception:', error);
    gracefulShutdown('uncaughtException');
});

// Initialize application
const startServer = async () => {
    try {
        // Connect to database first
        await connectDB();
        
        // Start server
        const server = app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 SarkariSuccess Hub API Server running on port ${PORT}`);
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔗 Health check: http://localhost:${PORT}/health`);
            logger.info('Server started successfully', {
                port: PORT,
                environment: process.env.NODE_ENV || 'development'
            });
        });

        // Configure server timeouts
        server.timeout = 30000; // 30 seconds
        server.keepAliveTimeout = 65000; // 65 seconds
        server.headersTimeout = 66000; // 66 seconds

        // Store server reference for graceful shutdown
        global.server = server;
        
    } catch (error) {
        console.error('🚨 Failed to start server:', error);
        logger.error('Server startup failed', { error: error.message, stack: error.stack });
        process.exit(1);
    }
};

// Start the server
startServer();

module.exports = app;