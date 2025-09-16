require('dotenv').config();

// Validate critical environment variables at startup
const requiredEnvVars = ['ATLAS_URI', 'JWT_SECRET', 'JWT_REFRESH_SECRET'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  console.error(`FATAL ERROR: Missing required environment variables: ${missingVars.join(', ')}`);
  process.exit(1);
}

if (process.env.JWT_SECRET.length < 32) {
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
const fs = require('fs');

// Import individual route files
const userRoutes = require('./routes/users');
const aiRoutes = require('./routes/ai');

const app = express();
const PORT = process.env.PORT || 10000;

// Create logs directory if it doesn't exist
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// --- Enhanced Security Middleware Setup ---

// FIXED: Stricter CORS configuration with enhanced security
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['https://sarkarisuccess.netlify.app'];

// Always add localhost for development
if (process.env.NODE_ENV !== 'production') {
  allowedOrigins.push('http://localhost:3000', 'http://localhost:5173', 'http://localhost:8080');
}

console.log('🌐 CORS Allowed Origins:', allowedOrigins);

const corsOptions = {
  origin: (origin, callback) => {
    // FIXED: Don't allow requests with no origin in production
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

// Enhanced Helmet configuration for security headers
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
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  frameguard: { action: 'deny' },
  xssFilter: true,
  referrerPolicy: { policy: 'same-origin' }
}));

// Compression middleware
app.use(compression());

// Body parsing with size limits and request ID
app.use((req, res, next) => {
  // Generate unique request ID for tracking
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

// ENHANCED: More comprehensive input sanitization
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ key, req }) => {
    console.warn(`⚠️ Sanitized input detected: ${key} in request ${req.id}`);
  }
}));
app.use(xss());

// Logging middleware
if (process.env.NODE_ENV !== 'test' && process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

if (process.env.NODE_ENV === 'production') {
  const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    transports: [
      new winston.transports.File({ filename: 'logs/combined.log' }),
      new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
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

// FIXED: Optimized rate limiting with better UX
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again after 15 minutes',
    code: 'RATE_LIMIT_ERROR',
    retryAfter: '15 minutes'
  },
  skip: (req) => {
    return req.url === '/health' || req.url === '/';
  }
});

// FIXED: Less restrictive auth rate limiting for better UX
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // FIXED: Increased from 5 to 10 for better UX
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

// Apply rate limiting
app.use('/api/', generalLimiter);

// --- Enhanced MongoDB Database Connection ---
const connectDB = async () => {
  try {
    const options = {
      // Core connection pool settings
      maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
      minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || 5,
      // Timeout settings
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 30000,
      // Write concern and reliability
      retryWrites: true,
      w: 'majority',
      // ENHANCED: Additional monitoring options
      monitorCommands: process.env.NODE_ENV !== 'production'
    };

    await mongoose.connect(process.env.ATLAS_URI, options);
    console.log('✅ MongoDB database connection established successfully');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
};

connectDB();

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

// Root endpoint with enhanced information
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'SarkariSuccess-Hub API is running!',
    version: '2.2', // Updated version
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    requestId: req.id
  });
});

// ENHANCED: More detailed health check endpoint
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

// Apply auth rate limiting to authentication routes
app.use('/api/users/login', authLimiter);
app.use('/api/users/register', authLimiter);
app.use('/api/users/refresh', authLimiter);

// Mount routes
app.use('/api/users', userRoutes);
app.use('/api/ai', aiRoutes);

// Log mounted routes for debugging
console.log('🚀 API Routes mounted:');
console.log(' - /api/users (authentication & user management)');
console.log(' - /api/ai (AI-powered features)');

// --- Enhanced Error Handling Middleware ---

// 404 handler with sanitized response
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

// ENHANCED: Global error handler with better security and logging
app.use((err, req, res, next) => {
  // Generate error ID for tracking
  const errorId = `${req.id || Date.now().toString(36)}-${Math.random().toString(36).substr(2)}`;
  
  // Enhanced error logging
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

  // Determine error status and message
  const status = err.status || err.statusCode || 500;
  let message;

  // FIXED: Sanitize error messages to prevent information disclosure
  if (status >= 500) {
    message = process.env.NODE_ENV === 'production'
      ? 'Internal Server Error'
      : err.message;
  } else {
    // Sanitize client error messages
    message = err.message || 'Bad Request';
    // Remove sensitive information patterns
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

// --- Server Activation ---
const server = app.listen(PORT, () => {
  console.log(`🚀 SarkariSuccess-Hub API running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health Check: http://localhost:${PORT}/health`);

  // Show OpenAI integration status
  const hasOpenAIKey = !!process.env.OPENAI_API_KEY;
  console.log(`🤖 OpenAI Integration: ${hasOpenAIKey ? '✅ Configured' : '❌ Missing API Key'}`);
});

// Enhanced graceful shutdown handling
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

  // Force exit if graceful shutdown takes too long
  setTimeout(() => {
    console.error('❌ Forced shutdown after 10 seconds');
    process.exit(1);
  }, 10000);
};

process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Promise Rejection:', err);
  gracefulShutdown('UNHANDLED_REJECTION');
});

process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = { app, server };