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
const apiRoutes = require('./routes'); // Centralized API routes

const app = express();
const PORT = process.env.PORT || 10000;

// Create logs directory if it doesn't exist
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// --- Enhanced Security Middleware Setup ---

// Dynamic CORS configuration with enhanced security
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['https://sarkarisuccess.netlify.app'];

if (process.env.NODE_ENV !== 'production') {
  allowedOrigins.push('http://localhost:3000', 'http://localhost:5173', 'http://localhost:8080');
}

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200 // Support legacy browsers
};

app.use(cors(corsOptions));

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

// Body parsing with size limits
app.use(express.json({
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security middleware for input sanitization
app.use(mongoSanitize()); // Prevent NoSQL injection attacks
app.use(xss()); // Clean user input from malicious HTML

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

// Enhanced rate limiting with different tiers
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // General API limit
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again after 15 minutes',
    code: 'RATE_LIMIT_ERROR'
  },
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.url === '/health';
  }
});

// Stricter rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 authentication attempts per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later',
    code: 'AUTH_RATE_LIMIT_ERROR'
  }
});

// Apply rate limiting
app.use('/api/', generalLimiter);

// --- FIXED MongoDB Database Connection ---
const connectDB = async () => {
  try {
    // ✅ FIXED: Use only safe, universally supported MongoDB options
    const options = {
      // Core connection pool settings
      maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
      minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || 5,
      
      // Timeout settings (well supported)
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 30000,
      
      // Write concern and reliability
      retryWrites: true,
      w: 'majority'
      
      // ❌ REMOVED: These options were causing the deployment error:
      // ssl: process.env.NODE_ENV === 'production',
      // sslValidate: process.env.NODE_ENV === 'production',
      // authTimeoutMS: 10000,
    };

    await mongoose.connect(process.env.ATLAS_URI, options);
    console.log('MongoDB database connection established successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

connectDB();

mongoose.connection.on('error', err => {
  console.error('MongoDB runtime error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected from MongoDB');
});

mongoose.connection.on('reconnected', () => {
  console.log('Mongoose reconnected to MongoDB');
});

// --- API Routes ---
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'SarkariSuccess-Hub API is running!',
    version: '2.1',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/health', (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStatus = dbState === 1 ? 'connected' : 'disconnected';
  
  res.json({
    success: true,
    status: 'healthy',
    database: dbStatus,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: '2.1'
  });
});

// Apply auth rate limiting to authentication routes
app.use('/api/users/login', authLimiter);
app.use('/api/users/register', authLimiter);

// Main API routes
app.use('/api', apiRoutes);

// --- Enhanced Error Handling Middleware ---
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found. Please check the API documentation for valid endpoints.',
    timestamp: new Date().toISOString()
  });
});

// Global error handler with security considerations
app.use((err, req, res, next) => {
  // Log error details securely
  const errorId = Date.now().toString(36) + Math.random().toString(36).substr(2);
  
  console.error(`Error [${errorId}]:`, {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });

  // Determine error status and message
  const status = err.status || err.statusCode || 500;
  let message;
  
  if (status >= 500) {
    message = process.env.NODE_ENV === 'production'
      ? 'Internal Server Error'
      : err.message;
  } else {
    message = err.message || 'Bad Request';
  }

  res.status(status).json({
    success: false,
    message,
    errorId: process.env.NODE_ENV === 'production' ? errorId : undefined,
    timestamp: new Date().toISOString()
  });
});

// --- Server Activation ---
const server = app.listen(PORT, () => {
  console.log(`SarkariSuccess-Hub API running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown handling
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  server.close(() => {
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed.');
      process.exit(0);
    });
  });
});

module.exports = { app, server };