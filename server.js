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

// FIXED: Check JWT_SECRET length for security
if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
  console.error('FATAL ERROR: JWT_SECRET must be at least 32 characters long for security.');
  process.exit(1);
}

console.log('✅ All environment variables validated');

// Core dependencies
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

console.log('✅ Core modules loaded successfully');

// Create logs directory if it doesn't exist
const fs = require('fs');
const path = require('path');

if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs', { recursive: true });
  console.log('📁 Created logs directory');
}

// Enhanced error handling for route module loading
const createFallbackRouter = (routeName) => {
  const router = express.Router();
  
  // Health check endpoint
  router.get('/health', (req, res) => {
    res.status(503).json({
      success: false,
      message: `${routeName} routes temporarily unavailable`,
      error: 'Route module failed to load',
      timestamp: new Date().toISOString()
    });
  });
  
  // Catch all other routes
  router.all('*', (req, res) => {
    res.status(503).json({
      success: false,
      message: `${routeName} routes temporarily unavailable`,
      error: 'Route module failed to load',
      availableEndpoints: ['GET /health'],
      requestedEndpoint: `${req.method} ${req.path}`,
      timestamp: new Date().toISOString()
    });
  });
  
  return router;
};

const loadRouteModule = (path, name) => {
  try {
    const module = require(path);
    console.log(`✅ Loaded ${name} routes successfully`);
    return module;
  } catch (moduleError) {
    console.error(`❌ Error loading ${name} routes from '${path}':`, moduleError.message);
    console.log(`⚠️ Creating fallback routes for ${name}`);
    return createFallbackRouter(name);
  }
};

// Load routes with fallback
const userRoutes = loadRouteModule('./routes/users', 'users');
const progressRoutes = loadRouteModule('./routes/progress', 'progress');
const quizzesRoutes = loadRouteModule('./routes/quizzes', 'quizzes');
const toolsRoutes = loadRouteModule('./routes/tools', 'tools');

const app = express();

// Enhanced error handling for startup errors
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  setTimeout(() => {
    console.error('❌ Forced shutdown due to unhandled rejection');
    process.exit(1);
  }, 5000);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  setTimeout(() => {
    console.error('❌ Forced shutdown due to uncaught exception');
    process.exit(1);
  }, 5000);
});

// --- Security Middleware Setup ---
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['https://testtitans.netlify.app', 'https://sarkarisuccess.netlify.app'];

if (process.env.NODE_ENV !== 'production') {
  allowedOrigins.push('http://localhost:3000', 'http://localhost:5173', 'http://localhost:8080');
}

console.log('🌐 CORS Allowed Origins:', allowedOrigins);

const corsOptions = {
  origin: (origin, callback) => {
    // Allow no-origin requests for public paths (like health checks)
    if (!origin) {
      return callback(null, true); // FIXED: Always allow no-origin requests
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
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID', 'Accept'],
  exposedHeaders: ['X-Request-ID']
};

// Apply CORS middleware
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Security middleware
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
      manifestSrc: ["'self'"]
    }
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

// Request ID and timing middleware
app.use((req, res, next) => {
  req.id = Date.now().toString(36) + Math.random().toString(36).substr(2);
  req.startTime = Date.now();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Body parsing middleware
app.use(express.json({
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security sanitization middleware
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ key, req }) => {
    console.warn(`⚠️ Sanitized input detected: ${key} in request ${req.id}`);
  }
}));

app.use(xss());

// Rate limiting middleware
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again after 15 minutes',
    code: 'RATE_LIMIT_ERROR',
    retryAfter: '15 minutes'
  },
  skip: (req) => req.url === '/health' || req.url === '/' || req.url === '/api/health'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 auth attempts per windowMs
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

// Apply general rate limiting
app.use('/api/', generalLimiter);

// --- FIXED: MongoDB Database Connection with Retry Logic ---
const connectDB = async () => {
  const maxRetries = 5;
  const retryDelay = 5000; // 5 seconds
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`🔄 Database connection attempt ${attempt}/${maxRetries}...`);
      
      // FIXED: Corrected MongoDB connection options
      const options = {
        maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
        minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || 5,
        serverSelectionTimeoutMS: 15000, // 15 seconds
        socketTimeoutMS: 45000,
        connectTimeoutMS: 30000,
        retryWrites: true,
        w: 'majority'
      };
      
      await mongoose.connect(process.env.ATLAS_URI, options);
      console.log('✅ MongoDB database connection established successfully');
      
      // Set up connection event handlers
      mongoose.connection.on('error', err => {
        console.error('❌ MongoDB runtime error:', err);
      });
      
      mongoose.connection.on('disconnected', () => {
        console.log('⚠️ Mongoose disconnected from MongoDB');
      });
      
      mongoose.connection.on('reconnected', () => {
        console.log('✅ Mongoose reconnected to MongoDB');
      });
      
      return; // Exit the retry loop on success
    } catch (err) {
      console.error(`❌ Database connection attempt ${attempt} failed:`, err.message);
      
      if (attempt === maxRetries) {
        console.error('🚨 FATAL: Could not connect to database after maximum retries');
        process.exit(1);
      }
      
      console.log(`⏳ Retrying in ${retryDelay / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
  }
};

// Initialize database connection
connectDB().catch(err => {
  console.error('❌ Database connection initialization failed:', err);
  process.exit(1);
});

// --- API Routes ---

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'SarkariSuccess-Hub API is running!',
    version: '2.2',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    requestId: req.id,
    responseTime: (Date.now() - req.startTime) + 'ms'
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStateMap = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  
  const dbStatus = dbStateMap[dbState] || 'unknown';
  
  const healthStatus = {
    success: true,
    status: dbState === 1 ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    version: '2.2',
    requestId: req.id,
    responseTime: (Date.now() - req.startTime) + 'ms',
    services: {
      database: {
        status: dbStatus,
        readyState: dbState,
        host: process.env.ATLAS_URI ? 'configured' : 'not configured'
      },
      server: {
        uptime: process.uptime() + ' seconds',
        memory: {
          used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
          total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB'
        },
        environment: process.env.NODE_ENV || 'development',
        nodeVersion: process.version
      },
      features: {
        openai: !!process.env.OPENAI_API_KEY,
        cors: allowedOrigins.length > 0,
        rateLimit: true,
        security: true
      }
    }
  };
  
  const statusCode = dbState === 1 ? 200 : 503;
  res.status(statusCode).json(healthStatus);
});

// API health endpoint
app.get('/api/health', (req, res) => {
  res.redirect('/health');
});

// Rate limiting for auth routes
app.use('/api/users/login', authLimiter);
app.use('/api/users/register', authLimiter);
app.use('/api/users/refresh-token', authLimiter);

// Mount API routes
app.use('/api/users', userRoutes);
app.use('/api/progress', progressRoutes);
app.use('/api/quizzes', quizzesRoutes);
app.use('/api/tools', toolsRoutes);

console.log('🚀 API Routes mounted:');
console.log(' - /api/users (authentication & user management)');
console.log(' - /api/progress (progress tracking)');
console.log(' - /api/quizzes (quiz management)');
console.log(' - /api/tools (tool management)');

// --- Error Handling Middleware ---

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  console.log(`❌ API 404 Not Found: ${req.method} ${req.url} [${req.id}]`);
  res.status(404).json({
    success: false,
    message: 'API endpoint not found. Please check the API documentation for valid endpoints.',
    timestamp: new Date().toISOString(),
    requestId: req.id,
    requestedEndpoint: `${req.method} ${req.path}`,
    availableRoutes: [
      'GET /health',
      'GET /api/health',
      'POST /api/users/register',
      'POST /api/users/login',
      'POST /api/users/refresh-token',
      'GET /api/users/profile',
      'GET /api/progress',
      'GET /api/quizzes',
      'GET /api/tools'
    ]
  });
});

// General 404 handler
app.use((req, res) => {
  console.log(`❌ 404 Not Found: ${req.method} ${req.url} [${req.id}]`);
  res.status(404).json({
    success: false,
    message: 'Route not found.',
    timestamp: new Date().toISOString(),
    requestId: req.id,
    suggestion: 'Try accessing /api/ endpoints or check the API documentation.'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  const errorId = `${req.id || Date.now().toString(36)}-${Math.random().toString(36).substr(2)}`;
  
  // Enhanced error logging
  const errorInfo = {
    errorId,
    message: err.message,
    name: err.name,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    url: req.url,
    method: req.method,
    ip: req.ip || req.connection?.remoteAddress,
    userAgent: req.get('User-Agent'),
    requestId: req.id,
    timestamp: new Date().toISOString(),
    userId: req.user?.id || 'anonymous',
    body: process.env.NODE_ENV === 'development' ? req.body : undefined
  };
  
  console.error(`❌ Global Error [${errorId}]:`, errorInfo);
  
  const status = err.status || err.statusCode || 500;
  let message;
  
  // Handle specific error types
  if (err.name === 'ValidationError') {
    message = 'Request validation failed';
  } else if (err.name === 'CastError') {
    message = 'Invalid data format provided';
  } else if (err.name === 'MongoError' && err.code === 11000) {
    message = 'Duplicate data detected';
  } else if (status >= 500) {
    message = process.env.NODE_ENV === 'production'
      ? 'Internal Server Error'
      : err.message;
  } else {
    message = err.message || 'Bad Request';
  }
  
  // Sanitize sensitive information from error messages
  message = message.replace(/mongodb|mongoose|database|connection/gi, 'system');
  message = message.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, 'server');
  
  res.status(status).json({
    success: false,
    message,
    timestamp: new Date().toISOString(),
    requestId: req.id,
    ...(process.env.NODE_ENV !== 'production' && {
      errorId,
      type: err.name
    })
  });
});

// --- Server Startup with Enhanced Error Handling ---
const startServer = async () => {
  try {
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 SarkariSuccess-Hub API running on port ${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 Local URL: http://localhost:${PORT}`);
      console.log(`🔗 Health Check: http://localhost:${PORT}/health`);
      
      // Feature status
      const hasOpenAIKey = !!process.env.OPENAI_API_KEY;
      console.log(`🤖 OpenAI Integration: ${hasOpenAIKey ? '✅ Configured' : '❌ Missing API Key'}`);
      
      // Database status
      const dbState = mongoose.connection.readyState;
      console.log(`💾 Database Status: ${dbState === 1 ? '✅ Connected' : '⚠️ Connecting...'}`);
      
      // Security status
      console.log(`🔒 Security Features: ✅ Helmet, CORS, Rate Limiting, XSS Protection`);
      console.log(`📝 Logging: ${process.env.NODE_ENV === 'production' ? '✅ Production' : '✅ Development'}`);
      console.log('\n--- Server Ready ---');
    });
    
    // Configure server timeouts
    server.timeout = 30000; // 30 seconds
    server.keepAliveTimeout = 65000; // 65 seconds
    server.headersTimeout = 66000; // 66 seconds
    
    // Graceful shutdown handlers
    const gracefulShutdown = async (signal) => {
      console.log(`\n⚠️ ${signal} received. Shutting down gracefully...`);
      
      server.close((err) => {
        if (err) {
          console.error('❌ Error during server shutdown:', err);
        } else {
          console.log('✅ HTTP Server closed successfully');
        }
        
        // FIXED: Close database connection without callback
        mongoose.connection.close()
          .then(() => {
            console.log('✅ MongoDB connection closed');
            process.exit(err ? 1 : 0);
          })
          .catch((dbErr) => {
            console.error('❌ Error closing MongoDB connection:', dbErr);
            process.exit(1);
          });
      });
      
      // Force shutdown after 10 seconds
      setTimeout(() => {
        console.error('❌ Forced shutdown after 10 seconds');
        process.exit(1);
      }, 10000);
    };
    
    // Register shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
  } catch (startupError) {
    console.error('❌ Failed to start server:', startupError);
    process.exit(1);
  }
};

// Start the server
startServer();

// Export for testing
module.exports = app;