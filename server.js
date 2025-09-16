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

// Import individual route files
const userRoutes = require('./routes/users');
const aiRoutes = require('./routes/ai');

const app = express();
const PORT = process.env.PORT || 10000;

// REMOVED: No need to create a 'logs' directory on ephemeral filesystems like Render.
// if (!fs.existsSync('logs')) {
//   fs.mkdirSync('logs');
// }

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
      // CHANGED: Log only to console in production. Render will handle log storage.
      new winston.transports.Console({
        format: winston.format.simple()
      })
      // REMOVED: File transports are not ideal for ephemeral filesystems.
      // new winston.transports.File({ filename: 'logs/combined.log' }),
      // new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
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

// --- Enhanced MongoDB Database Connection ---
const connectDB = async () => {
  try {
    const options = {
      maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
      minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || 5,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 30000,
      retryWrites: true,
      w: 'majority',
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

app.use('/api/users/login', authLimiter);
app.use('/api/users/register', authLimiter);
app.use('/api/users/refresh', authLimiter);

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

  const hasOpenAIKey = !!process.env.OPENAI_API_KEY;
  console.log(`🤖 OpenAI Integration: ${hasOpenAIKey ? '✅ Configured' : '❌ Missing API Key'}`);
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

// REMOVED: Unnecessary for the main entry point file.
// module.exports = { app, server };