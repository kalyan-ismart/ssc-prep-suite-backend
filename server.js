// server.js

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const expressWinston = require('express-winston');
const apiRoutes = require('./routes'); // Centralized API routes

const app = express();
const PORT = process.env.PORT || 10000;

// --- Middleware Setup ---

// CORS configuration to allow frontend origin
const corsOptions = {
  origin: ['https://sarkarisuccess.netlify.app'], // Replace with your frontend URL
  credentials: true,
};
app.use(cors(corsOptions));

// Security, compression, and body parsing
app.use(helmet());
app.use(compression());
app.use(express.json());

// HTTP request logger
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('dev'));
}

// Advanced logging with Winston for production
if (process.env.NODE_ENV === 'production') {
  const logger = winston.createLogger({
    transports: [
      new winston.transports.File({ filename: 'combined.log' }),
      new winston.transports.Console()
    ]
  });
  app.use(expressWinston.logger({
    winstonInstance: logger,
    meta: true,
    msg: 'HTTP {{req.method}} {{req.url}}',
    expressFormat: true,
    colorize: false
  }));
}

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 requests per IP per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);


// --- Database Connection ---

const uri = process.env.ATLAS_URI;
if (!uri) {
  console.error('FATAL ERROR: ATLAS_URI is not defined in environment variables.');
  process.exit(1); // Exit if no database connection string
}

mongoose.connect(uri)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

mongoose.connection.on('error', err => {
  console.error('MongoDB runtime error:', err);
});


// --- API Routes ---

// Base/Health Check Route
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'SarkariSuccess-Hub API is running!',
    platform: 'Comprehensive Government Exam Preparation Hub',
    version: '2.0',
  });
});

// Register all API routes
app.use(apiRoutes);


// --- Error Handling Middleware ---

// 404 handler for unmatched routes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found. Please check the API documentation for valid endpoints.',
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'An unexpected error occurred on the server.',
    error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message
  });
});


// --- Server Activation ---

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SarkariSuccess-Hub API running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

// Export app for testing purposes
module.exports = app;