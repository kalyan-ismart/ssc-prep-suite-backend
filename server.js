const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const expressWinston = require('express-winston');

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;

// Security and performance middleware
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Advanced logging (Winston)
const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console()
  ]
});
app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: true,
  msg: "HTTP {{req.method}} {{req.url}}",
  expressFormat: true,
  colorize: false,
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// MongoDB connection
const uri = process.env.ATLAS_URI;
if (!uri) {
  throw new Error('ATLAS_URI is not defined in environment variables');
}
mongoose.connect(uri)
  .then(() => console.log("MongoDB database connection established successfully"))
  .catch(err => console.error("MongoDB connection error:", err));

const connection = mongoose.connection;
connection.once('open', () => {
  console.log("SarkariSuccess-Hub Backend API connected to MongoDB successfully");
});

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'SarkariSuccess-Hub Backend API is running!',
    status: 'success',
    platform: 'Comprehensive Government Exam Preparation Hub',
    version: '2.0.0',
    endpoints: {
      tools: '/tools',
      categories: '/categories',
      users: '/users',
      progress: '/progress',
      analytics: '/analytics',
      quizzes: '/quizzes',
      goals: '/goals',
      examSchedule: '/exam-schedule'
    }
  });
});

// Enhanced Routes for SarkariSuccess-Hub
const toolsRouter = require('./routes/tools');
const categoriesRouter = require('./routes/categories');
const usersRouter = require('./routes/users');
const progressRouter = require('./routes/progress');
const analyticsRouter = require('./routes/analytics');

// Ensure these files exist, even as placeholders:
const quizzesRouter = require('./routes/quizzes');
const goalsRouter = require('./routes/goals');
const examScheduleRouter = require('./routes/examSchedule');

// API Routes
app.use('/tools', toolsRouter);
app.use('/categories', categoriesRouter);
app.use('/users', usersRouter);
app.use('/progress', progressRouter);
app.use('/analytics', analyticsRouter);
app.use('/quizzes', quizzesRouter);
app.use('/goals', goalsRouter);
app.use('/exam-schedule', examScheduleRouter);

// Legacy support for existing modules endpoint (backward compatibility)
const modulesRouter = require('./routes/modules');
app.use('/modules', modulesRouter);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'production' ? {} : err.message
  });
  // NOTE: Do not call next() after sending response
});

// 404 handler (Express 5.x compatible)
app.use((req, res) => {
  res.status(404).json({
    message: 'Route not found',
    availableEndpoints: [
      '/tools', '/categories', '/users', '/progress', 
      '/analytics', '/quizzes', '/goals', '/exam-schedule'
    ]
  });
});

// Listen on correct host and port
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SarkariSuccess-Hub Backend is running on port: ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

// Export app for testing
module.exports = app;