// routes/index.js - FIXED: Proper AI route mounting

const express = require('express');
const router = express.Router();

// Import all route modules
const toolRoutes = require('./tools');
const categoryRoutes = require('./categories');
const userRoutes = require('./users');
const progressRoutes = require('./progress');
const analyticsRoutes = require('./analytics');
const quizRoutes = require('./quizzes');
const goalRoutes = require('./goals');
const examScheduleRoutes = require('./examSchedule');
const moduleRoutes = require('./modules');
const aiRoutes = require('./ai');

// Register each route module with its base path
// These will be prefixed with /api in server.js
router.use('/tools', toolRoutes);
router.use('/categories', categoryRoutes);
router.use('/users', userRoutes);
router.use('/progress', progressRoutes);
router.use('/analytics', analyticsRoutes);
router.use('/quizzes', quizRoutes);
router.use('/goals', goalRoutes);
router.use('/exam-schedule', examScheduleRoutes);
router.use('/modules', moduleRoutes);

// ✅ FIXED: AI routes now properly mounted
// This will resolve to /api/ai when mounted in server.js
router.use('/ai', aiRoutes);

// Add route debugging middleware for development
if (process.env.NODE_ENV !== 'production') {
  router.use((req, res, next) => {
    console.log(`🔗 Route accessed: ${req.method} ${req.originalUrl}`);
    next();
  });
}

// Health check for the API routes
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'API routes are healthy',
    timestamp: new Date().toISOString(),
    availableRoutes: [
      'GET /api/health',
      'GET /api/tools',
      'GET /api/categories',
      'POST /api/users/register',
      'POST /api/users/login',
      'GET /api/ai/health',
      'POST /api/ai/chat',
      'POST /api/ai/summarize',
      'POST /api/ai/study-help'
    ]
  });
});

module.exports = router;