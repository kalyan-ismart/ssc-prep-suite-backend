// routes/index.js

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

// Register each route module with its base path
router.use('/tools', toolRoutes);
router.use('/categories', categoryRoutes);
router.use('/users', userRoutes);
router.use('/progress', progressRoutes);
router.use('/analytics', analyticsRoutes);
router.use('/quizzes', quizRoutes);
router.use('/goals', goalRoutes);
router.use('/exam-schedule', examScheduleRoutes);
router.use('/modules', moduleRoutes);

module.exports = router;