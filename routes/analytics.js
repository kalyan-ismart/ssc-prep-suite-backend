const router = require('express').Router();
const { param, body, validationResult } = require('express-validator');
const mongoose = require('mongoose');

/** Utility: Standard error response */
function errorResponse(res, status, message, errors = []) {
  return res.status(status).json({ success: false, message, errors });
}

// Sample data for demonstration
const sampleAnalyticsData = { /* ... unchanged ... */ };

// GET dashboard analytics
router.get('/dashboard/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const userId = req.params.userId;
    const dashboardData = { /* ... unchanged ... */ };
    res.json(dashboardData);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch dashboard analytics', [error.message]);
  }
});

// GET performance analytics
router.get('/performance/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const userId = req.params.userId;
    const performanceData = { /* ... unchanged ... */ };
    res.json(performanceData);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch performance analytics', [error.message]);
  }
});

// GET study patterns
router.get('/study-patterns/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const userId = req.params.userId;
    const studyPatternsData = { /* ... unchanged ... */ };
    res.json(studyPatternsData);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch study patterns', [error.message]);
  }
});

// GET competitive analysis
router.get('/competitive/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const userId = req.params.userId;
    const competitiveData = { /* ... unchanged ... */ };
    res.json(competitiveData);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch competitive analysis', [error.message]);
  }
});

// GET tool usage analytics
router.get('/tools/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const userId = req.params.userId;
    const toolsData = { /* ... unchanged ... */ };
    res.json(toolsData);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch tool analytics', [error.message]);
  }
});

// GET goal tracking and achievement analytics
router.get('/goals/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const userId = req.params.userId;
    const goalsData = { /* ... unchanged ... */ };
    res.json(goalsData);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch goals analytics', [error.message]);
  }
});

// GET exam-specific preparation analytics (Express 5 compatible)
router.get('/exam-prep/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const userId = req.params.userId;
    const examType = 'all';
    const examPrepData = { /* ... unchanged ... */ };

    res.json(examPrepData);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch exam prep analytics', [error.message]);
  }
});

router.get('/exam-prep/:userId/:examType', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.'),
  param('examType').isString()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const userId = req.params.userId;
    const examType = req.params.examType || 'all';
    const examPrepData = { /* ... unchanged ... */ };

    if (examType !== 'all' && examPrepData.preparation && examPrepData.preparation[examType.toUpperCase()]) {
      examPrepData.specificExam = examPrepData.preparation[examType.toUpperCase()];
    }

    res.json(examPrepData);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch exam prep analytics', [error.message]);
  }
});

// GET overall platform statistics
router.get('/platform-stats', (req, res) => {
  try {
    const platformStats = { /* ... unchanged ... */ };
    res.json(platformStats);
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch platform statistics', [error.message]);
  }
});

// POST endpoint to log analytics events
router.post('/track', [
  body('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.'),
  body('event').isString().withMessage('Event name required.'),
  body('data').exists()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const { userId, event, data } = req.body;
    const logEntry = { userId, event, data, timestamp: new Date().toISOString(), sessionId: req.headers['x-session-id'] || 'unknown' };

    // In production, log to DB/analytics service
    console.log('Analytics Event Logged:', logEntry);

    res.json({
      success: true,
      message: 'Analytics event tracked successfully',
      eventId: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: logEntry.timestamp
    });
  } catch (error) {
    errorResponse(res, 500, 'Failed to track analytics event', [error.message]);
  }
});

module.exports = router;