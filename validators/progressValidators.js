const { body, param, validationResult } = require('express-validator');

/**
 * Middleware to run validationResult and return errors.
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array(),
    });
  }
  return next();
};

/**
 * Validator for userId parameters.
 */
const validateUserId = [
  param('userId').isMongoId().withMessage('Valid user ID (MongoDB ObjectId) is required'),
  validate,
];

/**
 * Validators for updating progress.
 */
const validateProgressUpdate = [
  param('userId').isMongoId().withMessage('Valid user ID (MongoDB ObjectId) is required'),
  body('timeSpent').optional().isInt({ min: 0, max: 1440 })
    .withMessage('Time spent must be 0-1440 minutes'),
  body('score').optional().isFloat({ min: 0, max: 100 })
    .withMessage('Score must be between 0 and 100'),
  body('streakData').optional().isObject().withMessage('Streak data must be an object'),
  body('streakData.currentStreak').optional().isInt({ min: 0 })
    .withMessage('Current streak must be a non-negative integer'),
  body('streakData.longestStreak').optional().isInt({ min: 0 })
    .withMessage('Longest streak must be a non-negative integer'),
  body('streakData.lastStudyDate').optional().isISO8601()
    .withMessage('Last study date must be a valid ISO date'),
  validate,
];

/**
 * Validators for analytics query parameters.
 */
const validateAnalyticsQuery = [
  param('userId').isMongoId().withMessage('Valid user ID (MongoDB ObjectId) is required'),
  body('timeRange').optional().isIn(['7days', '30days', '90days', '1year'])
    .withMessage('Time range must be: 7days, 30days, 90days, or 1year'),
  body('metrics').optional().isArray().withMessage('Metrics must be an array'),
  validate,
];

module.exports = {
  validate,
  validateUserId,
  validateProgressUpdate,
  validateAnalyticsQuery,
};
