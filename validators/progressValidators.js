const { body, param, validationResult } = require('express-validator');
const validator = require('validator');

/**
 * ENHANCED: Middleware to run validationResult and return sanitized errors.
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // ENHANCED: Sanitize error messages to prevent information disclosure
    const sanitizedErrors = errors.array().map(error => ({
      ...error,
      msg: error.msg.replace(/mongodb|mongoose|database|connection/gi, 'system')
    }));

    return res.status(422).json({
      success: false,
      message: 'Validation failed',
      errors: sanitizedErrors,
      timestamp: new Date().toISOString(),
      requestId: req.id
    });
  }
  return next();
};

/**
 * ENHANCED: Validator for userId parameters with better security.
 */
const validateUserId = [
  param('userId')
    .isMongoId()
    .withMessage('Valid user ID is required')
    .customSanitizer((value) => {
      // ENHANCED: Ensure the ID is properly sanitized
      return validator.isMongoId(value) ? value : null;
    }),
  validate,
];

/**
 * ENHANCED: Validators for updating progress with comprehensive validation.
 */
const validateProgressUpdate = [
  param('userId')
    .isMongoId()
    .withMessage('Valid user ID is required')
    .customSanitizer((value) => {
      return validator.isMongoId(value) ? value : null;
    }),
    
  body('timeSpent')
    .optional()
    .isInt({ min: 0, max: 1440 })
    .withMessage('Time spent must be between 0 and 1440 minutes')
    .customSanitizer((value) => {
      // ENHANCED: Ensure numeric values are properly converted
      const num = parseInt(value);
      return (num >= 0 && num <= 1440) ? num : 0;
    }),
    
  body('score')
    .optional()
    .isFloat({ min: 0, max: 100 })
    .withMessage('Score must be between 0 and 100')
    .customSanitizer((value) => {
      const num = parseFloat(value);
      return (num >= 0 && num <= 100) ? num : 0;
    }),
    
  body('streakData')
    .optional()
    .isObject()
    .withMessage('Streak data must be an object')
    .custom((value) => {
      // ENHANCED: Validate streak data structure
      if (value && typeof value === 'object') {
        const allowedKeys = ['currentStreak', 'longestStreak', 'lastStudyDate'];
        const keys = Object.keys(value);
        const invalidKeys = keys.filter(key => !allowedKeys.includes(key));
        
        if (invalidKeys.length > 0) {
          throw new Error(`Invalid streak data fields: ${invalidKeys.join(', ')}`);
        }
        
        // Validate individual streak fields
        if (value.currentStreak !== undefined && (!Number.isInteger(value.currentStreak) || value.currentStreak < 0)) {
          throw new Error('Current streak must be a non-negative integer');
        }
        
        if (value.longestStreak !== undefined && (!Number.isInteger(value.longestStreak) || value.longestStreak < 0)) {
          throw new Error('Longest streak must be a non-negative integer');
        }
        
        if (value.lastStudyDate !== undefined && !validator.isISO8601(value.lastStudyDate)) {
          throw new Error('Last study date must be a valid ISO date');
        }
      }
      return true;
    }),
    
  body('streakData.currentStreak')
    .optional()
    .isInt({ min: 0, max: 365 })
    .withMessage('Current streak must be between 0 and 365 days'),
    
  body('streakData.longestStreak')
    .optional()
    .isInt({ min: 0, max: 365 })
    .withMessage('Longest streak must be between 0 and 365 days'),
    
  body('streakData.lastStudyDate')
    .optional()
    .isISO8601()
    .withMessage('Last study date must be a valid ISO date')
    .custom((value) => {
      // ENHANCED: Validate that the date is not in the future
      const date = new Date(value);
      const now = new Date();
      if (date > now) {
        throw new Error('Last study date cannot be in the future');
      }
      return true;
    }),
    
  validate,
];

/**
 * ENHANCED: Validators for analytics query parameters with better security.
 */
const validateAnalyticsQuery = [
  param('userId')
    .isMongoId()
    .withMessage('Valid user ID is required')
    .customSanitizer((value) => {
      return validator.isMongoId(value) ? value : null;
    }),
    
  body('timeRange')
    .optional()
    .isIn(['7days', '30days', '90days', '1year'])
    .withMessage('Time range must be: 7days, 30days, 90days, or 1year')
    .customSanitizer((value) => {
      // ENHANCED: Ensure only valid time ranges are accepted
      const validRanges = ['7days', '30days', '90days', '1year'];
      return validRanges.includes(value) ? value : '30days';
    }),
    
  body('metrics')
    .optional()
    .isArray({ min: 0, max: 10 })
    .withMessage('Metrics must be an array with maximum 10 items')
    .custom((metrics) => {
      // ENHANCED: Validate individual metrics
      if (Array.isArray(metrics)) {
        const validMetrics = [
          'studyTime', 'quizzes', 'scores', 'streak', 'progress',
          'accuracy', 'subjects', 'performance', 'goals', 'achievements'
        ];
        
        const invalidMetrics = metrics.filter(metric => 
          !validMetrics.includes(metric) || typeof metric !== 'string'
        );
        
        if (invalidMetrics.length > 0) {
          throw new Error(`Invalid metrics: ${invalidMetrics.join(', ')}`);
        }
      }
      return true;
    }),
    
  body('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO date')
    .custom((value) => {
      // ENHANCED: Validate date range constraints
      const date = new Date(value);
      const now = new Date();
      const maxPastDate = new Date();
      maxPastDate.setFullYear(now.getFullYear() - 2); // Max 2 years back
      
      if (date > now) {
        throw new Error('Start date cannot be in the future');
      }
      
      if (date < maxPastDate) {
        throw new Error('Start date cannot be more than 2 years ago');
      }
      
      return true;
    }),
    
  body('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO date')
    .custom((value, { req }) => {
      const endDate = new Date(value);
      const now = new Date();
      
      if (endDate > now) {
        throw new Error('End date cannot be in the future');
      }
      
      // ENHANCED: Validate end date is after start date
      if (req.body.startDate) {
        const startDate = new Date(req.body.startDate);
        if (endDate <= startDate) {
          throw new Error('End date must be after start date');
        }
        
        // ENHANCED: Limit date range to prevent performance issues
        const daysDiff = (endDate - startDate) / (1000 * 60 * 60 * 24);
        if (daysDiff > 730) { // Max 2 years range
          throw new Error('Date range cannot exceed 2 years');
        }
      }
      
      return true;
    }),
    
  validate,
];

/**
 * ENHANCED: Additional validator for quiz submission with comprehensive validation.
 */
const validateQuizSubmission = [
  param('quizId')
    .isMongoId()
    .withMessage('Valid quiz ID is required')
    .customSanitizer((value) => {
      return validator.isMongoId(value) ? value : null;
    }),
    
  body('answers')
    .isArray({ min: 1, max: 100 })
    .withMessage('Answers must be an array with 1-100 items')
    .custom((answers) => {
      // ENHANCED: Validate answer structure
      answers.forEach((answer, index) => {
        if (typeof answer !== 'object' || !answer.questionId || answer.selectedOption === undefined) {
          throw new Error(`Invalid answer structure at index ${index}`);
        }
        
        if (!validator.isMongoId(answer.questionId)) {
          throw new Error(`Invalid question ID at index ${index}`);
        }
        
        // Sanitize answer content
        if (typeof answer.selectedOption === 'string') {
          answer.selectedOption = validator.escape(answer.selectedOption);
        }
      });
      return true;
    }),
    
  body('timeSpent')
    .optional()
    .isInt({ min: 1, max: 7200 }) // Max 2 hours
    .withMessage('Time spent must be between 1 and 7200 seconds'),
    
  body('startedAt')
    .optional()
    .isISO8601()
    .withMessage('Started at must be a valid ISO date')
    .custom((value) => {
      const startedAt = new Date(value);
      const now = new Date();
      const maxPastTime = new Date(now.getTime() - (8 * 60 * 60 * 1000)); // Max 8 hours ago
      
      if (startedAt > now) {
        throw new Error('Started at cannot be in the future');
      }
      
      if (startedAt < maxPastTime) {
        throw new Error('Quiz session too old (max 8 hours)');
      }
      
      return true;
    }),
    
  validate,
];

/**
 * ENHANCED: Input sanitization helper functions.
 */
const sanitizeSearchQuery = (req, res, next) => {
  if (req.query.search) {
    // ENHANCED: Comprehensive search query sanitization
    req.query.search = validator.escape(req.query.search)
      .replace(/[<>\"'%;()&+]/g, '') // Remove potentially dangerous characters
      .trim()
      .substring(0, 100); // Limit length
  }
  next();
};

const sanitizeUserInput = (req, res, next) => {
  // ENHANCED: Sanitize common user input fields
  const fieldsToSanitize = ['username', 'fullName', 'title', 'description', 'content'];
  
  fieldsToSanitize.forEach(field => {
    if (req.body[field] && typeof req.body[field] === 'string') {
      req.body[field] = validator.escape(req.body[field]).trim();
    }
  });
  
  next();
};

/**
 * ENHANCED: Rate limiting validation for different endpoint types.
 */
const validateRateLimit = (limitType) => {
  return (req, res, next) => {
    // Add rate limit context to request
    req.rateLimitContext = {
      type: limitType,
      ip: req.ip,
      userId: req.user?.id,
      timestamp: new Date().toISOString()
    };
    next();
  };
};

module.exports = {
  validate,
  validateUserId,
  validateProgressUpdate,
  validateAnalyticsQuery,
  validateQuizSubmission,
  sanitizeSearchQuery,
  sanitizeUserInput,
  validateRateLimit
};