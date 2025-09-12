// validators/progressValidators.js

const { body, param, validationResult } = require('express-validator');
const mongoose = require('mongoose');

/**
 * Middleware to check validation results
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array(),
    });
  }
  next();
};

/**
 * Validator for userId (used in GET /user/:userId and GET /analytics/:userId)
 */
const validateUserId = [
  param('userId')
    .isMongoId()
    .withMessage('Valid user ID (MongoDB ObjectId) is required'),
];

/**
 * Validators for updating progress (POST /update/:userId)
 */
const validateProgressUpdate = [
  param('userId')
    .isMongoId()
    .withMessage('Valid user ID (MongoDB ObjectId) is required'),
  body('timeSpent')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Time spent must be a non-negative integer (in minutes)'),
  body('score')
    .optional()
    .isFloat({ min: 0, max: 100 })
    .withMessage('Score must be a number between 0 and 100'),
  body('streakData')
    .optional()
    .isObject()
    .withMessage('Streak data must be an object'),
];

module.exports = {
  validate,
  validateUserId,
  validateProgressUpdate,
};