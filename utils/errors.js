// utils/errors.js

const winston = require('winston');

// Create logger for security events
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/security.log' }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
  ],
});

/**
 * A utility function to wrap async route handlers and catch errors.
 * This avoids the need for try-catch blocks in every async route.
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next))
    .catch((err) => {
      // Log error details securely
      securityLogger.error('Async Error:', {
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        userId: req.user?.id || 'anonymous'
      });
      next(err);
    });
};

/**
 * A standardized function for sending error responses with security considerations.
 */
const errorResponse = (res, statusCode, message, errors = []) => {
  // Sanitize error messages to prevent information leakage
  const sanitizedMessage = typeof message === 'string' ? message : 'An error occurred';
  
  // Log security-relevant status codes
  if (statusCode === 401 || statusCode === 403 || statusCode === 429) {
    securityLogger.warn('Security Event:', {
      statusCode,
      message: sanitizedMessage,
      timestamp: new Date().toISOString(),
      ip: res.req?.ip
    });
  }

  return res.status(statusCode).json({
    success: false,
    message: sanitizedMessage,
    errors: Array.isArray(errors) ? errors : [],
    timestamp: new Date().toISOString()
  });
};

/**
 * Enhanced handler for Mongoose/database related errors with security considerations.
 */
const handleDatabaseError = (res, err) => {
  // Log full error for debugging (never expose to client)
  securityLogger.error('Database Error:', {
    name: err.name,
    message: err.message,
    stack: err.stack,
    timestamp: new Date().toISOString()
  });

  // Handle specific error types securely
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return errorResponse(res, 400, 'Validation Error', messages);
  }

  if (err.name === 'CastError') {
    return errorResponse(res, 400, 'Invalid ID format');
  }

  if (err.code === 11000) {
    // Don't expose which field caused the duplicate key error
    return errorResponse(res, 409, 'Duplicate entry detected');
  }

  if (err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
    return errorResponse(res, 503, 'Database service temporarily unavailable');
  }

  // Generic server error - don't expose internal details
  return errorResponse(res, 500, 'Internal server error');
};

/**
 * Enhanced validation error handler
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Log validation attempts for security monitoring
    securityLogger.warn('Validation Failed:', {
      url: req.url,
      method: req.method,
      errors: errors.array(),
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });

    return errorResponse(res, 422, 'Validation failed', errors.array());
  }
  return next();
};

/**
 * Security event logger
 */
const logSecurityEvent = (eventType, details, req = null) => {
  securityLogger.warn('Security Event:', {
    eventType,
    details,
    ip: req?.ip,
    userAgent: req?.get('User-Agent'),
    url: req?.url,
    method: req?.method,
    userId: req?.user?.id,
    timestamp: new Date().toISOString()
  });
};

// Export all the utility functions
module.exports = {
  asyncHandler,
  errorResponse,
  handleDatabaseError,
  handleValidationErrors,
  logSecurityEvent,
  securityLogger
};