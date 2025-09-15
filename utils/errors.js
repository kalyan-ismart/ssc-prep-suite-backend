const winston = require('winston');
const { validationResult } = require('express-validator');

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
    new winston.transports.Console({ format: winston.format.simple() }),
  ],
});

/**
 * Wrap async route handlers to catch errors.
 */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch((err) => {
    securityLogger.error('Async Error:', {
      error: err.message,
      stack: err.stack,
      url: req.url,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
      userId: req.user?.id || 'anonymous',
    });
    next(err);
  });

/**
 * Send standardized error response.
 */
const errorResponse = (res, statusCode, message, errors = []) => {
  const sanitizedMessage = typeof message === 'string' ? message : 'An error occurred';

  if ([401, 403, 429].includes(statusCode)) {
    securityLogger.warn('Security Event:', {
      statusCode,
      message: sanitizedMessage,
      timestamp: new Date().toISOString(),
      ip: res.req?.ip,
    });
  }

  return res.status(statusCode).json({
    success: false,
    message: sanitizedMessage,
    errors: Array.isArray(errors) ? errors : [],
    timestamp: new Date().toISOString(),
  });
};

/**
 * Handle Mongoose/database errors.
 */
const handleDatabaseError = (res, err) => {
  securityLogger.error('Database Error:', {
    name: err.name,
    message: err.message,
    stack: err.stack,
    timestamp: new Date().toISOString(),
  });

  if (err.name === 'ValidationError') {
    const msgs = Object.values(err.errors).map((v) => v.message);
    return errorResponse(res, 400, 'Validation Error', msgs);
  }
  if (err.name === 'CastError') {
    return errorResponse(res, 400, 'Invalid ID format');
  }
  if (err.code === 11000) {
    return errorResponse(res, 409, 'Duplicate entry detected');
  }
  if (['MongoNetworkError', 'MongoTimeoutError'].includes(err.name)) {
    return errorResponse(res, 503, 'Database service temporarily unavailable');
  }
  return errorResponse(res, 500, 'Internal server error');
};

/**
 * Middleware to handle validation errors.
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    securityLogger.warn('Validation Failed:', {
      url: req.url,
      method: req.method,
      errors: errors.array(),
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
    });
    return errorResponse(res, 422, 'Validation failed', errors.array());
  }
  return next();
};

/**
 * Security event logger.
 */
const logSecurityEvent = (eventType, details, req = {}) => {
  securityLogger.warn('Security Event:', {
    eventType,
    details,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    url: req.url,
    method: req.method,
    userId: req.user?.id,
    timestamp: new Date().toISOString(),
  });
};

module.exports = {
  asyncHandler,
  errorResponse,
  handleDatabaseError,
  handleValidationErrors,
  logSecurityEvent,
  securityLogger,
};
