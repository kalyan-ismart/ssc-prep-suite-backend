const winston = require('winston');
const { validationResult } = require('express-validator');

// ENHANCED: Create comprehensive security logger with better configuration
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    // ADDED: Custom format for security events
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        message,
        requestId: meta.requestId,
        userId: meta.userId,
        ip: meta.ip,
        userAgent: meta.userAgent,
        eventType: meta.eventType,
        ...meta
      });
    })
  ),
  transports: [
    new winston.transports.File({ 
      filename: 'logs/security.log',
      maxsize: 10485760, // 10MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 10485760,
      maxFiles: 5
    }),
    new winston.transports.Console({ 
      format: winston.format.simple(),
      level: process.env.NODE_ENV === 'production' ? 'error' : 'info'
    }),
  ],
  // ENHANCED: Add exception and rejection handlers
  exceptionHandlers: [
    new winston.transports.File({ filename: 'logs/exceptions.log' })
  ],
  rejectionHandlers: [
    new winston.transports.File({ filename: 'logs/rejections.log' })
  ]
});

/**
 * ENHANCED: Wrap async route handlers to catch errors with better context.
 */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch((err) => {
    // ENHANCED: Add more context to error logging
    const errorContext = {
      error: err.message,
      stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined,
      url: req.url,
      method: req.method,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
      requestId: req.id,
      userId: req.user?.id || 'anonymous',
      body: process.env.NODE_ENV !== 'production' ? 
        JSON.stringify(req.body).substring(0, 500) : undefined,
      query: JSON.stringify(req.query),
      params: JSON.stringify(req.params)
    };

    securityLogger.error('Async Route Error:', errorContext);
    next(err);
  });

/**
 * ENHANCED: Send standardized error response with improved security.
 */
const errorResponse = (res, statusCode, message, errors = []) => {
  // ENHANCED: Sanitize error messages to prevent information disclosure
  let sanitizedMessage = typeof message === 'string' ? message : 'An error occurred';
  
  // Remove sensitive information patterns from error messages
  sanitizedMessage = sanitizedMessage
    .replace(/mongodb|mongoose|database|connection/gi, 'system')
    .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, 'server')
    .replace(/port \d+/gi, 'service')
    .replace(/password|token|secret|key/gi, 'credential');

  // ENHANCED: Log security events with more context
  if ([401, 403, 429].includes(statusCode)) {
    const securityContext = {
      statusCode,
      message: sanitizedMessage,
      originalMessage: message,
      timestamp: new Date().toISOString(),
      ip: res.req?.ip,
      userAgent: res.req?.get('User-Agent'),
      url: res.req?.url,
      method: res.req?.method,
      requestId: res.req?.id,
      userId: res.req?.user?.id
    };

    securityLogger.warn('Security Event:', securityContext);
  }

  return res.status(statusCode).json({
    success: false,
    message: sanitizedMessage,
    errors: Array.isArray(errors) ? errors.map(err => ({
      ...err,
      // ENHANCED: Sanitize individual error messages
      msg: err.msg ? err.msg.replace(/mongodb|mongoose|database/gi, 'system') : err.msg
    })) : [],
    timestamp: new Date().toISOString(),
    requestId: res.req?.id
  });
};

/**
 * ENHANCED: Handle Mongoose/database errors with better categorization.
 */
const handleDatabaseError = (res, err) => {
  const errorContext = {
    name: err.name,
    message: err.message,
    code: err.code,
    stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined,
    timestamp: new Date().toISOString(),
    requestId: res.req?.id,
    userId: res.req?.user?.id
  };

  securityLogger.error('Database Error:', errorContext);

  // ENHANCED: More specific error handling
  switch (err.name) {
    case 'ValidationError':
      const msgs = Object.values(err.errors).map((v) => v.message);
      return errorResponse(res, 400, 'Data validation failed', msgs);

    case 'CastError':
      return errorResponse(res, 400, 'Invalid data format provided');

    case 'MongoServerError':
      if (err.code === 11000) {
        // Handle duplicate key errors more gracefully
        const field = Object.keys(err.keyPattern)[0];
        return errorResponse(res, 409, `This ${field} is already in use`);
      }
      return errorResponse(res, 500, 'Database operation failed');

    case 'MongoNetworkError':
    case 'MongoTimeoutError':
      return errorResponse(res, 503, 'Service temporarily unavailable. Please try again later.');

    case 'MongoParseError':
      return errorResponse(res, 400, 'Invalid request format');

    default:
      return errorResponse(res, 500, 'Internal server error');
  }
};

/**
 * ENHANCED: Middleware to handle validation errors with better logging.
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const validationContext = {
      url: req.url,
      method: req.method,
      errors: errors.array(),
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
      requestId: req.id,
      userId: req.user?.id
    };

    securityLogger.warn('Validation Failed:', validationContext);
    return errorResponse(res, 422, 'Request validation failed', errors.array());
  }

  return next();
};

/**
 * ENHANCED: Security event logger with structured logging.
 */
const logSecurityEvent = (eventType, details, req = {}) => {
  const securityEvent = {
    eventType,
    details: typeof details === 'object' ? details : { message: details },
    ip: req.ip || req.connection?.remoteAddress,
    userAgent: req.get ? req.get('User-Agent') : undefined,
    url: req.url,
    method: req.method,
    userId: req.user?.id,
    requestId: req.id,
    timestamp: new Date().toISOString(),
    severity: getSeverityLevel(eventType)
  };

  const logLevel = securityEvent.severity === 'high' ? 'error' : 
                  securityEvent.severity === 'medium' ? 'warn' : 'info';

  securityLogger[logLevel]('Security Event:', securityEvent);

  // ENHANCED: Send alerts for high-severity events
  if (securityEvent.severity === 'high') {
    sendSecurityAlert(securityEvent);
  }
};

/**
 * ENHANCED: Determine severity level based on event type.
 */
const getSeverityLevel = (eventType) => {
  const highSeverityEvents = [
    'MULTIPLE_LOGIN_FAILURES',
    'SUSPICIOUS_ACTIVITY',
    'ACCOUNT_COMPROMISE_DETECTED',
    'BRUTE_FORCE_ATTEMPT',
    'INJECTION_ATTEMPT'
  ];

  const mediumSeverityEvents = [
    'LOGIN_INVALID_PASSWORD',
    'UNAUTHORIZED_ACCESS_ATTEMPT',
    'REGISTRATION_VALIDATION_FAILED',
    'TOKEN_MANIPULATION'
  ];

  if (highSeverityEvents.some(event => eventType.includes(event))) {
    return 'high';
  } else if (mediumSeverityEvents.some(event => eventType.includes(event))) {
    return 'medium';
  } else {
    return 'low';
  }
};

/**
 * ENHANCED: Send security alerts for critical events.
 */
const sendSecurityAlert = (securityEvent) => {
  // In a real implementation, this would send alerts via:
  // - Email notifications
  // - Slack/Teams webhooks  
  // - SMS alerts
  // - Third-party monitoring services (PagerDuty, etc.)
  
  console.warn(`🚨 SECURITY ALERT: ${securityEvent.eventType}`, {
    details: securityEvent.details,
    ip: securityEvent.ip,
    timestamp: securityEvent.timestamp
  });
};

/**
 * ENHANCED: Rate limiting violation handler.
 */
const handleRateLimitViolation = (req, res, options) => {
  const violationContext = {
    ip: req.ip,
    url: req.url,
    method: req.method,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString(),
    limit: options.max,
    windowMs: options.windowMs,
    requestId: req.id
  };

  logSecurityEvent('RATE_LIMIT_VIOLATION', violationContext, req);

  return errorResponse(res, 429, 'Too many requests. Please try again later.', [{
    msg: `Rate limit exceeded. Maximum ${options.max} requests per ${options.windowMs / 60000} minutes.`,
    retryAfter: Math.ceil(options.windowMs / 1000)
  }]);
};

/**
 * ENHANCED: Input sanitization with logging.
 */
const sanitizeInput = (input, context = {}) => {
  if (typeof input !== 'string') {
    return input;
  }

  const originalInput = input;
  
  // Remove potential NoSQL injection attempts
  const sanitized = input
    .replace(/\$where/gi, '')
    .replace(/\$regex/gi, '')
    .replace(/\$ne/gi, '')
    .replace(/\$in/gi, '')
    .replace(/\$nin/gi, '')
    .replace(/\$or/gi, '')
    .replace(/\$and/gi, '');

  // Log if sanitization occurred
  if (sanitized !== originalInput) {
    securityLogger.warn('Input Sanitized:', {
      originalLength: originalInput.length,
      sanitizedLength: sanitized.length,
      context,
      timestamp: new Date().toISOString()
    });
  }

  return sanitized;
};

module.exports = {
  asyncHandler,
  errorResponse,
  handleDatabaseError,
  handleValidationErrors,
  logSecurityEvent,
  securityLogger,
  handleRateLimitViolation,
  sanitizeInput
};