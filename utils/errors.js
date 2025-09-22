// utils/errors.js
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
            level: process.env.NODE_ENV === 'production' ? 'error' : 'debug'
        })
    ]
});

// ENHANCED: Security event logging with severity levels
const logSecurityEvent = async (req, eventType, severity = 'info', additionalData = {}) => {
    const logData = {
        eventType,
        severity,
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown',
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        url: req.url,
        method: req.method,
        userId: req.user?.userId || req.body?.userId || 'anonymous',
        ...additionalData
    };

    try {
        securityLogger.log(severity, `Security Event: ${eventType}`, logData);
        
        // Send alerts for critical security events (placeholder for now)
        if (severity === 'error' || (severity === 'warning' && isCriticalEvent(eventType))) {
            await sendSecurityAlert(eventType, logData);
        }
    } catch (error) {
        console.error('Failed to log security event:', error);
    }
};

// ENHANCED: Determine if event is critical and needs immediate alerting
const isCriticalEvent = (eventType) => {
    const criticalEvents = [
        'MULTIPLE_FAILED_LOGINS',
        'POTENTIAL_BRUTE_FORCE',
        'SQL_INJECTION_ATTEMPT',
        'XSS_ATTEMPT',
        'UNAUTHORIZED_ACCESS_ATTEMPT',
        'PRIVILEGE_ESCALATION_ATTEMPT',
        'SUSPICIOUS_ACTIVITY'
    ];
    return criticalEvents.includes(eventType);
};

// ENHANCED: Send security alerts (simplified version)
const sendSecurityAlert = async (eventType, logData) => {
    try {
        // Log critical security events to console for now
        console.error(`🚨 SECURITY ALERT: ${eventType}`, {
            severity: logData.severity,
            time: logData.timestamp,
            ip: logData.ip,
            userId: logData.userId,
            url: logData.url
        });

        // TODO: Implement email/webhook alerts when needed
        // For now, we'll just log to console and security log file
        
    } catch (error) {
        console.error('Failed to send security alert:', error);
        securityLogger.error('Failed to send security alert', { error: error.message, eventType });
    }
};

// ENHANCED: Error response function with security considerations
const errorResponse = (res, message, statusCode = 500, details = null, requestId = null) => {
    const isDevelopment = process.env.NODE_ENV !== 'production';
    
    // Sanitize sensitive information from error messages
    const sanitizedMessage = message?.replace(/mongodb|mongoose|database|connection|password|token|secret/gi, 'system');
    
    const response = {
        success: false,
        message: sanitizedMessage || 'An error occurred',
        timestamp: new Date().toISOString(),
        requestId: requestId || res.locals?.requestId,
        ...(isDevelopment && details && { details })
    };

    return res.status(statusCode).json(response);
};

// ENHANCED: Database error handler with specific error type detection
const handleDatabaseError = (error, req, res, next) => {
    let message = 'Database operation failed';
    let statusCode = 500;

    // Handle specific MongoDB/Mongoose errors
    if (error.name === 'ValidationError') {
        message = 'Validation failed';
        statusCode = 400;
        const validationErrors = Object.values(error.errors).map(err => ({
            field: err.path,
            message: err.message
        }));
        return errorResponse(res, message, statusCode, validationErrors, req.id);
    }

    if (error.code === 11000) { // Duplicate key error
        message = 'Resource already exists';
        statusCode = 409;
        const field = Object.keys(error.keyValue)[0];
        return errorResponse(res, `${field} already exists`, statusCode, null, req.id);
    }

    if (error.name === 'CastError') {
        message = 'Invalid resource ID';
        statusCode = 400;
        return errorResponse(res, message, statusCode, null, req.id);
    }

    if (error.name === 'DocumentNotFoundError') {
        message = 'Resource not found';
        statusCode = 404;
        return errorResponse(res, message, statusCode, null, req.id);
    }

    // Log the error for investigation
    securityLogger.error('Database error', {
        error: error.message,
        stack: error.stack,
        requestId: req.id,
        url: req.url,
        method: req.method,
        userId: req.user?.userId
    });

    return errorResponse(res, message, statusCode, null, req.id);
};

// ENHANCED: Async handler wrapper with better error context
const asyncHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch((error) => {
            // Add request context to error
            error.requestId = req.id;
            error.url = req.url;
            error.method = req.method;
            error.userId = req.user?.userId;

            // Log the error
            securityLogger.error('Async handler error', {
                error: error.message,
                stack: error.stack,
                requestId: error.requestId,
                url: error.url,
                method: error.method,
                userId: error.userId
            });

            next(error);
        });
    };
};

// ENHANCED: Input sanitization to prevent NoSQL injection
const sanitizeInput = (input) => {
    if (typeof input === 'string') {
        // Remove potential MongoDB operators
        return input.replace(/^\$/, '').replace(/\./g, '');
    }
    
    if (typeof input === 'object' && input !== null) {
        const sanitized = {};
        for (const [key, value] of Object.entries(input)) {
            // Skip keys that start with $ (MongoDB operators)
            if (!key.startsWith('$')) {
                sanitized[key] = sanitizeInput(value);
            }
        }
        return sanitized;
    }
    
    return input;
};

// ENHANCED: Validation middleware with security logging
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        // Log validation failures for security monitoring
        logSecurityEvent(req, 'VALIDATION_FAILED', 'warning', {
            errors: errors.array(),
            body: sanitizeInput(req.body)
        });

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

    next();
};

// ENHANCED: Rate limiting violation handler
const rateLimitHandler = (req, res) => {
    logSecurityEvent(req, 'RATE_LIMIT_EXCEEDED', 'warning', {
        limit: req.rateLimit?.limit,
        current: req.rateLimit?.current,
        remaining: req.rateLimit?.remaining,
        resetTime: req.rateLimit?.resetTime
    });

    return res.status(429).json({
        success: false,
        message: 'Too many requests, please try again later',
        retryAfter: Math.ceil((req.rateLimit?.resetTime - Date.now()) / 1000),
        requestId: req.id,
        timestamp: new Date().toISOString()
    });
};

// ENHANCED: Detect and log potential security threats
const detectSecurityThreats = (req, res, next) => {
    const userInput = JSON.stringify({ ...req.body, ...req.query, ...req.params });
    
    // Check for potential SQL injection patterns
    const sqlPatterns = /(union|select|insert|update|delete|drop|create|alter|exec|execute)/i;
    if (sqlPatterns.test(userInput)) {
        logSecurityEvent(req, 'POTENTIAL_SQL_INJECTION', 'error', {
            input: userInput,
            patterns: 'SQL injection patterns detected'
        });
    }

    // Check for XSS patterns
    const xssPatterns = /(<script|javascript:|on\w+\s*=)/i;
    if (xssPatterns.test(userInput)) {
        logSecurityEvent(req, 'POTENTIAL_XSS_ATTACK', 'error', {
            input: userInput,
            patterns: 'XSS patterns detected'
        });
    }

    // Check for NoSQL injection patterns
    const nosqlPatterns = /(\$where|\$regex|\$ne|\$gt|\$lt)/i;
    if (nosqlPatterns.test(userInput)) {
        logSecurityEvent(req, 'POTENTIAL_NOSQL_INJECTION', 'warning', {
            input: userInput,
            patterns: 'NoSQL injection patterns detected'
        });
    }

    next();
};

module.exports = {
    securityLogger,
    logSecurityEvent,
    errorResponse,
    handleDatabaseError,
    asyncHandler,
    sanitizeInput,
    validateRequest,
    rateLimitHandler,
    detectSecurityThreats,
    sendSecurityAlert
};