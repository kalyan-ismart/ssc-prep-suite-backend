// middleware/auth.js - Authentication Middleware

const jwt = require('jsonwebtoken');

/**
 * Middleware to verify JWT token and authenticate user
 */
const auth = (req, res, next) => {
    try {
        // Get token from header
        const authHeader = req.header('Authorization');
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: 'No token provided. Access denied.',
                code: 'NO_TOKEN'
            });
        }

        // Extract token
        const token = authHeader.substring(7); // Remove 'Bearer ' prefix
        
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check token type
        if (decoded.type !== 'access') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token type.',
                code: 'INVALID_TOKEN_TYPE'
            });
        }

        // Add user info to request
        req.user = decoded.user;
        next();
        
    } catch (error) {
        console.error('Authentication error:', error.message);
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expired. Please login again.',
                code: 'TOKEN_EXPIRED'
            });
        }

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token. Access denied.',
                code: 'INVALID_TOKEN'
            });
        }

        return res.status(401).json({
            success: false,
            message: 'Token verification failed. Access denied.',
            code: 'AUTH_FAILED'
        });
    }
};

/**
 * Middleware to verify admin role
 */
const adminAuth = (req, res, next) => {
    // First run auth middleware
    auth(req, res, (err) => {
        if (err) return next(err);
        
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required.',
                code: 'AUTH_REQUIRED'
            });
        }

        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Admin access required. Access denied.',
                code: 'ADMIN_REQUIRED'
            });
        }

        next();
    });
};

/**
 * Optional authentication middleware - doesn't fail if no token
 */
const optionalAuth = (req, res, next) => {
    try {
        const authHeader = req.header('Authorization');
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            // No token provided, continue without authentication
            req.user = null;
            return next();
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.type === 'access') {
            req.user = decoded.user;
        } else {
            req.user = null;
        }

        next();
    } catch (error) {
        // Token exists but is invalid, continue without authentication
        req.user = null;
        next();
    }
};

module.exports = {
    auth,
    adminAuth,
    optionalAuth
};