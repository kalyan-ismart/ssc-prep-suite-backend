// middleware/auth.js

const jwt = require('jsonwebtoken');
const { errorResponse } = require('../utils/errors');

/**
 * Authentication middleware to verify JWT tokens
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const auth = (req, res, next) => {
  try {
    // Get token from header
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.header('x-auth-token');

    // Check if no token
    if (!token) {
      return errorResponse(res, 401, 'No token provided. Access denied.');
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return errorResponse(res, 401, 'Token has expired. Please login again.');
    } else if (error.name === 'JsonWebTokenError') {
      return errorResponse(res, 401, 'Invalid token. Access denied.');
    } else {
      return errorResponse(res, 500, 'Token verification failed.');
    }
  }
};

/**
 * Admin authorization middleware
 * Must be used after auth middleware
 */
const adminAuth = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return errorResponse(res, 403, 'Access denied. Admin privileges required.');
  }
  next();
};

/**
 * Optional authentication middleware
 * Adds user info if token is present but doesn't require it
 */
const optionalAuth = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.header('x-auth-token');

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded.user;
    }
    next();
  } catch (error) {
    // Continue without authentication if token is invalid
    next();
  }
};

module.exports = { auth, adminAuth, optionalAuth };