// utils/errors.js

/**
 * A utility function to wrap async route handlers and catch errors.
 * This avoids the need for try-catch blocks in every async route.
 */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/**
 * A standardized function for sending error responses.
 */
const errorResponse = (res, statusCode, message, errors = []) => {
  return res.status(statusCode).json({
    success: false,
    message,
    errors,
  });
};

/**
 * A specific handler for Mongoose/database related errors.
 */
const handleDatabaseError = (res, err) => {
  console.error(err); // Log the full error for debugging

  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return errorResponse(res, 400, 'Validation Error', messages);
  }

  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const value = err.keyValue[field];
    return errorResponse(res, 409, `Duplicate key error: ${field} '${value}' already exists.`);
  }

  return errorResponse(res, 500, 'Server Error');
};

// Export all the utility functions
module.exports = {
  asyncHandler,
  errorResponse,
  handleDatabaseError,
};