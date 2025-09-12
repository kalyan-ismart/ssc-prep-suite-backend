// utils/errors.js

function errorResponse(res, status, message, errors = []) {
  return res.status(status).json({ success: false, message, errors });
}

module.exports = { errorResponse };
