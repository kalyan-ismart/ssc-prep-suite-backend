// middleware/auth.js
const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
  // 1. Get token from header
  const authHeader = req.header('Authorization');

  // Check if header exists
  if (!authHeader) {
    return res.status(401).json({ message: 'No token, authorization denied.' });
  }

  // 2. Extract token from "Bearer <token>"
  const token = authHeader.split(' ')[1];

  // Check if token exists after split
  if (!token) {
    return res.status(401).json({ message: 'Token format is invalid, authorization denied.' });
  }

  // 3. Verify token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Add user from payload to the request object
    req.user = decoded.user;
    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid.' });
  }
};
