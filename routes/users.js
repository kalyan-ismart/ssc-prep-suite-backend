// routes/users.js 

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, param, query, validationResult } = require('express-validator');
const validator = require('validator');
const User = require('../models/user.model');
const Progress = require('../models/progress.model');
const {
  errorResponse,
  handleDatabaseError,
  asyncHandler,
  logSecurityEvent,
} = require('../utils/errors');
const { auth, adminAuth } = require('../middleware/auth');

const router = express.Router();

// ENHANCED: Common passwords list for better security
const COMMON_PASSWORDS = [
  'password', 'password123', '123456', '123456789', 'qwerty', 'qwerty123',
  'abc123', 'password1', 'admin', 'letmein', 'welcome', 'monkey', 'dragon',
  'master', 'shadow', 'superman', 'michael', 'football', 'baseball',
  '1234567890', 'iloveyou', 'trustno1', 'sunshine', 'princess'
];

// ENHANCED: Password strength validation
const validatePassword = body('password')
  .isString()
  .isLength({ min: 12, max: 128 })
  .withMessage('Password must be 12-128 characters')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/)
  .withMessage('Password must contain uppercase, lowercase, number, and special character')
  .custom(password => {
    const lower = password.toLowerCase();
    if (COMMON_PASSWORDS.some(p => lower.includes(p))) {
      throw new Error('Password contains common patterns and is not secure');
    }
    return true;
  });

// ENHANCED: Registration validation rules
const validateRegistration = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 32 })
    .matches(/^[a-zA-Z0-9_.-]+$/)
    .withMessage('Username must be 3-32 characters and can contain letters, numbers, underscore, dot, hyphen')
    .custom(value => {
      const reserved = ['admin', 'root', 'system'];
      if (reserved.includes(value.toLowerCase())) {
        throw new Error('Username contains reserved word');
      }
      return true;
    }),

  body('email')
    .isEmail()
    .withMessage('Please provide a valid email.')
    .normalizeEmail(),

  validatePassword,

  body('fullName')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Full name must be less than 100 characters.')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Full name can only contain letters and spaces'),
];

// ENHANCED: Login validation rules
const validateLogin = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email.')
    .normalizeEmail(),

  body('password')
    .notEmpty()
    .withMessage('Password is required.')
    .isLength({ min: 1, max: 128 })
    .withMessage('Invalid password format'),
];

// Route: POST /users/register
router.post(
  '/register',
  validateRegistration,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logSecurityEvent('REGISTRATION_VALIDATION_FAILED', { errors: errors.array(), ip: req.ip }, req);
      return errorResponse(res, 422, 'Validation failed.', errors.array());
    }

    const { username, email, password, fullName } = req.body;
    try {
      const [userByName, userByEmail] = await Promise.all([
        User.findOne({ username }),
        User.findOne({ email }),
      ]);

      if (userByName) {
        logSecurityEvent('REGISTRATION_DUPLICATE_USERNAME', { username }, req);
        return errorResponse(res, 409, 'Username already exists.');
      }
      if (userByEmail) {
        logSecurityEvent('REGISTRATION_DUPLICATE_EMAIL', { email }, req);
        return errorResponse(res, 409, 'Email already registered.');
      }

      const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 15;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      const user = new User({ username, email, password: hashedPassword, fullName });
      await user.save();

      const progress = new Progress({ user: user._id });
      await progress.save();

      const accessToken = jwt.sign(
        { user: { id: user._id, role: user.role }, type: 'access' },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      const refreshToken = jwt.sign(
        { userId: user._id, tokenVersion: user.tokenVersion, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
      );

      logSecurityEvent('USER_REGISTERED', { userId: user._id }, req);

      res.status(201).json({
        success: true,
        message: 'User registered successfully.',
        accessToken,
        refreshToken,
        user: { id: user._id, username: user.username, email: user.email, role: user.role }
      });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// Route: POST /users/login
router.post(
  '/login',
  validateLogin,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logSecurityEvent('LOGIN_VALIDATION_FAILED', { errors: errors.array() }, req);
      return errorResponse(res, 422, 'Validation failed.', errors.array());
    }

    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email }).select('+password');
      if (!user) {
        logSecurityEvent('LOGIN_USER_NOT_FOUND', { email }, req);
        return errorResponse(res, 401, 'Invalid credentials.');
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        logSecurityEvent('LOGIN_INVALID_PASSWORD', { userId: user._id }, req);
        return errorResponse(res, 401, 'Invalid credentials.');
      }

      user.lastLogin = new Date();
      await user.save();

      const accessToken = jwt.sign(
        { user: { id: user._id, role: user.role }, type: 'access' },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      const refreshToken = jwt.sign(
        { userId: user._id, tokenVersion: user.tokenVersion, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
      );

      logSecurityEvent('USER_LOGIN_SUCCESS', { userId: user._id }, req);

      res.json({
        success: true,
        message: 'Login successful.',
        accessToken,
        refreshToken,
        user: { id: user._id, username: user.username, email: user.email, role: user.role }
      });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

module.exports = router;
