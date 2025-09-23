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

const isNullOrUndefined = require('../utils/nullUndefinedCheck');

const router = express.Router();

// Enhanced password validation with common passwords list
const COMMON_PASSWORDS = [
  'password', 'password123', '123456', '123456789', 'qwerty', 'qwerty123',
  'abc123', 'password1', 'admin', 'letmein', 'welcome', 'monkey', 'dragon',
  'master', 'shadow', 'superman', 'michael', 'football', 'baseball',
  '1234567890', 'iloveyou', 'trustno1', 'sunshine', 'princess'
];

const validatePassword = body('password')
  .isLength({ min: 8, max: 128 })
  .withMessage('Password must be 8-128 characters')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  .withMessage('Password must contain at least one lowercase, uppercase, number and special character')
  .custom((value) => {
    if (COMMON_PASSWORDS.includes(value.toLowerCase())) {
      throw new Error('Password is too common');
    }
    return true;
  });

const validateUser = [
  body('username')
    .isString()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscore and hyphen')
    .customSanitizer((value) => validator.escape(value)),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required')
    .isLength({ max: 254 })
    .withMessage('Email is too long'),
  validatePassword,
  body('fullName')
    .isString()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be 2-100 characters')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Full name can only contain letters and spaces')
    .customSanitizer((value) => validator.escape(value)),
  body('phoneNumber')
    .optional()
    .isMobilePhone('en-IN')
    .withMessage('Valid Indian phone number required'),
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Valid date of birth required (YYYY-MM-DD)')
    .custom((value) => {
      const birthDate = new Date(value);
      const today = new Date();
      const age = today.getFullYear() - birthDate.getFullYear();
      if (age < 16 || age > 100) {
        throw new Error('Age must be between 16 and 100 years');
      }
      return true;
    }),
];

const validateLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required')
    .customSanitizer((value) => validator.escape(value)),
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password is required')
];

const validateUserQuery = [
  query('search')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('Search query too long')
    .customSanitizer((value) => validator.escape(value)),
  query('role')
    .optional()
    .isIn(['admin', 'user'])
    .withMessage('Invalid role'),
  query('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be boolean'),
  query('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Page must be between 1 and 1000'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 50 })
    .withMessage('Limit must be between 1 and 50')
];

// GET all users (Admin only)
router.get('/', [auth, adminAuth, ...validateUserQuery], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const { search, role, isActive } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);
    const skip = (page - 1) * limit;

    const filter = {};
    
    if (role) filter.role = role;
    if (isActive !== undefined) filter.isActive = isActive === 'true';

    if (search) {
      const sanitizedSearch = validator.escape(search);
      filter.$or = [
        { username: { $regex: sanitizedSearch, $options: 'i' } },
        { email: { $regex: sanitizedSearch, $options: 'i' } },
        { fullName: { $regex: sanitizedSearch, $options: 'i' } },
      ];
    }

    const [data, total] = await Promise.all([
      User.find(filter)
        .select('-password -refreshTokens -__v')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 })
        .lean(),
      User.countDocuments(filter)
    ]);

    const totalPages = Math.ceil(total / limit);

    res.json({
      success: true,
      data,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST register new user
router.post('/register', validateUser, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const { username, email, password, fullName, phoneNumber, dateOfBirth } = req.body;

    // Check for existing user
    const existingUser = await User.findOne({
      $or: [
        { email: email.toLowerCase() },
        { username: username.toLowerCase() }
      ]
    });

    if (existingUser) {
      const field = existingUser.email === email.toLowerCase() ? 'email' : 'username';
      return errorResponse(res, 409, `User with this ${field} already exists.`);
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      fullName,
      phoneNumber: phoneNumber || undefined,
      dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : undefined,
    });

    await user.save();

    // Create initial progress document
    const progress = new Progress({
      user: user._id,
      totalStudyTime: 0,
      averageScore: 0,
      quizzesTaken: 0,
      streak: { currentStreak: 0, longestStreak: 0 }
    });
    await progress.save();

    logSecurityEvent('USER_REGISTERED', {
      userId: user._id,
      username: user.username,
      email: user.email
    }, req);

    // Generate tokens
    const payload = { id: user._id, username: user.username, role: user.role };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

    // Save refresh token
    user.refreshTokens.push({ token: refreshToken, createdAt: new Date() });
    await user.save();

    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      createdAt: user.createdAt
    };

    res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      data: {
        user: userResponse,
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST login user
router.post('/login', validateLogin, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ 
      email: email.toLowerCase(),
      isActive: true 
    }).select('+password');

    if (!user) {
      logSecurityEvent('LOGIN_FAILED', {
        email: email.toLowerCase(),
        reason: 'user_not_found'
      }, req);
      return errorResponse(res, 401, 'Invalid email or password.');
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      // Increment failed login attempts
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      user.lastFailedLogin = new Date();
      
      // Lock account after 5 failed attempts
      if (user.loginAttempts >= 5) {
        user.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      }
      
      await user.save();

      logSecurityEvent('LOGIN_FAILED', {
        userId: user._id,
        email: user.email,
        attempts: user.loginAttempts,
        reason: 'invalid_password'
      }, req);

      return errorResponse(res, 401, 'Invalid email or password.');
    }

    // Check if account is locked
    if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
      logSecurityEvent('LOGIN_BLOCKED', {
        userId: user._id,
        reason: 'account_locked',
        lockedUntil: user.accountLockedUntil
      }, req);
      return errorResponse(res, 423, 'Account temporarily locked due to multiple failed login attempts.');
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lastFailedLogin = undefined;
    user.accountLockedUntil = undefined;
    user.lastLogin = new Date();

    // Clean old refresh tokens (keep only last 5)
    user.refreshTokens = user.refreshTokens
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, 5);

    // Generate tokens
    const payload = { id: user._id, username: user.username, role: user.role };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

    // Save new refresh token
    user.refreshTokens.push({ token: refreshToken, createdAt: new Date() });
    await user.save();

    logSecurityEvent('LOGIN_SUCCESS', {
      userId: user._id,
      username: user.username,
      email: user.email
    }, req);

    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      lastLogin: user.lastLogin
    };

    res.json({
      success: true,
      message: 'Login successful.',
      data: {
        user: userResponse,
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST refresh token
router.post('/refresh', [
  body('refreshToken').isString().withMessage('Refresh token is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const { refreshToken } = req.body;

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Find user with this refresh token
    const user = await User.findOne({
      _id: decoded.id,
      'refreshTokens.token': refreshToken,
      isActive: true
    });

    if (!user) {
      logSecurityEvent('REFRESH_TOKEN_INVALID', {
        token: refreshToken.substring(0, 20) + '...',
        userId: decoded.id
      }, req);
      return errorResponse(res, 401, 'Invalid refresh token.');
    }

    // Generate new tokens
    const payload = { id: user._id, username: user.username, role: user.role };
    const newAccessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

    // Remove old refresh token and add new one
    user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== refreshToken);
    user.refreshTokens.push({ token: newRefreshToken, createdAt: new Date() });
    await user.save();

    logSecurityEvent('TOKEN_REFRESHED', {
      userId: user._id
    }, req);

    res.json({
      success: true,
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return errorResponse(res, 401, 'Invalid refresh token.');
    }
    return handleDatabaseError(res, error);
  }
}));

// POST logout
router.post('/logout', [auth], asyncHandler(async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (user) {
      // Remove all refresh tokens
      user.refreshTokens = [];
      await user.save();

      logSecurityEvent('LOGOUT', {
        userId: user._id
      }, req);
    }

    res.json({
      success: true,
      message: 'Logged out successfully.'
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// GET current user profile
router.get('/profile', [auth], asyncHandler(async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -refreshTokens -__v')
      .lean();

    if (!user) {
      return errorResponse(res, 404, 'User not found.');
    }

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST update user profile
router.post('/profile/update', [
  auth,
  body('fullName')
    .optional()
    .isString()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be 2-100 characters')
    .customSanitizer((value) => validator.escape(value)),
  body('phoneNumber')
    .optional()
    .isMobilePhone('en-IN')
    .withMessage('Valid Indian phone number required'),
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Valid date of birth required (YYYY-MM-DD)')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const updateData = {};
    const { fullName, phoneNumber, dateOfBirth } = req.body;

    if (fullName) updateData.fullName = fullName;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (dateOfBirth) updateData.dateOfBirth = new Date(dateOfBirth);

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updateData },
      { new: true, runValidators: true }
    ).select('-password -refreshTokens -__v').lean();

    logSecurityEvent('PROFILE_UPDATED', {
      userId: req.user.id,
      fields: Object.keys(updateData)
    }, req);

    res.json({
      success: true,
      message: 'Profile updated successfully.',
      data: updatedUser
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

module.exports = router;