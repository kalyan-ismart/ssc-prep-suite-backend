// routes/users.js - COMPLETE FIXED VERSION with Enhanced Security

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

// ENHANCED: Password strength validation with comprehensive checking
const validatePassword = body('password')
  .isString()
  .isLength({ min: 12, max: 128 })
  .withMessage('Password must be 12-128 characters long')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/)
  .withMessage('Password must contain uppercase, lowercase, number, and special character')
  .custom(password => {
    const lower = password.toLowerCase();
    if (COMMON_PASSWORDS.some(p => lower.includes(p))) {
      throw new Error('Password contains common patterns and is not secure');
    }
    if (/(.)\1{2,}/.test(password)) {
      throw new Error('Password cannot contain more than 2 repeated characters in sequence');
    }
    const sequences = ['123', 'abc', 'qwe', 'asd', 'zxc'];
    if (sequences.some(seq => lower.includes(seq))) {
      throw new Error('Password cannot contain common keyboard sequences');
    }
    return true;
  });

// ENHANCED: Registration validation rules
const validateRegistration = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 32 })
    .matches(/^[a-zA-Z0-9_\-.]+$/)
    .withMessage('Username must be 3-32 characters and can contain letters, numbers, or _-.')
    .custom(value => {
      const reserved = ['admin', 'root', 'administrator', 'null', 'undefined', 'system', 'api'];
      if (reserved.includes(value.toLowerCase())) {
        throw new Error('Username contains reserved word');
      }
      return true;
    }),

  body('email')
    .isEmail()
    .withMessage('Please provide a valid email.')
    .normalizeEmail()
    .custom(value => {
      if (!validator.isEmail(value)) {
        throw new Error('Invalid email format');
      }
      const disposable = ['10minutemail.com', 'guerrillamail.com', 'mailinator.com'];
      const domain = value.split('@')[1];
      if (disposable.includes(domain)) {
        throw new Error('Disposable email addresses are not allowed');
      }
      return true;
    }),

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

// Login validation rules
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

// User-update validation rules
const validateUserUpdate = [
  param('id').isMongoId().withMessage('Valid user ID is required.'),

  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 32 })
    .matches(/^[a-zA-Z0-9_\-.]+$/)
    .withMessage('Username must be 3-32 characters and can contain letters, numbers, or _-.'),

  body('email')
    .optional()
    .isEmail()
    .withMessage('Please provide a valid email.')
    .normalizeEmail(),

  body('fullName')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Full name must be less than 100 characters.')
    .matches(/^[a-zA-Z\s]*$/)
    .withMessage('Full name can only contain letters and spaces'),

  body('role')
    .optional()
    .isIn(['user', 'admin'])
    .withMessage('Role must be either user or admin.'),
];

// Change password validation
const validateChangePassword = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required.'),
  body('newPassword')
    .isString()
    .isLength({ min: 12, max: 128 })
    .withMessage('New password must be 12-128 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/)
    .withMessage('New password must contain uppercase, lowercase, number, and special character'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match');
      }
      return true;
    }),
];

// Pagination & search validation
const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Page must be between 1 and 1000.'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100.'),

  query('search')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Search query must be less than 100 characters.')
    .customSanitizer(value => validator.escape(value)),
];

// ENHANCED: Secure token generation with rotation support
const generateTokens = user => {
  const accessPayload = {
    user: { id: user.id, role: user.role },
    type: 'access',
    iat: Math.floor(Date.now() / 1000),
  };
  const accessToken = jwt.sign(accessPayload, process.env.JWT_SECRET, {
    expiresIn: '15m',
    issuer: 'sarkarisuccess-api',
    audience: 'sarkarisuccess-client',
  });

  const refreshPayload = {
    userId: user.id,
    tokenVersion: user.tokenVersion || 0,
    type: 'refresh',
    iat: Math.floor(Date.now() / 1000),
  };
  const refreshToken = jwt.sign(refreshPayload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: '7d',
    issuer: 'sarkarisuccess-api',
    audience: 'sarkarisuccess-client',
  });

  return { accessToken, refreshToken };
};

// ENHANCED: Secure user query helper to prevent NoSQL injection
const findUserSecurely = async criteria => {
  const sanitized = {};
  if (criteria.email && validator.isEmail(criteria.email)) {
    sanitized.email = criteria.email;
  }
  if (criteria._id && validator.isMongoId(criteria._id)) {
    sanitized._id = criteria._id;
  }
  if (criteria.username && typeof criteria.username === 'string') {
    sanitized.username = criteria.username;
  }
  return User.findOne(sanitized);
};

// --- Authentication Routes ---

// @route   POST /users/register
// @desc    Register a new user and return JWT
// @access  Public
router.post(
  '/register',
  validateRegistration,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logSecurityEvent(
        'REGISTRATION_VALIDATION_FAILED',
        { errors: errors.array(), ip: req.ip, userAgent: req.get('User-Agent') },
        req
      );
      return errorResponse(res, 422, 'Validation failed.', errors.array());
    }

    const { username, email, password, fullName } = req.body;

    try {
      const [usernameExists, emailExists] = await Promise.all([
        findUserSecurely({ username }),
        findUserSecurely({ email }),
      ]);
      if (usernameExists) {
        logSecurityEvent('REGISTRATION_DUPLICATE_USERNAME', { username }, req);
        return errorResponse(res, 409, 'Username already exists.');
      }
      if (emailExists) {
        logSecurityEvent('REGISTRATION_DUPLICATE_EMAIL', { email }, req);
        return errorResponse(res, 409, 'Email already registered.');
      }

      const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 14;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      const user = new User({
        username,
        email,
        password: hashedPassword,
        fullName,
        tokenVersion: 0,
        createdAt: new Date(),
        lastLogin: null,
      });
      await user.save();

      const newProgress = new Progress({ user: user._id });
      await newProgress.save();

      const { accessToken, refreshToken } = generateTokens(user);
      logSecurityEvent(
        'USER_REGISTERED',
        { userId: user._id, username, email },
        req
      );

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        accessToken,
        refreshToken,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          createdAt: user.createdAt,
        },
      });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// @route   POST /users/login
// @desc    Authenticate user and return JWT
// @access  Public
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

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logSecurityEvent('LOGIN_INVALID_PASSWORD', { userId: user._id, email }, req);
        return errorResponse(res, 401, 'Invalid credentials.');
      }

      user.lastLogin = new Date();
      await user.save();

      const { accessToken, refreshToken } = generateTokens(user);
      logSecurityEvent('USER_LOGIN_SUCCESS', { userId: user._id, email }, req);

      res.json({
        success: true,
        message: 'Login successful',
        accessToken,
        refreshToken,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          lastLogin: user.lastLogin,
        },
      });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// @route   POST /users/refresh
// @desc    Refresh access and rotate refresh token
// @access  Public
router.post(
  '/refresh',
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return errorResponse(res, 401, 'Refresh token required.');
    }

    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      if (decoded.type !== 'refresh') {
        logSecurityEvent('REFRESH_TOKEN_INVALID_TYPE', { userId: decoded.userId }, req);
        return errorResponse(res, 401, 'Invalid token type.');
      }

      const user = await User.findById(decoded.userId);
      if (!user || user.tokenVersion !== decoded.tokenVersion) {
        logSecurityEvent('REFRESH_TOKEN_INVALID', { userId: decoded.userId }, req);
        return errorResponse(res, 401, 'Invalid refresh token.');
      }

      user.tokenVersion = (user.tokenVersion || 0) + 1;
      await user.save();

      const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);
      logSecurityEvent('REFRESH_TOKEN_SUCCESS', { userId: user._id }, req);

      res.json({
        success: true,
        accessToken,
        refreshToken: newRefreshToken,
      });
    } catch (err) {
      logSecurityEvent('REFRESH_TOKEN_ERROR', { error: err.message }, req);
      return errorResponse(res, 401, 'Invalid refresh token.');
    }
  })
);

// @route   POST /users/logout
// @desc    Logout user and invalidate tokens
// @access  Private
router.post(
  '/logout',
  auth,
  asyncHandler(async (req, res) => {
    try {
      await User.findByIdAndUpdate(req.user.id, { $inc: { tokenVersion: 1 } });
      logSecurityEvent('USER_LOGOUT', { userId: req.user.id }, req);
      res.json({ success: true, message: 'Logged out successfully.' });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// --- CRUD Routes (Protected) ---

// @route   GET /users
// @desc    Get all users with pagination and search
// @access  Private (Admin only)
router.get(
  '/',
  [auth, adminAuth, ...validatePagination],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 422, 'Validation failed.', errors.array());
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const search = req.query.search || '';

    try {
      const filter = {};
      if (search) {
        const sanitized = validator.escape(search);
        filter.$or = [
          { username: { $regex: sanitized, $options: 'i' } },
          { email: { $regex: sanitized, $options: 'i' } },
          { fullName: { $regex: sanitized, $options: 'i' } },
        ];
      }

      const [users, total] = await Promise.all([
        User.find(filter)
          .select('-password -tokenVersion')
          .skip(skip)
          .limit(limit)
          .sort({ createdAt: -1 })
          .lean(),
        User.countDocuments(filter),
      ]);
      const totalPages = Math.ceil(total / limit);

      res.json({
        success: true,
        data: users,
        pagination: { page, limit, total, totalPages, hasNext: page < totalPages, hasPrev: page > 1 },
      });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// @route   GET /users/me
// @desc    Get current user profile
// @access  Private
router.get(
  '/me',
  auth,
  asyncHandler(async (req, res) => {
    try {
      const user = await User.findById(req.user.id).select('-password -tokenVersion');
      if (!user) {
        return errorResponse(res, 404, 'User not found.');
      }

      res.json({ success: true, data: user });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// @route   GET /users/:id
// @desc    Get user by ID
// @access  Private (Self or Admin)
router.get(
  '/:id',
  [auth, param('id').isMongoId().withMessage('Invalid user ID.')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 422, 'Validation failed.', errors.array());
    }

    if (req.user.id !== req.params.id && req.user.role !== 'admin') {
      logSecurityEvent('UNAUTHORIZED_PROFILE_ACCESS', { requesterId: req.user.id, targetId: req.params.id }, req);
      return errorResponse(res, 403, 'Access denied. You can only view your own profile.');
    }

    try {
      const user = await findUserSecurely({ _id: req.params.id });
      if (!user) {
        return errorResponse(res, 404, 'User not found.');
      }

      const responseUser = {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
      };

      res.json({ success: true, data: responseUser });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// @route   PUT /users/:id
// @desc    Update user profile
// @access  Private (Self or Admin)
router.put(
  '/:id',
  [auth, ...validateUserUpdate],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 422, 'Validation failed.', errors.array());
    }

    // Users can only update their own profile unless they're admin
    if (req.user.id !== req.params.id && req.user.role !== 'admin') {
      logSecurityEvent('UNAUTHORIZED_UPDATE_ATTEMPT', { requesterId: req.user.id, targetId: req.params.id }, req);
      return errorResponse(res, 403, 'Access denied. You can only update your own profile.');
    }

    try {
      const { username, email, fullName, role } = req.body;
      const updateData = {};

      if (username) updateData.username = username;
      if (email) updateData.email = email;
      if (fullName) updateData.fullName = fullName;
      
      // Only admins can change roles
      if (role && req.user.role === 'admin') {
        updateData.role = role;
      }

      updateData.updatedAt = new Date();

      const user = await User.findByIdAndUpdate(req.params.id, updateData, { new: true }).select('-password -tokenVersion');
      if (!user) {
        return errorResponse(res, 404, 'User not found.');
      }

      logSecurityEvent('USER_UPDATED', { userId: req.params.id, updatedBy: req.user.id, fields: Object.keys(updateData) }, req);
      res.json({ success: true, data: user, message: 'User updated successfully.' });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// @route   POST /users/change-password
// @desc    Change user password
// @access  Private
router.post(
  '/change-password',
  [auth, ...validateChangePassword],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 422, 'Validation failed.', errors.array());
    }

    const { currentPassword, newPassword } = req.body;

    try {
      const user = await User.findById(req.user.id).select('+password');
      if (!user) {
        return errorResponse(res, 404, 'User not found.');
      }

      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        logSecurityEvent('PASSWORD_CHANGE_INVALID_CURRENT', { userId: req.user.id }, req);
        return errorResponse(res, 400, 'Current password is incorrect.');
      }

      const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 14;
      const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

      user.password = hashedNewPassword;
      user.tokenVersion = (user.tokenVersion || 0) + 1; // Invalidate all tokens
      user.updatedAt = new Date();
      await user.save();

      logSecurityEvent('PASSWORD_CHANGED', { userId: req.user.id }, req);
      res.json({ success: true, message: 'Password changed successfully. Please log in again.' });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

// @route   DELETE /users/:id
// @desc    Delete user account
// @access  Private (Admin only or self-deletion)
router.delete(
  '/:id',
  [auth, param('id').isMongoId().withMessage('Invalid user ID.')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 422, 'Validation failed.', errors.array());
    }

    // Only admin can delete other users, users can delete themselves
    if (req.user.id !== req.params.id && req.user.role !== 'admin') {
      logSecurityEvent('UNAUTHORIZED_DELETE_ATTEMPT', { requesterId: req.user.id, targetId: req.params.id }, req);
      return errorResponse(res, 403, 'Access denied. You can only delete your own account.');
    }

    try {
      const user = await User.findById(req.params.id);
      if (!user) {
        return errorResponse(res, 404, 'User not found.');
      }

      // Delete associated progress data
      await Progress.findOneAndDelete({ user: req.params.id });
      
      // Delete the user
      await User.findByIdAndDelete(req.params.id);

      logSecurityEvent('USER_DELETED', { deletedUserId: req.params.id, deletedBy: req.user.id }, req);
      res.json({ success: true, message: 'User account deleted successfully.' });
    } catch (err) {
      return handleDatabaseError(res, err);
    }
  })
);

module.exports = router;