// routes/users.js

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, param, query, validationResult } = require('express-validator');
const validator = require('validator');
const User = require('../models/user.model');
const Progress = require('../models/progress.model');
const { errorResponse, handleDatabaseError, asyncHandler, logSecurityEvent } = require('../utils/errors');
const { auth, adminAuth } = require('../middleware/auth');

const router = express.Router();

// --- Enhanced Validation Rules ---
const validateRegistration = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 32 })
    .matches(/^[a-zA-Z0-9_\-.]+$/)
    .withMessage('Username must be 3-32 characters and can contain letters, numbers, or _-.')
    // Check for profanity or reserved words
    .custom((value) => {
      const reservedWords = ['admin', 'root', 'administrator', 'null', 'undefined'];
      if (reservedWords.includes(value.toLowerCase())) {
        throw new Error('Username contains reserved word');
      }
      return true;
    }),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email.')
    .custom((value) => {
      // Additional email validation
      if (!validator.isEmail(value)) {
        throw new Error('Invalid email format');
      }
      return true;
    }),
  body('password')
    .isString()
    .isLength({ min: 12, max: 128 })
    .withMessage('Password must be 12-128 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/)
    .withMessage('Password must contain at least one uppercase letter, lowercase letter, number, and special character')
    // Check password strength
    .custom((value) => {
      const commonPasswords = ['password123', '123456789', 'qwerty123'];
      if (commonPasswords.some(common => value.toLowerCase().includes(common))) {
        throw new Error('Password is too common');
      }
      return true;
    }),
  body('fullName')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Full name must be less than 100 characters.')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Full name can only contain letters and spaces'),
];

const validateLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email.'),
  body('password')
    .notEmpty()
    .withMessage('Password is required.')
    .isLength({ min: 1, max: 128 })
    .withMessage('Invalid password format'),
];

const validateUserUpdate = [
  param('id')
    .isMongoId()
    .withMessage('Valid user ID is required.'),
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 32 })
    .matches(/^[a-zA-Z0-9_\-.]+$/)
    .withMessage('Username must be 3-32 characters and can contain letters, numbers, or _-.'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email.'),
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
    .customSanitizer((value) => {
      return validator.escape(value);
    }),
];

// --- Token Management Functions ---
const generateTokens = (user) => {
  const payload = { user: { id: user.id, role: user.role } };
  
  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { 
    expiresIn: '15m',
    issuer: 'sarkarisuccess-api',
    audience: 'sarkarisuccess-client'
  });
  
  const refreshToken = jwt.sign(
    { userId: user.id, tokenVersion: user.tokenVersion || 0 }, 
    process.env.JWT_REFRESH_SECRET, 
    { 
      expiresIn: '7d',
      issuer: 'sarkarisuccess-api',
      audience: 'sarkarisuccess-client'
    }
  );
  
  return { accessToken, refreshToken };
};

// --- Authentication Routes ---

// @route POST /users/register
// @desc Register a new user and return JWT
// @access Public
router.post('/register', validateRegistration, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logSecurityEvent('REGISTRATION_VALIDATION_FAILED', { errors: errors.array() }, req);
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  const { username, email, password, fullName } = req.body;

  try {
    // Check for duplicate username or email (case-insensitive)
    const [usernameExists, emailExists] = await Promise.all([
      User.findOne({ username: new RegExp(`^${username}$`, 'i') }),
      User.findOne({ email: new RegExp(`^${email}$`, 'i') })
    ]);

    if (usernameExists) {
      logSecurityEvent('REGISTRATION_DUPLICATE_USERNAME', { username }, req);
      return errorResponse(res, 409, 'Username already exists.');
    }

    if (emailExists) {
      logSecurityEvent('REGISTRATION_DUPLICATE_EMAIL', { email }, req);
      return errorResponse(res, 409, 'Email already registered.');
    }

    // Hash password with higher salt rounds
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const user = new User({ 
      username, 
      email, 
      password: hashedPassword, 
      fullName,
      tokenVersion: 0
    });
    await user.save();

    // Create an associated progress document
    const newProgress = new Progress({ user: user._id });
    await newProgress.save();

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    logSecurityEvent('USER_REGISTERED', { userId: user._id, username, email }, req);

    res.status(201).json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role
      }
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// @route POST /users/login
// @desc Authenticate user and return JWT
// @access Public
router.post('/login', validateLogin, asyncHandler(async (req, res) => {
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

    // Update last login and increment token version for security
    user.lastLogin = new Date();
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    logSecurityEvent('USER_LOGIN_SUCCESS', { userId: user._id, email }, req);

    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// @route POST /users/refresh
// @desc Refresh access token using refresh token
// @access Public
router.post('/refresh', asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return errorResponse(res, 401, 'Refresh token required.');
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.tokenVersion !== decoded.tokenVersion) {
      logSecurityEvent('REFRESH_TOKEN_INVALID', { userId: decoded.userId }, req);
      return errorResponse(res, 401, 'Invalid refresh token.');
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

    res.json({
      success: true,
      accessToken,
      refreshToken: newRefreshToken
    });
  } catch (err) {
    logSecurityEvent('REFRESH_TOKEN_ERROR', { error: err.message }, req);
    return errorResponse(res, 401, 'Invalid refresh token.');
  }
}));

// @route POST /users/logout
// @desc Logout user and invalidate tokens
// @access Private
router.post('/logout', auth, asyncHandler(async (req, res) => {
  try {
    // Increment token version to invalidate all existing tokens
    await User.findByIdAndUpdate(req.user.id, { 
      $inc: { tokenVersion: 1 } 
    });

    logSecurityEvent('USER_LOGOUT', { userId: req.user.id }, req);

    res.json({
      success: true,
      message: 'Logged out successfully.'
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// --- CRUD Routes (Protected) ---

// @route GET /users
// @desc Get all users with pagination and search
// @access Private (Admin only)
router.get('/', [auth, adminAuth, ...validatePagination], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  const search = req.query.search || '';

  try {
    // Build search filter with sanitized input
    const filter = {};
    if (search) {
      const sanitizedSearch = validator.escape(search);
      filter.$or = [
        { username: { $regex: sanitizedSearch, $options: 'i' } },
        { email: { $regex: sanitizedSearch, $options: 'i' } },
        { fullName: { $regex: sanitizedSearch, $options: 'i' } }
      ];
    }

    const [users, total] = await Promise.all([
      User.find(filter)
        .select('-password -tokenVersion')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 })
        .lean(),
      User.countDocuments(filter)
    ]);

    const totalPages = Math.ceil(total / limit);

    res.json({
      success: true,
      data: users,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// @route GET /users/:id
// @desc Get user by ID
// @access Private (Own profile or Admin)
router.get('/:id', [auth, param('id').isMongoId()], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  // Users can only access their own profile unless they're admin
  if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    logSecurityEvent('UNAUTHORIZED_PROFILE_ACCESS', { 
      requesterId: req.user.id, 
      targetId: req.params.id 
    }, req);
    return errorResponse(res, 403, 'Access denied. You can only view your own profile.');
  }

  try {
    const user = await User.findById(req.params.id)
      .select('-password -tokenVersion')
      .populate('progress')
      .lean();

    if (!user) {
      return errorResponse(res, 404, 'User not found.');
    }

    res.json({ success: true, data: user });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// @route POST /users/update/:id
// @desc Update user by ID
// @access Private (Own profile or Admin)
router.post('/update/:id', [auth, ...validateUserUpdate], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  // Users can only update their own profile unless they're admin
  if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    logSecurityEvent('UNAUTHORIZED_PROFILE_UPDATE', { 
      requesterId: req.user.id, 
      targetId: req.params.id 
    }, req);
    return errorResponse(res, 403, 'Access denied. You can only update your own profile.');
  }

  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return errorResponse(res, 404, 'User not found.');
    }

    // Check for duplicate username/email if changing
    const updateData = req.body;
    if (updateData.username && updateData.username !== user.username) {
      const existingUser = await User.findOne({ 
        username: new RegExp(`^${updateData.username}$`, 'i'),
        _id: { $ne: req.params.id }
      });
      if (existingUser) {
        return errorResponse(res, 409, 'Username already exists.');
      }
    }

    if (updateData.email && updateData.email !== user.email) {
      const existingUser = await User.findOne({ 
        email: new RegExp(`^${updateData.email}$`, 'i'),
        _id: { $ne: req.params.id }
      });
      if (existingUser) {
        return errorResponse(res, 409, 'Email already registered.');
      }
    }

    // Only admins can change roles
    if (updateData.role && req.user.role !== 'admin') {
      delete updateData.role;
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true, runValidators: true }
    ).select('-password -tokenVersion').lean();

    logSecurityEvent('USER_PROFILE_UPDATED', { 
      userId: req.params.id, 
      updatedBy: req.user.id 
    }, req);

    res.json({
      success: true,
      message: 'User updated successfully.',
      data: updatedUser
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// @route DELETE /users/:id
// @desc Delete user by ID
// @access Private (Admin only)
router.delete('/:id', [auth, adminAuth, param('id').isMongoId()], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return errorResponse(res, 404, 'User not found.');
    }

    // Don't allow admin to delete themselves
    if (req.user.id === req.params.id) {
      return errorResponse(res, 400, 'You cannot delete your own account.');
    }

    // Delete associated progress data
    await Progress.deleteOne({ user: req.params.id });

    // Delete user
    await User.findByIdAndDelete(req.params.id);

    logSecurityEvent('USER_DELETED', { 
      deletedUserId: req.params.id, 
      deletedBy: req.user.id 
    }, req);

    res.json({
      success: true,
      message: 'User and associated data deleted successfully.'
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// @route GET /users/profile/me
// @desc Get current user profile
// @access Private
router.get('/profile/me', auth, asyncHandler(async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -tokenVersion')
      .populate('progress')
      .lean();

    if (!user) {
      return errorResponse(res, 404, 'User not found.');
    }

    res.json({ success: true, data: user });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

module.exports = router;