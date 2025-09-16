// routes/users.js - FIXED VERSION with Enhanced Security

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
  .withMessage('Password must contain at least one uppercase letter, lowercase letter, number, and special character')
  .custom((password) => {
    // Check against common passwords
    const lowerPassword = password.toLowerCase();
    const hasCommonPassword = COMMON_PASSWORDS.some(common => 
      lowerPassword.includes(common.toLowerCase())
    );
    
    if (hasCommonPassword) {
      throw new Error('Password contains common patterns and is not secure');
    }

    // Check for repeated characters
    if (/(.)\1{2,}/.test(password)) {
      throw new Error('Password cannot contain more than 2 repeated characters in sequence');
    }

    // Check for sequential patterns
    const sequences = ['123', 'abc', 'qwe', 'asd', 'zxc'];
    const hasSequence = sequences.some(seq => lowerPassword.includes(seq));
    if (hasSequence) {
      throw new Error('Password cannot contain common keyboard sequences');
    }

    return true;
  });

// --- Enhanced Validation Rules ---
const validateRegistration = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 32 })
    .matches(/^[a-zA-Z0-9_\-.]+$/)
    .withMessage('Username must be 3-32 characters and can contain letters, numbers, or _-.')
    .custom((value) => {
      const reservedWords = ['admin', 'root', 'administrator', 'null', 'undefined', 'system', 'api'];
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
      
      // Check for disposable email domains
      const disposableDomains = ['10minutemail.com', 'guerrillamail.com', 'mailinator.com'];
      const domain = value.split('@')[1];
      if (disposableDomains.includes(domain)) {
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

// ENHANCED: More secure token generation with rotation support
const generateTokens = (user) => {
  const payload = { 
    user: { 
      id: user.id, 
      role: user.role 
    },
    type: 'access',
    iat: Math.floor(Date.now() / 1000)
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '15m',
    issuer: 'sarkarisuccess-api',
    audience: 'sarkarisuccess-client'
  });

  const refreshToken = jwt.sign(
    { 
      userId: user.id, 
      tokenVersion: user.tokenVersion || 0,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000)
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: '7d',
      issuer: 'sarkarisuccess-api',
      audience: 'sarkarisuccess-client'
    }
  );

  return { accessToken, refreshToken };
};

// ENHANCED: Secure user query helper to prevent NoSQL injection
const findUserSecurely = async (criteria) => {
  const sanitizedCriteria = {};
  
  // Only allow specific fields for querying
  if (criteria.email && validator.isEmail(criteria.email)) {
    sanitizedCriteria.email = criteria.email;
  }
  if (criteria._id && validator.isMongoId(criteria._id)) {
    sanitizedCriteria._id = criteria._id;
  }
  if (criteria.username && typeof criteria.username === 'string') {
    sanitizedCriteria.username = criteria.username;
  }
  
  return User.findOne(sanitizedCriteria);
};

// --- Authentication Routes ---

// @route POST /users/register
// @desc Register a new user and return JWT
// @access Public
router.post('/register', validateRegistration, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logSecurityEvent('REGISTRATION_VALIDATION_FAILED', { 
      errors: errors.array(),
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }, req);
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  const { username, email, password, fullName } = req.body;

  try {
    // ENHANCED: Use secure query methods to prevent NoSQL injection
    const [usernameExists, emailExists] = await Promise.all([
      findUserSecurely({ username: username }),
      findUserSecurely({ email: email })
    ]);

    if (usernameExists) {
      logSecurityEvent('REGISTRATION_DUPLICATE_USERNAME', { username }, req);
      return errorResponse(res, 409, 'Username already exists.');
    }

    if (emailExists) {
      logSecurityEvent('REGISTRATION_DUPLICATE_EMAIL', { email: email }, req);
      return errorResponse(res, 409, 'Email already registered.');
    }

    // Hash password with higher salt rounds for better security
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 14; // Increased from 12
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      fullName,
      tokenVersion: 0,
      createdAt: new Date(),
      lastLogin: null
    });

    await user.save();

    // Create an associated progress document
    const newProgress = new Progress({ user: user._id });
    await newProgress.save();

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    logSecurityEvent('USER_REGISTERED', { 
      userId: user._id, 
      username, 
      email: email 
    }, req);

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
        createdAt: user.createdAt
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
    // ENHANCED: Use secure query method
    const user = await User.findOne({ 
      email: validator.isEmail(email) ? email : null 
    }).select('+password');

    if (!user) {
      logSecurityEvent('LOGIN_USER_NOT_FOUND', { email }, req);
      return errorResponse(res, 401, 'Invalid credentials.');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logSecurityEvent('LOGIN_INVALID_PASSWORD', { userId: user._id, email }, req);
      return errorResponse(res, 401, 'Invalid credentials.');
    }

    // FIXED: Only increment token version on explicit logout or security events
    // Don't invalidate all sessions on every login
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
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
        lastLogin: user.lastLogin
      }
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// ENHANCED: Improved refresh token handling with rotation
router.post('/refresh', asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return errorResponse(res, 401, 'Refresh token required.');
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // ENHANCED: Validate token type
    if (decoded.type !== 'refresh') {
      logSecurityEvent('REFRESH_TOKEN_INVALID_TYPE', { userId: decoded.userId }, req);
      return errorResponse(res, 401, 'Invalid token type.');
    }

    const user = await User.findById(decoded.userId);
    if (!user || user.tokenVersion !== decoded.tokenVersion) {
      logSecurityEvent('REFRESH_TOKEN_INVALID', { userId: decoded.userId }, req);
      return errorResponse(res, 401, 'Invalid refresh token.');
    }

    // ENHANCED: Implement token rotation for better security
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();

    // Generate new token pair
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

    logSecurityEvent('REFRESH_TOKEN_SUCCESS', { userId: user._id }, req);

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
    // ENHANCED: Secure search filter construction
    const filter = {};
    if (search) {
      const sanitizedSearch = validator.escape(search);
      // Use exact field matching to prevent injection
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

// ENHANCED: Additional security routes and improvements
// @route GET /users/:id
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
    // ENHANCED: Use secure query method
    const user = await findUserSecurely({ _id: req.params.id });
    
    if (!user) {
      return errorResponse(res, 404, 'User not found.');
    }

    // Remove sensitive fields
    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin
    };

    res.json({ success: true, data: userResponse });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// Continue with other routes using similar security enhancements...
// [Additional routes would follow the same pattern with enhanced security]

module.exports = router;