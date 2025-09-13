// routes/users.js

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, param, query, validationResult } = require('express-validator');
const User = require('../models/user.model');
const Progress = require('../models/progress.model');
const { errorResponse, handleDatabaseError, asyncHandler } = require('../utils/errors');
const { auth, adminAuth } = require('../middleware/auth');

const router = express.Router();

// --- Enhanced Validation Rules ---

const validateRegistration = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 32 })
    .matches(/^[a-zA-Z0-9_\-.]+$/)
    .withMessage('Username must be 3-32 characters and can contain letters, numbers, or _-.'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email.'),
  body('password')
    .isString()
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be at least 8 characters with uppercase, lowercase, number and special character.'),
  body('fullName')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Full name must be less than 100 characters.'),
];

const validateLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email.'),
  body('password')
    .notEmpty()
    .withMessage('Password is required.'),
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
    .withMessage('Full name must be less than 100 characters.'),
  body('role')
    .optional()
    .isIn(['user', 'admin'])
    .withMessage('Role must be either user or admin.'),
];

const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer.'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100.'),
  query('search')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Search query must be less than 100 characters.'),
];

// --- Authentication Routes ---

// @route POST /users/register
// @desc Register a new user and return JWT
// @access Public
router.post('/register', validateRegistration, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  const { username, email, password, fullName } = req.body;

  try {
    // Check for duplicate username or email
    const [usernameExists, emailExists] = await Promise.all([
      User.findOne({ username }),
      User.findOne({ email })
    ]);

    if (usernameExists) {
      return errorResponse(res, 409, 'Username already exists.');
    }
    if (emailExists) {
      return errorResponse(res, 409, 'Email already registered.');
    }

    // Create new user (password is automatically hashed by the model's pre-save hook)
    const user = new User({ username, email, password, fullName });
    await user.save();

    // Create an associated progress document
    const newProgress = new Progress({ user: user._id });
    await newProgress.save();

    // Create and sign JWT
    const payload = { user: { id: user.id, role: user.role } };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ 
      success: true, 
      token,
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
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return errorResponse(res, 401, 'Invalid credentials.');
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return errorResponse(res, 401, 'Invalid credentials.');
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const payload = { user: { id: user.id, role: user.role } };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      success: true, 
      token,
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
    // Build search filter
    const filter = {};
    if (search) {
      filter.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { fullName: { $regex: search, $options: 'i' } }
      ];
    }

    const [users, total] = await Promise.all([
      User.find(filter)
        .select('-password')
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
    return errorResponse(res, 403, 'Access denied. You can only view your own profile.');
  }

  try {
    const user = await User.findById(req.params.id)
      .select('-password')
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
      const existingUser = await User.findOne({ username: updateData.username });
      if (existingUser) {
        return errorResponse(res, 409, 'Username already exists.');
      }
    }

    if (updateData.email && updateData.email !== user.email) {
      const existingUser = await User.findOne({ email: updateData.email });
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
    ).select('-password').lean();

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
      .select('-password')
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