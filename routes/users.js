// routes/users.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, param, query, validationResult } = require('express-validator');
const User = require('../models/user.model');
const Progress = require('../models/progress.model'); // For creating progress on register
const { errorResponse } = require('../utils/errors'); // Assuming you have this helper

const router = express.Router();

// --- Reusable Validation Rules ---
const validateRegistration = [
  body('username').trim().isLength({ min: 3, max: 32 }).matches(/^[a-zA-Z0-9_\-.]+$/).withMessage('Username must be 3-32 characters and can contain letters, numbers, or _-.'),
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email.'),
  body('password').isString().isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
  body('fullName').optional().isString().trim().isLength({ max: 100 }),
];

const validateLogin = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email.'),
  body('password').notEmpty().withMessage('Password is required.'),
];


// @route   POST /users/register
// @desc    Register a new user and return JWT
// @access  Public
router.post('/register', validateRegistration, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  const { username, email, password, fullName } = req.body;

  try {
    // Check for duplicate username or email
    const usernameExists = await User.findOne({ username });
    if (usernameExists) return errorResponse(res, 409, 'Username already exists.');

    const emailExists = await User.findOne({ email });
    if (emailExists) return errorResponse(res, 409, 'Email already registered.');

    // Create new user (password is automatically hashed by the model's pre-save hook)
    const user = new User({ username, email, password, fullName });
    await user.save();
    
    // Create an associated progress document
    const newProgress = new Progress({ user: user._id });
    await newProgress.save();

    // Create and sign JWT
    const payload = { user: { id: user.id, role: user.role } };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ success: true, token });

  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Server error during registration.', [err.message]);
  }
});


// @route   POST /users/login
// @desc    Authenticate user and return JWT
// @access  Public
router.post('/login', validateLogin, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return errorResponse(res, 401, 'Invalid credentials.');

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return errorResponse(res, 401, 'Invalid credentials.');

    const payload = { user: { id: user.id, role: user.role } };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ success: true, token });

  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Server error during login.', [err.message]);
  }
});


// --- Existing CRUD Routes (Should be protected later) ---

// GET all users (with pagination, filtering)
router.get('/', [ /* ... your validation rules ... */ ], async (req, res) => {
    // ... your existing code for GET / ...
});

// GET user by ID
router.get('/:id', [ /* ... your validation rules ... */ ], async (req, res) => {
    // ... your existing code for GET /:id ...
});

// POST update user by ID
router.post('/update/:id', [ /* ... your validation rules ... */ ], async (req, res) => {
    // ... your existing code for POST /update/:id ...
});

// DELETE user by ID
router.delete('/:id', [ /* ... your validation rules ... */ ], async (req, res) => {
    // ... your existing code for DELETE /:id ...
});


module.exports = router;

