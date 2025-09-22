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
    .isLength({ min: 12, max: 128 })
    .withMessage('Password must be 12-128 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, lowercase letter, number, and special character')
    .custom((value) => {
        if (COMMON_PASSWORDS.includes(value.toLowerCase())) {
            throw new Error('Password is too common');
        }
        return true;
    });

// ENHANCED: Registration validation
const validateRegistration = [
    body('username')
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be 3-30 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username can only contain letters, numbers, and underscores')
        .customSanitizer((value) => validator.escape(value.toLowerCase())),
    
    body('email')
        .isEmail()
        .withMessage('Must be a valid email')
        .normalizeEmail()
        .customSanitizer((value) => validator.normalizeEmail(value)),
    
    validatePassword,
    
    body('fullName')
        .isLength({ min: 2, max: 100 })
        .withMessage('Full name must be 2-100 characters')
        .matches(/^[a-zA-Z\s\-'\.]+$/)
        .withMessage('Full name contains invalid characters')
        .customSanitizer((value) => validator.escape(value.trim())),
];

// User Registration
router.post('/register', validateRegistration, asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        await logSecurityEvent(req, 'REGISTRATION_VALIDATION_FAILED', 'warning', {
            errors: errors.array(),
            email: req.body.email
        });
        return errorResponse(res, 'Validation failed', 422, errors.array());
    }

    const { username, email, password, fullName } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
        $or: [{ email }, { username }]
    });

    if (existingUser) {
        await logSecurityEvent(req, 'REGISTRATION_DUPLICATE_ATTEMPT', 'warning', {
            email,
            username,
            existingField: existingUser.email === email ? 'email' : 'username'
        });
        return errorResponse(res, 'User already exists with this email or username', 409);
    }

    // Hash password
    const salt = await bcrypt.genSalt(15); // Increased from default 10
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
        username,
        email,
        password: hashedPassword,
        fullName,
        role: 'user'
    });

    await user.save();

    // Create initial progress record
    const progress = new Progress({
        user: user._id,
        totalQuizzesTaken: 0,
        totalCorrectAnswers: 0,
        totalQuestions: 0,
        averageScore: 0,
        streak: { current: 0, best: 0, lastQuizDate: null },
        categoryProgress: {},
        weeklyProgress: []
    });
    await progress.save();

    // Generate tokens
    const accessToken = jwt.sign(
        { userId: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
        { userId: user._id, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
    );

    // Store refresh token
    user.refreshTokens = [refreshToken];
    await user.save();

    await logSecurityEvent(req, 'USER_REGISTRATION_SUCCESS', 'info', {
        userId: user._id,
        email: user.email,
        username: user.username
    });

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
}));

// User Login
const validateLogin = [
    body('email')
        .isEmail()
        .withMessage('Must be a valid email')
        .normalizeEmail(),
    body('password')
        .notEmpty()
        .withMessage('Password is required')
];

router.post('/login', validateLogin, asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return errorResponse(res, 'Validation failed', 422, errors.array());
    }

    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
        await logSecurityEvent(req, 'LOGIN_FAILED_USER_NOT_FOUND', 'warning', { email });
        return errorResponse(res, 'Invalid credentials', 401);
    }

    // Check if account is locked
    if (user.loginAttempts >= 5 && user.lockUntil > Date.now()) {
        await logSecurityEvent(req, 'LOGIN_FAILED_ACCOUNT_LOCKED', 'warning', { 
            userId: user._id,
            email,
            lockUntil: user.lockUntil
        });
        return errorResponse(res, 'Account temporarily locked due to too many failed attempts', 423);
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        // Increment failed attempts
        user.loginAttempts = (user.loginAttempts || 0) + 1;
        if (user.loginAttempts >= 5) {
            user.lockUntil = Date.now() + (15 * 60 * 1000); // 15 minutes
        }
        await user.save();

        await logSecurityEvent(req, 'LOGIN_FAILED_INVALID_PASSWORD', 'warning', {
            userId: user._id,
            email,
            attempts: user.loginAttempts
        });
        return errorResponse(res, 'Invalid credentials', 401);
    }

    // Reset failed attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLogin = new Date();

    // Generate new tokens
    const accessToken = jwt.sign(
        { userId: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
        { userId: user._id, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
    );

    // Update refresh tokens (keep only last 5)
    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push(refreshToken);
    if (user.refreshTokens.length > 5) {
        user.refreshTokens = user.refreshTokens.slice(-5);
    }

    await user.save();

    await logSecurityEvent(req, 'USER_LOGIN_SUCCESS', 'info', {
        userId: user._id,
        email: user.email
    });

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
}));

// Refresh Token
router.post('/refresh-token', asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return errorResponse(res, 'Refresh token required', 401);
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        
        if (decoded.type !== 'refresh') {
            throw new Error('Invalid token type');
        }

        const user = await User.findById(decoded.userId);
        if (!user || !user.refreshTokens.includes(refreshToken)) {
            await logSecurityEvent(req, 'REFRESH_TOKEN_INVALID', 'warning', {
                userId: decoded.userId
            });
            return errorResponse(res, 'Invalid refresh token', 401);
        }

        // Generate new tokens
        const newAccessToken = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        const newRefreshToken = jwt.sign(
            { userId: user._id, type: 'refresh' },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: '7d' }
        );

        // Update refresh tokens (rotate tokens)
        user.refreshTokens = user.refreshTokens.filter(token => token !== refreshToken);
        user.refreshTokens.push(newRefreshToken);
        await user.save();

        await logSecurityEvent(req, 'REFRESH_TOKEN_SUCCESS', 'info', {
            userId: user._id
        });

        res.json({
            success: true,
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        });

    } catch (error) {
        await logSecurityEvent(req, 'REFRESH_TOKEN_ERROR', 'warning', {
            error: error.message
        });
        return errorResponse(res, 'Invalid refresh token', 401);
    }
}));

// Logout
router.post('/logout', auth, asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    
    const user = await User.findById(req.user.userId);
    if (user && refreshToken) {
        user.refreshTokens = user.refreshTokens.filter(token => token !== refreshToken);
        await user.save();
    }

    await logSecurityEvent(req, 'USER_LOGOUT', 'info', {
        userId: req.user.userId
    });

    res.json({
        success: true,
        message: 'Logged out successfully'
    });
}));

// Change Password
const validatePasswordChange = [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    validatePassword.clone().withMessage('New password validation failed')
];

router.post('/change-password', auth, validatePasswordChange, asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return errorResponse(res, 'Validation failed', 422, errors.array());
    }

    const { currentPassword, password: newPassword } = req.body;
    const user = await User.findById(req.user.userId).select('+password');

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
        await logSecurityEvent(req, 'PASSWORD_CHANGE_FAILED', 'warning', {
            userId: user._id
        });
        return errorResponse(res, 'Current password is incorrect', 401);
    }

    // Check if new password is same as current
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
        return errorResponse(res, 'New password must be different from current password', 400);
    }

    // Hash new password
    const salt = await bcrypt.genSalt(15);
    user.password = await bcrypt.hash(newPassword, salt);
    user.passwordChangedAt = new Date();

    // Invalidate all refresh tokens (force re-login)
    user.refreshTokens = [];
    
    await user.save();

    await logSecurityEvent(req, 'PASSWORD_CHANGE_SUCCESS', 'info', {
        userId: user._id
    });

    res.json({
        success: true,
        message: 'Password changed successfully. Please login again.'
    });
}));

// Get User Profile
router.get('/profile', auth, asyncHandler(async (req, res) => {
    const user = await User.findById(req.user.userId).select('-password -refreshTokens');
    if (!user) {
        return errorResponse(res, 'User not found', 404);
    }

    res.json({
        success: true,
        data: user
    });
}));

// Update User Profile
const validateProfileUpdate = [
    body('fullName')
        .optional()
        .isLength({ min: 2, max: 100 })
        .withMessage('Full name must be 2-100 characters')
        .customSanitizer((value) => validator.escape(value.trim())),
    
    body('username')
        .optional()
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be 3-30 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username can only contain letters, numbers, and underscores')
];

router.put('/profile', auth, validateProfileUpdate, asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return errorResponse(res, 'Validation failed', 422, errors.array());
    }

    const { fullName, username } = req.body;
    const updates = {};

    if (fullName) updates.fullName = fullName;
    if (username) {
        // Check if username is already taken
        const existingUser = await User.findOne({ 
            username, 
            _id: { $ne: req.user.userId } 
        });
        if (existingUser) {
            return errorResponse(res, 'Username already taken', 409);
        }
        updates.username = username.toLowerCase();
    }

    const user = await User.findByIdAndUpdate(
        req.user.userId,
        updates,
        { new: true, runValidators: true }
    ).select('-password -refreshTokens');

    await logSecurityEvent(req, 'PROFILE_UPDATE', 'info', {
        userId: user._id,
        updates: Object.keys(updates)
    });

    res.json({
        success: true,
        message: 'Profile updated successfully',
        data: user
    });
}));

// Get All Users (Admin only)
router.get('/', adminAuth, asyncHandler(async (req, res) => {
    const { page = 1, limit = 10, search = '' } = req.query;
    
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    // Build search query
    const searchQuery = search ? {
        $or: [
            { username: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
            { fullName: { $regex: search, $options: 'i' } }
        ]
    } : {};

    const [users, total] = await Promise.all([
        User.find(searchQuery)
            .select('-password -refreshTokens')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limitNum)
            .lean(),
        User.countDocuments(searchQuery)
    ]);

    res.json({
        success: true,
        data: users,
        pagination: {
            page: pageNum,
            limit: limitNum,
            total,
            totalPages: Math.ceil(total / limitNum)
        }
    });
}));

// Delete User Account
router.delete('/account', auth, asyncHandler(async (req, res) => {
    const { password } = req.body;

    if (!password) {
        return errorResponse(res, 'Password confirmation required', 400);
    }

    const user = await User.findById(req.user.userId).select('+password');
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        await logSecurityEvent(req, 'ACCOUNT_DELETE_FAILED', 'warning', {
            userId: user._id
        });
        return errorResponse(res, 'Invalid password', 401);
    }

    // Delete user and related data
    await Promise.all([
        User.findByIdAndDelete(req.user.userId),
        Progress.findOneAndDelete({ user: req.user.userId })
        // Add other related data deletions here
    ]);

    await logSecurityEvent(req, 'ACCOUNT_DELETED', 'info', {
        userId: user._id,
        email: user.email
    });

    res.json({
        success: true,
        message: 'Account deleted successfully'
    });
}));

module.exports = router;