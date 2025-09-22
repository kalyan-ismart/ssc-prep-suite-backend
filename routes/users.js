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

// FIXED: Password change validation - no clone method needed
const validatePasswordChange = [
    body('currentPassword')
        .notEmpty()
        .withMessage('Current password is required'),
    body('password')
        .isString()
        .isLength({ min: 12, max: 128 })
        .withMessage('New password must be 12-128 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/)
        .withMessage('New password must contain uppercase, lowercase, number, and special character')
        .custom(password => {
            const lower = password.toLowerCase();
            if (COMMON_PASSWORDS.some(p => lower.includes(p))) {
                throw new Error('Password contains common patterns and is not secure');
            }
            return true;
        })
];

// Route: POST /users/register
router.post(
    '/register',
    validateRegistration,
    asyncHandler(async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            await logSecurityEvent(req, 'REGISTRATION_VALIDATION_FAILED', 'warning', { 
                errors: errors.array(), 
                ip: req.ip 
            });
            return errorResponse(res, 'Validation failed.', 422, errors.array());
        }

        const { username, email, password, fullName } = req.body;

        try {
            const [userByName, userByEmail] = await Promise.all([
                User.findOne({ username }),
                User.findOne({ email }),
            ]);

            if (userByName) {
                await logSecurityEvent(req, 'REGISTRATION_DUPLICATE_USERNAME', 'warning', { username });
                return errorResponse(res, 'Username already exists.', 409);
            }

            if (userByEmail) {
                await logSecurityEvent(req, 'REGISTRATION_DUPLICATE_EMAIL', 'warning', { email });
                return errorResponse(res, 'Email already registered.', 409);
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
                { userId: user._id, tokenVersion: user.tokenVersion || 0, type: 'refresh' },
                process.env.JWT_REFRESH_SECRET,
                { expiresIn: '7d' }
            );

            await logSecurityEvent(req, 'USER_REGISTERED', 'info', { userId: user._id });

            res.status(201).json({
                success: true,
                message: 'User registered successfully.',
                accessToken,
                refreshToken,
                user: { id: user._id, username: user.username, email: user.email, role: user.role }
            });
        } catch (err) {
            return handleDatabaseError(err, req, res);
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
            await logSecurityEvent(req, 'LOGIN_VALIDATION_FAILED', 'warning', { errors: errors.array() });
            return errorResponse(res, 'Validation failed.', 422, errors.array());
        }

        const { email, password } = req.body;

        try {
            const user = await User.findOne({ email }).select('+password');
            if (!user) {
                await logSecurityEvent(req, 'LOGIN_USER_NOT_FOUND', 'warning', { email });
                return errorResponse(res, 'Invalid credentials.', 401);
            }

            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                await logSecurityEvent(req, 'LOGIN_INVALID_PASSWORD', 'warning', { userId: user._id });
                return errorResponse(res, 'Invalid credentials.', 401);
            }

            user.lastLogin = new Date();
            await user.save();

            const accessToken = jwt.sign(
                { user: { id: user._id, role: user.role }, type: 'access' },
                process.env.JWT_SECRET,
                { expiresIn: '15m' }
            );

            const refreshToken = jwt.sign(
                { userId: user._id, tokenVersion: user.tokenVersion || 0, type: 'refresh' },
                process.env.JWT_REFRESH_SECRET,
                { expiresIn: '7d' }
            );

            await logSecurityEvent(req, 'USER_LOGIN_SUCCESS', 'info', { userId: user._id });

            res.json({
                success: true,
                message: 'Login successful.',
                accessToken,
                refreshToken,
                user: { id: user._id, username: user.username, email: user.email, role: user.role }
            });
        } catch (err) {
            return handleDatabaseError(err, req, res);
        }
    })
);

// Route: POST /users/refresh-token
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
        if (!user) {
            await logSecurityEvent(req, 'REFRESH_TOKEN_INVALID', 'warning', {
                userId: decoded.userId
            });
            return errorResponse(res, 'Invalid refresh token', 401);
        }

        const newAccessToken = jwt.sign(
            { user: { id: user._id, role: user.role }, type: 'access' },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        const newRefreshToken = jwt.sign(
            { userId: user._id, tokenVersion: user.tokenVersion || 0, type: 'refresh' },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: '7d' }
        );

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

// Route: POST /users/change-password
router.post('/change-password', auth, validatePasswordChange, asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return errorResponse(res, 'Validation failed', 422, errors.array());
    }

    const { currentPassword, password: newPassword } = req.body;
    
    try {
        const user = await User.findById(req.user.id).select('+password');
        if (!user) {
            return errorResponse(res, 'User not found', 404);
        }

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
        const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 15;
        user.password = await bcrypt.hash(newPassword, saltRounds);
        user.passwordChangedAt = new Date();
        
        await user.save();

        await logSecurityEvent(req, 'PASSWORD_CHANGE_SUCCESS', 'info', {
            userId: user._id
        });

        res.json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (err) {
        return handleDatabaseError(err, req, res);
    }
}));

// Route: GET /users/profile
router.get('/profile', auth, asyncHandler(async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return errorResponse(res, 'User not found', 404);
        }

        res.json({
            success: true,
            data: user
        });
    } catch (err) {
        return handleDatabaseError(err, req, res);
    }
}));

// Route: GET /users (Admin only)
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

    try {
        const [users, total] = await Promise.all([
            User.find(searchQuery)
                .select('-password')
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
    } catch (err) {
        return handleDatabaseError(err, req, res);
    }
}));

module.exports = router;