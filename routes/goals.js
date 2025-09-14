// routes/goals.js

const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const validator = require('validator');
const Goal = require('../models/goal.model');
const { errorResponse, handleDatabaseError, asyncHandler, logSecurityEvent } = require('../utils/errors');
const { auth, adminAuth, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// Enhanced validation middleware for create/update
const validateGoal = [
  body('userId')
    .isMongoId()
    .withMessage('Valid user ID is required'),
  body('title')
    .isString()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Title must be 1-100 characters')
    .customSanitizer((value) => validator.escape(value)),
  body('target')
    .isInt({ min: 1, max: 100000 })
    .withMessage('Target must be between 1 and 100000'),
  body('completed')
    .optional()
    .isBoolean()
    .withMessage('Completed must be a boolean'),
  body('category')
    .isMongoId()
    .withMessage('Valid category ID is required'),
  body('deadline')
    .isISO8601()
    .toDate()
    .withMessage('Valid ISO date is required'),
  body('progress')
    .optional()
    .isInt({ min: 0, max: 100000 })
    .withMessage('Progress must be between 0 and 100000'),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean'),
];

const validateGoalQuery = [
  query('userId')
    .optional()
    .isMongoId()
    .withMessage('Valid user ID is required'),
  query('category')
    .optional()
    .isMongoId()
    .withMessage('Valid category ID is required'),
  query('search')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('Search query too long')
    .customSanitizer((value) => validator.escape(value)),
  query('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Page must be between 1 and 1000'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
];

// GET all goals (with optional filters and enhanced security)
router.get('/', [optionalAuth, ...validateGoalQuery], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const { userId, category, search } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const skip = (page - 1) * limit;

    const filter = {};
    if (userId) filter.user = userId;
    if (category) filter.category = category;

    // Authorization check - users can only see their own goals unless admin
    if (req.user && req.user.role !== 'admin' && userId && req.user.id !== userId) {
      logSecurityEvent('UNAUTHORIZED_GOAL_ACCESS', { 
        requesterId: req.user.id, 
        targetUserId: userId 
      }, req);
      return errorResponse(res, 403, 'Access denied. You can only view your own goals.');
    }

    if (search) {
      const sanitizedSearch = validator.escape(search);
      filter.$or = [
        { title: { $regex: sanitizedSearch, $options: 'i' } },
      ];
    }

    const [data, total] = await Promise.all([
      Goal.find(filter)
        .populate('user', 'username fullName')
        .populate('category', 'name icon color')
        .select('-__v')
        .skip(skip)
        .limit(limit)
        .sort({ deadline: 1 })
        .lean(),
      Goal.countDocuments(filter)
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

// GET goal by ID with enhanced security
router.get('/:id', [
  optionalAuth,
  param('id').isMongoId().withMessage('Valid goal ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const goal = await Goal.findById(req.params.id)
      .populate('user', 'username fullName')
      .populate('category', 'name icon color')
      .select('-__v')
      .lean();

    if (!goal) {
      return errorResponse(res, 404, 'Goal not found.');
    }

    // Authorization check - users can only see their own goals unless admin
    if (req.user && req.user.role !== 'admin' && req.user.id !== goal.user._id.toString()) {
      logSecurityEvent('UNAUTHORIZED_GOAL_ACCESS', { 
        requesterId: req.user.id, 
        goalId: req.params.id,
        goalOwner: goal.user._id 
      }, req);
      return errorResponse(res, 403, 'Access denied. You can only view your own goals.');
    }

    res.json({ success: true, data: goal });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST add goal with authentication
router.post('/add', [auth, ...validateGoal], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    // Users can only create goals for themselves unless admin
    if (req.user.role !== 'admin' && req.body.userId !== req.user.id) {
      logSecurityEvent('UNAUTHORIZED_GOAL_CREATION', { 
        requesterId: req.user.id, 
        targetUserId: req.body.userId 
      }, req);
      return errorResponse(res, 403, 'You can only create goals for yourself.');
    }

    const goal = new Goal({
      user: req.body.userId,
      title: req.body.title,
      target: req.body.target,
      category: req.body.category,
      deadline: req.body.deadline,
      progress: req.body.progress || 0,
      isActive: req.body.isActive !== undefined ? req.body.isActive : true,
      createdAt: new Date()
    });

    await goal.save();

    const populatedGoal = await Goal.findById(goal._id)
      .populate('user', 'username fullName')
      .populate('category', 'name icon color')
      .select('-__v')
      .lean();

    logSecurityEvent('GOAL_CREATED', { 
      goalId: goal._id, 
      createdBy: req.user.id,
      targetUserId: req.body.userId
    }, req);

    res.status(201).json({ 
      success: true, 
      message: 'Goal added successfully.', 
      data: populatedGoal 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST update goal by ID with enhanced security
router.post('/update/:id', [
  auth,
  param('id').isMongoId().withMessage('Valid goal ID is required'),
  ...validateGoal.map(v => v.optional({ nullable: true })),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const goal = await Goal.findById(req.params.id);
    if (!goal) {
      return errorResponse(res, 404, 'Goal not found.');
    }

    // Authorization check - users can only update their own goals unless admin
    if (req.user.role !== 'admin' && req.user.id !== goal.user.toString()) {
      logSecurityEvent('UNAUTHORIZED_GOAL_UPDATE', { 
        requesterId: req.user.id, 
        goalId: req.params.id,
        goalOwner: goal.user 
      }, req);
      return errorResponse(res, 403, 'You can only update your own goals.');
    }

    // Prevent users from changing goal ownership unless admin
    if (req.body.userId && req.user.role !== 'admin' && req.body.userId !== req.user.id) {
      delete req.body.userId;
    }

    // Update fields
    const updateData = {};
    if (req.body.userId) updateData.user = req.body.userId;
    if (req.body.title) updateData.title = req.body.title;
    if (req.body.target) updateData.target = req.body.target;
    if (req.body.completed !== undefined) updateData.completed = req.body.completed;
    if (req.body.category) updateData.category = req.body.category;
    if (req.body.deadline) updateData.deadline = req.body.deadline;
    if (req.body.progress !== undefined) updateData.progress = req.body.progress;
    if (req.body.isActive !== undefined) updateData.isActive = req.body.isActive;
    updateData.updatedAt = new Date();

    const updatedGoal = await Goal.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true, runValidators: true }
    )
      .populate('user', 'username fullName')
      .populate('category', 'name icon color')
      .select('-__v')
      .lean();

    logSecurityEvent('GOAL_UPDATED', { 
      goalId: req.params.id, 
      updatedBy: req.user.id 
    }, req);

    res.json({ 
      success: true, 
      message: 'Goal updated successfully.', 
      data: updatedGoal 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// DELETE goal by ID with enhanced security
router.delete('/:id', [
  auth,
  param('id').isMongoId().withMessage('Valid goal ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const goal = await Goal.findById(req.params.id);
    if (!goal) {
      return errorResponse(res, 404, 'Goal not found.');
    }

    // Authorization check - users can only delete their own goals unless admin
    if (req.user.role !== 'admin' && req.user.id !== goal.user.toString()) {
      logSecurityEvent('UNAUTHORIZED_GOAL_DELETE', { 
        requesterId: req.user.id, 
        goalId: req.params.id,
        goalOwner: goal.user 
      }, req);
      return errorResponse(res, 403, 'You can only delete your own goals.');
    }

    await Goal.findByIdAndDelete(req.params.id);

    logSecurityEvent('GOAL_DELETED', { 
      goalId: req.params.id, 
      deletedBy: req.user.id 
    }, req);

    res.json({ 
      success: true, 
      message: 'Goal deleted successfully.' 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

module.exports = router;