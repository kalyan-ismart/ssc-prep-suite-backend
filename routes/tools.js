// routes/tools.js

const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const validator = require('validator');
const Tool = require('../models/tool.model');
const { errorResponse, handleDatabaseError, asyncHandler, logSecurityEvent } = require('../utils/errors');
const { auth, adminAuth, optionalAuth } = require('../middleware/auth');
const isNullOrUndefined = require('../utils/nullUndefinedCheck');

const router = express.Router();

// Complete validation middleware for create/update
const validateTool = [
  body('name')
    .isString()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be 2-100 characters')
    .matches(/^[a-zA-Z0-9\s\-_\.]+$/)
    .withMessage('Name contains invalid characters')
    .customSanitizer((value) => validator.escape(value)),
  body('description')
    .isString()
    .trim()
    .isLength({ min: 5, max: 500 })
    .withMessage('Description must be 5-500 characters')
    .customSanitizer((value) => validator.escape(value)),
  body('category')
    .isString()
    .isIn(['calculator', 'converter', 'generator', 'analyzer', 'formatter', 'validator', 'planner', 'tracker', 'simulator', 'utility', 'other'])
    .withMessage('Valid category is required'),
  body('toolType')
    .isIn([
      'analytics', 'quiz', 'planner', 'calculator', 'tracker',
      'ai-assistant', 'simulator', 'database', 'practice', 'assessment',
      'utility', 'interactive', 'converter', 'generator', 'formatter', 'validator'
    ])
    .withMessage('Invalid tool type'),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean'),
  body('settings')
    .optional()
    .isObject()
    .withMessage('Settings must be an object')
    .custom((value) => {
      // Validate settings object structure
      if (value && typeof value === 'object') {
        const allowedKeys = ['maxAttempts', 'timeLimit', 'difficulty', 'features'];
        const keys = Object.keys(value);
        const invalidKeys = keys.filter(key => !allowedKeys.includes(key));
        if (invalidKeys.length > 0) {
          throw new Error(`Invalid settings keys: ${invalidKeys.join(', ')}`);
        }
      }
      return true;
    }),
  body('tags')
    .optional()
    .isArray({ max: 10 })
    .withMessage('Tags must be an array with maximum 10 items')
    .custom((tags) => {
      if (tags && Array.isArray(tags)) {
        for (const tag of tags) {
          if (typeof tag !== 'string' || tag.length > 50) {
            throw new Error('Each tag must be a string with maximum 50 characters');
          }
        }
      }
      return true;
    })
];

// Complete validation middleware for query parameters
const validateToolQuery = [
  query('category')
    .optional()
    .isString()
    .withMessage('Category must be a string'),
  query('type')
    .optional()
    .isString()
    .isLength({ max: 50 })
    .withMessage('Type must be a string with max 50 characters')
    .customSanitizer((value) => validator.escape(value)),
  query('search')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('Search query must be max 100 characters')
    .customSanitizer((value) => validator.escape(value)),
  query('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Page must be between 1 and 1000'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 50 })
    .withMessage('Limit must be between 1 and 50'),
  query('active')
    .optional()
    .isBoolean()
    .withMessage('Active must be a boolean')
];

// GET tools list (with optional filters and pagination)
router.get('/', [optionalAuth, ...validateToolQuery], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Invalid query parameters', errors.array());
  }

  try {
    const { category, type, search, active } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);
    const skip = (page - 1) * limit;

    const filter = {};

    // Apply filters with proper validation
    if (category) filter.category = category;
    if (type) filter.toolType = type;
    if (active !== undefined) filter.isActive = active === 'true';

    // Enhanced search with sanitized input
    if (search) {
      const sanitizedSearch = validator.escape(search);
      filter.$or = [
        { name: { $regex: sanitizedSearch, $options: 'i' } },
        { description: { $regex: sanitizedSearch, $options: 'i' } },
        { tags: { $elemMatch: { $regex: sanitizedSearch, $options: 'i' } } }
      ];
    }

    // Non-admins only see active tools by default
    if (!req.user || req.user.role !== 'admin') {
      filter.isActive = true;
    }

    const [data, total] = await Promise.all([
      Tool.find(filter)
        .populate('createdBy', 'username fullName')
        .select('-__v')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 })
        .lean(),
      Tool.countDocuments(filter)
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

// GET single tool by ID
router.get('/:id', [
  optionalAuth,
  param('id').isMongoId().withMessage('Valid tool ID is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed', errors.array());
  }

  try {
    const filter = { _id: req.params.id };

    // Non-admins can only see active tools
    if (!req.user || req.user.role !== 'admin') {
      filter.isActive = true;
    }

    const tool = await Tool.findOne(filter)
      .populate('createdBy', 'username fullName')
      .select('-__v')
      .lean();

    if (!tool) {
      return errorResponse(res, 404, 'Tool not found');
    }

    res.json({ success: true, data: tool });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST add tool (Admin only)
router.post('/add', [auth, adminAuth, ...validateTool], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed', errors.array());
  }

  try {
    // Check for duplicate tool name (case-insensitive)
    const existing = await Tool.findOne({
      name: new RegExp(`^${req.body.name.trim()}$`, 'i')
    });

    if (existing) {
      return errorResponse(res, 409, 'Tool name already exists');
    }

    const tool = new Tool({
      ...req.body,
      createdBy: req.user.id
    });

    await tool.save();

    const populatedTool = await Tool.findById(tool._id)
      .populate('createdBy', 'username fullName')
      .select('-__v')
      .lean();

    logSecurityEvent('TOOL_CREATED', {
      toolId: tool._id,
      name: tool.name,
      createdBy: req.user.id
    }, req);

    res.status(201).json({
      success: true,
      message: 'Tool added successfully',
      data: populatedTool
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST update tool by ID (Admin or creator)
router.post('/update/:id', [
  auth,
  param('id').isMongoId().withMessage('Valid tool ID is required'),
  ...validateTool.map(v => v.optional())
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed', errors.array());
  }

  try {
    const tool = await Tool.findById(req.params.id);
    if (!tool) {
      return errorResponse(res, 404, 'Tool not found');
    }

    // Only admin or creator may update
    if (req.user.role !== 'admin' && tool.createdBy.toString() !== req.user.id) {
      logSecurityEvent('UNAUTHORIZED_TOOL_UPDATE', {
        toolId: req.params.id,
        userId: req.user.id
      }, req);
      return errorResponse(res, 403, 'You can only update tools you created');
    }

    // Check for duplicate name if changing
    if (req.body.name && req.body.name.trim() !== tool.name) {
      const duplicate = await Tool.findOne({
        name: new RegExp(`^${req.body.name.trim()}$`, 'i'),
        _id: { $ne: req.params.id }
      });

      if (duplicate) {
        return errorResponse(res, 409, 'Tool name already exists');
      }
    }

    const updateData = { ...req.body };

    // Non-admins cannot change certain fields
    if (req.user.role !== 'admin') {
      delete updateData.isActive;
      delete updateData.category;
    }

    const updatedTool = await Tool.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true, runValidators: true }
    )
      .populate('createdBy', 'username fullName')
      .select('-__v')
      .lean();

    logSecurityEvent('TOOL_UPDATED', {
      toolId: req.params.id,
      updatedBy: req.user.id
    }, req);

    res.json({
      success: true,
      message: 'Tool updated successfully',
      data: updatedTool
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// DELETE tool by ID (Admin only)
router.delete('/:id', [
  auth,
  adminAuth,
  param('id').isMongoId().withMessage('Valid tool ID is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed', errors.array());
  }

  try {
    const tool = await Tool.findById(req.params.id);
    if (!tool) {
      return errorResponse(res, 404, 'Tool not found');
    }

    await Tool.findByIdAndDelete(req.params.id);

    logSecurityEvent('TOOL_DELETED', {
      toolId: req.params.id,
      name: tool.name,
      deletedBy: req.user.id
    }, req);

    res.json({
      success: true,
      message: 'Tool deleted successfully',
      deletedTool: {
        id: tool._id,
        name: tool.name,
        deletedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST toggle tool status (Admin only)
router.post('/:id/toggle', [
  auth,
  adminAuth,
  param('id').isMongoId().withMessage('Valid tool ID is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed', errors.array());
  }

  try {
    const tool = await Tool.findById(req.params.id);
    if (!tool) {
      return errorResponse(res, 404, 'Tool not found');
    }

    tool.isActive = !tool.isActive;
    await tool.save();

    const populatedTool = await Tool.findById(tool._id)
      .populate('createdBy', 'username fullName')
      .select('-__v')
      .lean();

    logSecurityEvent('TOOL_STATUS_TOGGLED', {
      toolId: tool._id,
      newStatus: tool.isActive,
      toggledBy: req.user.id
    }, req);

    res.json({
      success: true,
      message: `Tool ${tool.isActive ? 'activated' : 'deactivated'} successfully`,
      data: populatedTool
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

module.exports = router;