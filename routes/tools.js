// routes/tools.js

const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const Tool = require('../models/tool.model');
const { errorResponse, handleDatabaseError, asyncHandler } = require('../utils/errors');
const { auth, adminAuth, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// Validation middlewares for create/update
const validateTool = [
  body('name')
    .isString()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be 2-100 characters'),
  body('description')
    .isString()
    .trim()
    .isLength({ min: 5, max: 500 })
    .withMessage('Description must be 5-500 characters'),
  body('category')
    .isMongoId()
    .withMessage('Valid category ID is required'),
  body('toolType')
    .isIn([
      'analytics', 'quiz', 'planner', 'calculator', 'tracker',
      'ai-assistant', 'simulator', 'database', 'practice', 'assessment',
      'utility', 'interactive',
    ])
    .withMessage('Invalid tool type'),
  body('isActive')
    .optional()
    .isBoolean(),
  body('settings')
    .optional()
    .isObject(),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
];

const validateToolQuery = [
  query('category')
    .optional()
    .isMongoId()
    .withMessage('Valid category ID is required'),
  query('type')
    .optional()
    .isString()
    .isLength({ max: 50 })
    .withMessage('Type must be a string with max 50 characters'),
  query('search')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('Search query must be max 100 characters'),
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
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
    return errorResponse(res, 422, 'Invalid query.', errors.array());
  }

  try {
    const { category, type, search, active } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const filter = {};
    
    // Build filter
    if (category) filter.category = category;
    if (type) filter.toolType = type;
    if (active !== undefined) filter.isActive = active;
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $elemMatch: { $regex: search, $options: 'i' } } },
      ];
    }

    // Default to active tools only for non-admin users
    if (!req.user || req.user.role !== 'admin') {
      filter.isActive = true;
    }

    const [data, total] = await Promise.all([
      Tool.find(filter)
        .populate('category', 'name icon color')
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
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// GET tool by ID
router.get('/:id', [
  optionalAuth,
  param('id').isMongoId().withMessage('Valid tool ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const filter = { _id: req.params.id };
    
    // Non-admin users can only see active tools
    if (!req.user || req.user.role !== 'admin') {
      filter.isActive = true;
    }

    const tool = await Tool.findOne(filter)
      .populate('category', 'name icon color')
      .lean();

    if (!tool) {
      return errorResponse(res, 404, 'Tool not found.');
    }

    res.json({ success: true, data: tool });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// POST add tool (Admin only)
router.post('/add', [auth, adminAuth, ...validateTool], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    // Check for duplicate name
    const existing = await Tool.findOne({ name: req.body.name });
    if (existing) {
      return errorResponse(res, 409, 'Tool name already exists.');
    }

    // Add creator information
    const toolData = {
      ...req.body,
      createdBy: req.user.id,
      createdAt: new Date()
    };

    const tool = new Tool(toolData);
    await tool.save();

    const populatedTool = await Tool.findById(tool._id)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();

    res.status(201).json({ 
      success: true, 
      message: 'Tool added successfully.', 
      data: populatedTool 
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// POST update tool by ID (Admin only or tool creator)
router.post('/update/:id', [
  auth,
  param('id').isMongoId().withMessage('Valid tool ID is required'),
  ...validateTool.map(v => v.optional({ nullable: true })),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const tool = await Tool.findById(req.params.id);
    if (!tool) {
      return errorResponse(res, 404, 'Tool not found.');
    }

    // Check ownership - only admin or tool creator can update
    if (req.user.role !== 'admin' && tool.createdBy?.toString() !== req.user.id) {
      return errorResponse(res, 403, 'You can only update tools you created.');
    }

    // Check for duplicate name if changing
    if (req.body.name && req.body.name !== tool.name) {
      const existing = await Tool.findOne({ name: req.body.name });
      if (existing) {
        return errorResponse(res, 409, 'Tool name already exists.');
      }
    }

    // Update fields
    const updateData = { ...req.body, updatedAt: new Date() };
    
    // Only admin can change certain fields
    if (req.user.role !== 'admin') {
      delete updateData.isActive;
      delete updateData.category;
    }

    const updatedTool = await Tool.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true, runValidators: true }
    )
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();

    res.json({ 
      success: true, 
      message: 'Tool updated successfully.', 
      data: updatedTool 
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// DELETE tool by ID (Admin only)
router.delete('/:id', [
  auth, 
  adminAuth,
  param('id').isMongoId().withMessage('Valid tool ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const tool = await Tool.findById(req.params.id);
    if (!tool) {
      return errorResponse(res, 404, 'Tool not found.');
    }

    await Tool.findByIdAndDelete(req.params.id);

    res.json({ 
      success: true, 
      message: 'Tool deleted successfully.',
      deletedTool: {
        id: tool._id,
        name: tool.name,
        deletedAt: new Date().toISOString()
      }
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// POST toggle tool status (Admin only)
router.post('/:id/toggle', [
  auth,
  adminAuth,
  param('id').isMongoId().withMessage('Valid tool ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const tool = await Tool.findById(req.params.id);
    if (!tool) {
      return errorResponse(res, 404, 'Tool not found.');
    }

    tool.isActive = !tool.isActive;
    tool.updatedAt = new Date();
    await tool.save();

    const populatedTool = await Tool.findById(tool._id)
      .populate('category', 'name icon color')
      .lean();

    res.json({ 
      success: true, 
      message: `Tool ${tool.isActive ? 'activated' : 'deactivated'} successfully.`,
      data: populatedTool
    });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

module.exports = router;