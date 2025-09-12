// routes/tools.js
const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const Tool = require('../models/tool.model');
const { errorResponse } = require('../utils/errors');

const router = express.Router();

// Validation middlewares for create/update
const validateTool = [
  body('name').isString().trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2-100 characters'),
  body('description').isString().trim().isLength({ min: 5, max: 500 }).withMessage('Description must be 5-500 characters'),
  body('category').isMongoId().withMessage('Valid category ID is required'),
  body('toolType').isIn([
    'analytics', 'quiz', 'planner', 'calculator', 'tracker',
    'ai-assistant', 'simulator', 'database', 'practice', 'assessment',
    'utility', 'interactive',
  ]).withMessage('Invalid tool type'),
  body('isActive').optional().isBoolean(),
  body('settings').optional().isObject(),
  body('tags').optional().isArray().withMessage('Tags must be an array'),
];

// GET tools list (with optional filters)
router.get('/', [
  query('category').optional().isMongoId(),
  query('type').optional().isString(),
  query('search').optional().isString().isLength({ max: 100 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Invalid query.', errors.array());
  }

  try {
    const { category, type, search } = req.query;
    const filter = {};

    if (category) filter.category = category;
    if (type) filter.toolType = type;
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $elemMatch: { $regex: search, $options: 'i' } } },
      ];
    }

    const data = await Tool.find(filter).populate('category', 'name icon color').sort({ createdAt: -1 }).lean();
    res.json({ success: true, data });
  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Failed to fetch tools.', [err.message]);
  }
});

// GET tool by ID
router.get('/:id', [
  param('id').isMongoId().withMessage('Valid tool ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const tool = await Tool.findById(req.params.id).populate('category', 'name icon color').lean();
    if (!tool) return errorResponse(res, 404, 'Tool not found.');
    res.json({ success: true, data: tool });
  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Failed to fetch tool.', [err.message]);
  }
});

// POST add tool
router.post('/add', validateTool, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    // Check for duplicate name
    const existing = await Tool.findOne({ name: req.body.name });
    if (existing) return errorResponse(res, 409, 'Tool name already exists.');

    const tool = new Tool(req.body);
    await tool.save();
    const populatedTool = await Tool.findById(tool._id).populate('category', 'name icon color').lean();
    res.status(201).json({ success: true, message: 'Tool added.', data: populatedTool });
  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Failed to add tool.', [err.message]);
  }
});

// POST update tool by ID
router.post('/update/:id', [
  param('id').isMongoId().withMessage('Valid tool ID is required'),
  ...validateTool.map(v => v.optional({ nullable: true })),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    let tool = await Tool.findById(req.params.id);
    if (!tool) return errorResponse(res, 404, 'Tool not found.');

    // Check for duplicate name if changing
    if (req.body.name && req.body.name !== tool.name) {
      const dup = await Tool.findOne({ name: req.body.name });
      if (dup) return errorResponse(res, 409, 'Tool name already exists.');
    }

    // Update fields
    Object.entries(req.body).forEach(([key, value]) => {
      if (value !== undefined) tool[key] = value;
    });

    await tool.save();
    const populatedTool = await Tool.findById(tool._id).populate('category', 'name icon color').lean();
    res.json({ success: true, message: 'Tool updated.', data: populatedTool });
  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Failed to update tool.', [err.message]);
  }
});

// DELETE tool by ID
router.delete('/:id', [
  param('id').isMongoId().withMessage('Valid tool ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const result = await Tool.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Tool not found or already deleted.');
    res.json({ success: true, message: 'Tool deleted.' });
  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Failed to delete tool.', [err.message]);
  }
});

module.exports = router;