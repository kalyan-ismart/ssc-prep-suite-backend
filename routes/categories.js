// routes/categories.js

const express = require('express');
const { body, param, validationResult } = require('express-validator');
const Category = require('../models/category.model');
const Tool = require('../models/tool.model');
const { errorResponse, handleDatabaseError, asyncHandler } = require('../utils/errors');
const { auth, adminAuth, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// Validation middleware
const validateCategory = [
  body('name').isString().trim().isLength({ min: 1, max: 100 }).withMessage('Name must be 1-100 characters'),
  body('description').optional().isString().trim().isLength({ max: 500 }),
  body('icon').optional().isString().trim().isLength({ max: 5 }).withMessage('Icon must be a single emoji or text'),
];

// GET all categories
// Public read
router.get('/', optionalAuth, asyncHandler(async (req, res) => {
  try {
    const categories = await Category.find().lean();
    res.json({ success: true, data: categories });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// GET single category by ID
// Public read
router.get('/:id', optionalAuth, [
  param('id').isMongoId().withMessage('Valid category ID is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  try {
    const category = await Category.findById(req.params.id).lean();
    if (!category) return errorResponse(res, 404, 'Category not found.');
    res.json({ success: true, data: category });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// GET all tools for a category
// Public read
router.get('/:id/tools', optionalAuth, [
  param('id').isMongoId().withMessage('Valid category ID is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  try {
    const tools = await Tool.find({ category: req.params.id, isActive: true })
      .select('-settings')
      .lean();
    res.json({ success: true, data: tools });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// POST add category (Admin only)
router.post('/add', [auth, adminAuth, ...validateCategory], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  try {
    const existing = await Category.findOne({ name: req.body.name });
    if (existing) return errorResponse(res, 409, 'Category name already exists.');

    const category = new Category({
      name: req.body.name,
      description: req.body.description || '',
      icon: req.body.icon || ''
    });
    await category.save();
    res.status(201).json({ success: true, data: category });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// PUT update category (Admin only)
router.put('/update/:id', [auth, adminAuth,
  param('id').isMongoId().withMessage('Valid category ID is required'),
  ...validateCategory.map(v => v.optional({ nullable: true }))
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  try {
    const category = await Category.findById(req.params.id);
    if (!category) return errorResponse(res, 404, 'Category not found.');

    if (req.body.name && req.body.name !== category.name) {
      const dup = await Category.findOne({ name: req.body.name });
      if (dup) return errorResponse(res, 409, 'Category name already exists.');
    }

    Object.entries(req.body).forEach(([key, val]) => {
      if (val !== undefined) category[key] = val;
    });
    await category.save();

    res.json({ success: true, data: category });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

// DELETE category (Admin only)
router.delete('/:id', [auth, adminAuth,
  param('id').isMongoId().withMessage('Valid category ID is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  try {
    const category = await Category.findByIdAndDelete(req.params.id).lean();
    if (!category) return errorResponse(res, 404, 'Category not found.');
    res.json({ success: true, message: 'Category deleted successfully.' });
  } catch (err) {
    return handleDatabaseError(res, err);
  }
}));

module.exports = router;
