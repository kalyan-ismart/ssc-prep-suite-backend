const express = require('express');
const { body, param, validationResult } = require('express-validator');
const Category = require('../models/category.model');
const { errorResponse } = require('../utils/errors');

const router = express.Router();

// Validation middlewares
const validateCategory = [
  body('name').isString().trim().isLength({ min: 2, max: 50 }),
  body('description').isString().trim().isLength({ min: 5, max: 200 }),
  body('icon').isString().trim(),
  body('color').isString().matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/),
  body('order').optional().isInt({ min: 0 }),
  body('isActive').optional().isBoolean(),
];

// GET categories list
router.get('/', async (req, res) => {
  try {
    const categories = await Category.find().sort({ order: 1 }).lean();
    res.json({ success: true, data: categories });
  } catch (error) {
    console.error(error); // Log the error for debugging
    errorResponse(res, 500, 'Failed to fetch categories.', [error.message]);
  }
});

// POST add new category
router.post('/add', validateCategory, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const exists = await Category.findOne({ name: req.body.name });
    if (exists) return errorResponse(res, 409, 'Category name already exists.');

    const category = new Category(req.body);
    await category.save();
    res.status(201).json({ success: true, message: 'Category added.', data: category });
  } catch (error) {
    console.error(error); // Log the error for debugging
    errorResponse(res, 500, 'Failed to add category.', [error.message]);
  }
});

// GET category by ID
router.get('/:id', [
  param('id').isMongoId(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Invalid ID.', errors.array());
  }

  try {
    const category = await Category.findById(req.params.id).lean();
    if (!category) return errorResponse(res, 404, 'Category not found.');
    res.json({ success: true, data: category });
  } catch (error) {
    console.error(error); // Log the error for debugging
    errorResponse(res, 500, 'Failed to fetch category.', [error.message]);
  }
});

// DELETE category by ID
router.delete('/:id', [
  param('id').isMongoId(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Invalid ID.', errors.array());
  }

  try {
    const result = await Category.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Category not found or already deleted.');
    res.json({ success: true, message: 'Category deleted.' });
  } catch (error) {
    console.error(error); // Log the error for debugging
    errorResponse(res, 500, 'Failed to delete category.', [error.message]);
  }
});

// POST update category
router.post('/update/:id', [
  param('id').isMongoId(),
  ...validateCategory.map((validation) => validation.optional()),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const category = await Category.findById(req.params.id);
    if (!category) return errorResponse(res, 404, 'Category not found.');

    Object.entries(req.body).forEach(([key, value]) => {
      if (value !== undefined) category[key] = value;
    });

    await category.save();
    res.json({ success: true, message: 'Category updated.', data: category });
  } catch (error) {
    console.error(error); // Log the error for debugging
    errorResponse(res, 500, 'Failed to update category.', [error.message]);
  }
});

module.exports = router;