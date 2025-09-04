const router = require('express').Router();
const { body, param, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const Category = require('../models/category.model');

/** Error Response Utility */
function errorResponse(res, status, message, errors = []) {
  return res.status(status).json({ success: false, message, errors });
}

/** GET /categories - List all categories */
router.get('/', async (req, res) => {
  try {
    const categories = await Category.aggregate([
      {
        $lookup: {
          from: 'tools',
          localField: '_id',
          foreignField: 'category',
          as: 'tools'
        }
      },
      {
        $addFields: {
          toolsCount: { $size: '$tools' },
          activeToolsCount: {
            $size: {
              $filter: {
                input: '$tools',
                as: 'tool',
                cond: { $eq: ['$$tool.isActive', true] }
              }
            }
          }
        }
      },
      {
        $project: {
          name: 1,
          description: 1,
          icon: 1,
          color: 1,
          order: 1,
          isActive: 1,
          toolsCount: 1,
          activeToolsCount: 1,
          createdAt: 1,
          updatedAt: 1
        }
      },
      { $sort: { order: 1 } }
    ]);
    res.json({ success: true, data: categories });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch categories.', [err.message]);
  }
});

/** POST /categories/add - Add category */
router.post('/add', [
  body('name').isString().trim().isLength({ min: 2, max: 50 }).withMessage('Name must be 2-50 chars.'),
  body('description').isString().trim().isLength({ min: 5, max: 200 }),
  body('icon').isString().trim().withMessage('Icon required.'),
  body('color').isString().matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/).withMessage('Valid hex color required.'),
  body('order').optional().isInt({ min: 0 }),
  body('isActive').optional().isBoolean()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const newCategory = new Category({ ...req.body });
    await newCategory.save();
    res.status(201).json({ success: true, message: 'Category added!', data: newCategory });
  } catch (err) {
    errorResponse(res, 500, 'Failed to add category.', [err.message]);
  }
});

/** GET /categories/:id - Get single category */
router.get('/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid category ID.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const category = await Category.findById(req.params.id).lean();
    if (!category) return errorResponse(res, 404, 'Category not found.');
    res.json({ success: true, data: category });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch category.', [err.message]);
  }
});

/** DELETE /categories/:id - Delete category */
router.delete('/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid category ID.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const result = await Category.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Category not found or already deleted.');
    res.json({ success: true, message: 'Category deleted.' });
  } catch (err) {
    errorResponse(res, 500, 'Failed to delete category.', [err.message]);
  }
});

/** POST /categories/update/:id - Update category */
router.post('/update/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid category ID.'),
  body('name').optional().isString().trim().isLength({ min: 2, max: 50 }),
  body('description').optional().isString().trim().isLength({ min: 5, max: 200 }),
  body('icon').optional().isString().trim(),
  body('color').optional().isString().matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/),
  body('order').optional().isInt({ min: 0 }),
  body('isActive').optional().isBoolean()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const category = await Category.findById(req.params.id);
    if (!category) return errorResponse(res, 404, 'Category not found.');
    Object.entries(req.body).forEach(([key, value]) => {
      if (value !== undefined) category[key] = value;
    });
    await category.save();
    res.json({ success: true, message: 'Category updated!', data: category });
  } catch (err) {
    errorResponse(res, 500, 'Failed to update category.', [err.message]);
  }
});

module.exports = router;