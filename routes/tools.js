const router = require('express').Router();
const { body, param, query, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const Tool = require('../models/tool.model');

/** Error Response Utility */
function errorResponse(res, status, message, errors = []) {
  return res.status(status).json({ success: false, message, errors });
}

/** GET /tools - List all tools, optional search/filter */
router.get('/', [
  query('category').optional().custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid category ID.'),
  query('type').optional().isString(),
  query('search').optional().isString().isLength({ max: 100 })
], async (req, res) => {
  try {
    const { category, type, search } = req.query;
    let findQuery = {};
    if (category) findQuery.category = category;
    if (type) findQuery.toolType = type;
    if (search) {
      findQuery.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $elemMatch: { $regex: search, $options: 'i' } } }
      ];
    }
    const tools = await Tool.find(findQuery).populate('category', 'name icon color').lean();
    res.json({ success: true, data: tools });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch tools.', [err.message]);
  }
});

/** POST /tools/add - Add Tool */
router.post('/add', [
  body('name').isString().trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2-100 chars.'),
  body('description').isString().trim().isLength({ min: 5, max: 500 }),
  body('category').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Valid category ID required.'),
  body('toolType').isIn([
    'analytics', 'quiz', 'planner', 'calculator', 'tracker', 'ai-assistant', 'simulator',
    'database', 'practice', 'assessment', 'utility', 'interactive'
  ]).withMessage('Invalid tool type.'),
  body('isActive').optional().isBoolean(),
  body('settings').optional(),
  body('tags').optional().isArray()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const newTool = new Tool({ ...req.body });
    await newTool.save();
    res.status(201).json({ success: true, message: 'Tool added!', data: newTool });
  } catch (err) {
    errorResponse(res, 500, 'Failed to add tool.', [err.message]);
  }
});

/** GET /tools/:id - Get single tool */
router.get('/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid tool ID.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const tool = await Tool.findById(req.params.id).populate('category', 'name icon color').lean();
    if (!tool) return errorResponse(res, 404, 'Tool not found.');
    res.json({ success: true, data: tool });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch tool.', [err.message]);
  }
});

/** DELETE /tools/:id */
router.delete('/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid tool ID.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const result = await Tool.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Tool not found or already deleted.');
    res.json({ success: true, message: 'Tool deleted.' });
  } catch (err) {
    errorResponse(res, 500, 'Failed to delete tool.', [err.message]);
  }
});

/** POST /tools/update/:id - Update tool */
router.post('/update/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid tool ID.'),
  body('name').optional().isString().trim().isLength({ min: 2, max: 100 }),
  body('description').optional().isString().trim().isLength({ min: 5, max: 500 }),
  body('category').optional().custom((value) => mongoose.Types.ObjectId.isValid(value)),
  body('toolType').optional().isIn([
    'analytics', 'quiz', 'planner', 'calculator', 'tracker', 'ai-assistant', 'simulator',
    'database', 'practice', 'assessment', 'utility', 'interactive'
  ]),
  body('isActive').optional().isBoolean(),
  body('settings').optional(),
  body('tags').optional().isArray()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const tool = await Tool.findById(req.params.id);
    if (!tool) return errorResponse(res, 404, 'Tool not found.');
    Object.entries(req.body).forEach(([key, value]) => {
      if (value !== undefined) tool[key] = value;
    });
    await tool.save();
    res.json({ success: true, message: 'Tool updated!', data: tool });
  } catch (err) {
    errorResponse(res, 500, 'Failed to update tool.', [err.message]);
  }
});

module.exports = router;