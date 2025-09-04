const router = require('express').Router();
const { body, param, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const Module = require('../models/module.model');

/** Utility: Standard error response */
function errorResponse(res, status, message, errors = []) {
  return res.status(status).json({
    success: false,
    message,
    errors
  });
}

/** GET /modules - List all modules (lean for perf, consistent response) */
router.get('/', async (req, res) => {
  try {
    const modules = await Module.find()
      .populate('user', 'username email fullName')
      .lean();
    res.json({ success: true, data: modules });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch modules.', [err.message]);
  }
});

/** POST /modules/add - Create module with validation */
router.post('/add', [
  body('user').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Valid user ObjectId required.'),
  body('description').isString().trim().isLength({ min: 5, max: 500 }).withMessage('Description must be 5-500 chars.'),
  body('duration').isInt({ min: 1, max: 1440 }).withMessage('Duration must be between 1 and 1440 minutes.'),
  body('date').isISO8601().toDate().withMessage('Valid date required.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  const { user, description, duration, date } = req.body;
  try {
    const newModule = new Module({ user, description, duration, date });
    await newModule.save();
    res.status(201).json({ success: true, message: 'Module added!', data: newModule });
  } catch (err) {
    errorResponse(res, 500, 'Failed to add module.', [err.message]);
  }
});

/** GET /modules/:id - Get single module */
router.get('/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid module ID.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const module = await Module.findById(req.params.id)
      .populate('user', 'username email fullName')
      .lean();
    if (!module) return errorResponse(res, 404, 'Module not found.');
    res.json({ success: true, data: module });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch module.', [err.message]);
  }
});

/** DELETE /modules/:id - Delete module */
router.delete('/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid module ID.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const result = await Module.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Module not found or already deleted.');
    res.json({ success: true, message: 'Module deleted.' });
  } catch (err) {
    errorResponse(res, 500, 'Failed to delete module.', [err.message]);
  }
});

/** POST /modules/update/:id - Update module */
router.post('/update/:id', [
  param('id').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid module ID.'),
  body('user').optional().custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Valid user ObjectId required.'),
  body('description').optional().isString().trim().isLength({ min: 5, max: 500 }).withMessage('Description must be 5-500 chars.'),
  body('duration').optional().isInt({ min: 1, max: 1440 }).withMessage('Duration must be between 1 and 1440 minutes.'),
  body('date').optional().isISO8601().toDate().withMessage('Valid date required.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const module = await Module.findById(req.params.id);
    if (!module) return errorResponse(res, 404, 'Module not found.');
    if (req.body.user) module.user = req.body.user;
    if (req.body.description) module.description = req.body.description;
    if (req.body.duration !== undefined) module.duration = req.body.duration;
    if (req.body.date) module.date = req.body.date;
    await module.save();
    res.json({ success: true, message: 'Module updated!', data: module });
  } catch (err) {
    errorResponse(res, 500, 'Failed to update module.', [err.message]);
  }
});

module.exports = router;