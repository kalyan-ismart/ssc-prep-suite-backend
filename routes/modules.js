// routes/modules.js
const express = require('express');
const { body, param, validationResult } = require('express-validator');
const Module = require('../models/module.model');
const { errorResponse } = require('../utils/errors');

const router = express.Router();

// Validation middleware for create/update
const validateModule = [
  body('user').isMongoId().withMessage('Valid user ID is required'),
  body('description').isString().trim().isLength({ min: 5, max: 500 }).withMessage('Description must be 5-500 characters'),
  body('duration').isInt({ min: 1, max: 1440 }).withMessage('Duration must be 1-1440 minutes'),
  body('date').isISO8601().toDate().withMessage('Valid ISO date is required'),
];

// GET all modules (optionally filter by user)
router.get('/', async (req, res) => {
  try {
    const { userId } = req.query;
    const filter = userId ? { user: userId } : {};
    const data = await Module.find(filter).populate('user', 'username fullName').sort({ date: 1 }).lean();
    res.json({ success: true, data });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch modules.', [error.message]);
  }
});

// GET module by ID
router.get('/:id', [
  param('id').isMongoId().withMessage('Valid module ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const module = await Module.findById(req.params.id).populate('user', 'username fullName').lean();
    if (!module) return errorResponse(res, 404, 'Module not found.');
    res.json({ success: true, data: module });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch module.', [error.message]);
  }
});

// POST add a module
router.post('/add', validateModule, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const module = new Module(req.body);
    await module.save();
    const populatedModule = await Module.findById(module._id).populate('user', 'username fullName').lean();
    res.status(201).json({ success: true, message: 'Module added.', data: populatedModule });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to add module.', [error.message]);
  }
});

// POST update module by ID
router.post('/update/:id', [
  param('id').isMongoId().withMessage('Valid module ID is required'),
  ...validateModule.map(v => v.optional({ nullable: true })),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    let module = await Module.findById(req.params.id);
    if (!module) return errorResponse(res, 404, 'Module not found.');

    // Update fields if provided
    if (req.body.user) module.user = req.body.user;
    if (req.body.description) module.description = req.body.description;
    if (req.body.duration) module.duration = req.body.duration;
    if (req.body.date) module.date = req.body.date;

    await module.save();
    const populatedModule = await Module.findById(module._id).populate('user', 'username fullName').lean();
    res.json({ success: true, message: 'Module updated.', data: populatedModule });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to update module.', [error.message]);
  }
});

// DELETE module by ID
router.delete('/:id', [
  param('id').isMongoId().withMessage('Valid module ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const result = await Module.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Module not found.');
    res.json({ success: true, message: 'Module deleted.' });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to delete module.', [error.message]);
  }
});

module.exports = router;