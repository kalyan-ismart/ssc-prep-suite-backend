// routes/goals.js
const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const Goal = require('../models/goal.model');
const { errorResponse } = require('../utils/errors');

const router = express.Router();

// Validation middleware for create/update
const validateGoal = [
  body('userId').isMongoId().withMessage('Valid user ID is required'),
  body('title').isString().trim().isLength({ min: 1, max: 100 }).withMessage('Title must be 1-100 characters'),
  body('target').isInt({ min: 1 }).withMessage('Target must be a positive integer'),
  body('completed').optional().isBoolean().withMessage('Completed must be a boolean'),
  body('category').isMongoId().withMessage('Valid category ID is required'),
  body('deadline').isISO8601().toDate().withMessage('Valid ISO date is required'),
  body('progress').optional().isInt({ min: 0 }).withMessage('Progress must be a non-negative integer'),
  body('isActive').optional().isBoolean().withMessage('isActive must be a boolean'),
];

// GET all goals (with optional filters)
router.get('/', [
  query('userId').optional().isMongoId().withMessage('Valid user ID is required'),
  query('category').optional().isMongoId().withMessage('Valid category ID is required'),
  query('search').optional().isString().isLength({ max: 100 }).withMessage('Search query too long'),
], async (req, res) => {
  try {
    const { userId, category, search } = req.query;
    const filter = {};

    if (userId) filter.user = userId;
    if (category) filter.category = category;
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
      ];
    }

    const data = await Goal.find(filter)
      .populate('user', 'username fullName')
      .populate('category', 'name icon color')
      .sort({ deadline: 1 })
      .lean();
    res.json({ success: true, data });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch goals.', [error.message]);
  }
});

// GET goal by ID
router.get('/:id', [
  param('id').isMongoId().withMessage('Valid goal ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const goal = await Goal.findById(req.params.id)
      .populate('user', 'username fullName')
      .populate('category', 'name icon color')
      .lean();
    if (!goal) return errorResponse(res, 404, 'Goal not found.');
    res.json({ success: true, data: goal });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch goal.', [error.message]);
  }
});

// POST add goal
router.post('/add', validateGoal, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const goal = new Goal({
      user: req.body.userId,
      title: req.body.title,
      target: req.body.target,
      category: req.body.category,
      deadline: req.body.deadline,
      progress: req.body.progress || 0,
      isActive: req.body.isActive !== undefined ? req.body.isActive : true,
    });
    await goal.save();
    const populatedGoal = await Goal.findById(goal._id)
      .populate('user', 'username fullName')
      .populate('category', 'name icon color')
      .lean();
    res.status(201).json({ success: true, message: 'Goal added.', data: populatedGoal });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to add goal.', [error.message]);
  }
});

// POST update goal by ID
router.post('/update/:id', [
  param('id').isMongoId().withMessage('Valid goal ID is required'),
  ...validateGoal.map(v => v.optional({ nullable: true })),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    let goal = await Goal.findById(req.params.id);
    if (!goal) return errorResponse(res, 404, 'Goal not found.');

    // Update fields
    if (req.body.userId) goal.user = req.body.userId;
    if (req.body.title) goal.title = req.body.title;
    if (req.body.target) goal.target = req.body.target;
    if (req.body.completed !== undefined) goal.completed = req.body.completed;
    if (req.body.category) goal.category = req.body.category;
    if (req.body.deadline) goal.deadline = req.body.deadline;
    if (req.body.progress !== undefined) goal.progress = req.body.progress;
    if (req.body.isActive !== undefined) goal.isActive = req.body.isActive;

    await goal.save();
    const populatedGoal = await Goal.findById(goal._id)
      .populate('user', 'username fullName')
      .populate('category', 'name icon color')
      .lean();
    res.json({ success: true, message: 'Goal updated.', data: populatedGoal });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to update goal.', [error.message]);
  }
});

// DELETE goal by ID
router.delete('/:id', [
  param('id').isMongoId().withMessage('Valid goal ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const result = await Goal.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Goal not found.');
    res.json({ success: true, message: 'Goal deleted.' });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to delete goal.', [error.message]);
  }
});

module.exports = router;