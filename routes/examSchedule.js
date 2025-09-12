// routes/examSchedule.js
const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const ExamSchedule = require('../models/examSchedule.model');
const { errorResponse } = require('../utils/errors');

const router = express.Router();

// Validation middleware for create/update
const validateExam = [
  body('title').isString().trim().isLength({ min: 1, max: 100 }).withMessage('Title must be 1-100 characters'),
  body('date').isISO8601().toDate().withMessage('Valid ISO date is required'),
  body('description').optional().isString().trim().isLength({ max: 500 }).withMessage('Description must be at most 500 characters'),
  body('category').isMongoId().withMessage('Valid category ID is required'),
  body('createdBy').isMongoId().withMessage('Valid user ID is required'),
  body('isActive').optional().isBoolean().withMessage('isActive must be a boolean'),
];

// GET all exam schedules (with optional filters)
router.get('/', [
  query('category').optional().isMongoId().withMessage('Valid category ID is required'),
  query('createdBy').optional().isMongoId().withMessage('Valid user ID is required'),
  query('search').optional().isString().isLength({ max: 100 }).withMessage('Search query too long'),
], async (req, res) => {
  try {
    const { category, createdBy, search } = req.query;
    const filter = {};

    if (category) filter.category = category;
    if (createdBy) filter.createdBy = createdBy;
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
      ];
    }

    const data = await ExamSchedule.find(filter)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .sort({ date: 1 })
      .lean();
    res.json({ success: true, data });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch exam schedules.', [error.message]);
  }
});

// GET exam schedule by ID
router.get('/:id', [
  param('id').isMongoId().withMessage('Valid exam schedule ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const examSchedule = await ExamSchedule.findById(req.params.id)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();
    if (!examSchedule) return errorResponse(res, 404, 'Exam schedule not found.');
    res.json({ success: true, data: examSchedule });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch exam schedule.', [error.message]);
  }
});

// POST add exam schedule
router.post('/add', validateExam, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const examSchedule = new ExamSchedule(req.body);
    await examSchedule.save();
    const populatedExamSchedule = await ExamSchedule.findById(examSchedule._id)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();
    res.status(201).json({ success: true, message: 'Exam schedule added.', data: populatedExamSchedule });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to add exam schedule.', [error.message]);
  }
});

// POST update exam schedule by ID
router.post('/update/:id', [
  param('id').isMongoId().withMessage('Valid exam schedule ID is required'),
  ...validateExam.map(v => v.optional({ nullable: true })),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    let examSchedule = await ExamSchedule.findById(req.params.id);
    if (!examSchedule) return errorResponse(res, 404, 'Exam schedule not found.');

    // Update fields
    Object.entries(req.body).forEach(([key, value]) => {
      if (value !== undefined) examSchedule[key] = value;
    });

    await examSchedule.save();
    const populatedExamSchedule = await ExamSchedule.findById(examSchedule._id)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();
    res.json({ success: true, message: 'Exam schedule updated.', data: populatedExamSchedule });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to update exam schedule.', [error.message]);
  }
});

// DELETE exam schedule by ID
router.delete('/:id', [
  param('id').isMongoId().withMessage('Valid exam schedule ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const result = await ExamSchedule.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Exam schedule not found.');
    res.json({ success: true, message: 'Exam schedule deleted.' });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to delete exam schedule.', [error.message]);
  }
});

module.exports = router;