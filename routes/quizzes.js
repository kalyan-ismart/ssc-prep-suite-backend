// routes/quizzes.js
const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const Quiz = require('../models/quiz.model');
const { errorResponse } = require('../utils/errors');

const router = express.Router();

// Validation middleware for create/update
const validateQuiz = [
  body('title').isString().trim().isLength({ min: 1, max: 100 }).withMessage('Title must be 1-100 characters'),
  body('questions').optional().isArray().withMessage('Questions must be an array'),
  body('questions.*.questionText').optional().isString().trim().withMessage('Question text must be a string'),
  body('questions.*.options').optional().isArray().withMessage('Options must be an array'),
  body('questions.*.options.*.text').optional().isString().trim().withMessage('Option text must be a string'),
  body('questions.*.options.*.isCorrect').optional().isBoolean().withMessage('isCorrect must be a boolean'),
  body('category').isMongoId().withMessage('Valid category ID is required'),
  body('createdBy').isMongoId().withMessage('Valid user ID is required'),
  body('difficulty').optional().isIn(['easy', 'medium', 'hard']).withMessage('Invalid difficulty level'),
  body('isActive').optional().isBoolean().withMessage('isActive must be a boolean'),
];

// GET all quizzes (with optional filters)
router.get('/', [
  query('category').optional().isMongoId().withMessage('Valid category ID is required'),
  query('difficulty').optional().isIn(['easy', 'medium', 'hard']).withMessage('Invalid difficulty level'),
  query('search').optional().isString().isLength({ max: 100 }).withMessage('Search query too long'),
], async (req, res) => {
  try {
    const { category, difficulty, search } = req.query;
    const filter = {};

    if (category) filter.category = category;
    if (difficulty) filter.difficulty = difficulty;
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { 'questions.questionText': { $regex: search, $options: 'i' } },
      ];
    }

    const data = await Quiz.find(filter)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .sort({ createdAt: -1 })
      .lean();
    res.json({ success: true, data });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch quizzes.', [error.message]);
  }
});

// GET quiz by ID
router.get('/:id', [
  param('id').isMongoId().withMessage('Valid quiz ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const quiz = await Quiz.findById(req.params.id)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();
    if (!quiz) return errorResponse(res, 404, 'Quiz not found.');
    res.json({ success: true, data: quiz });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch quiz.', [error.message]);
  }
});

// POST add quiz
router.post('/add', validateQuiz, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const quiz = new Quiz(req.body);
    await quiz.save();
    const populatedQuiz = await Quiz.findById(quiz._id)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();
    res.status(201).json({ success: true, message: 'Quiz added.', data: populatedQuiz });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to add quiz.', [error.message]);
  }
});

// POST update quiz by ID
router.post('/update/:id', [
  param('id').isMongoId().withMessage('Valid quiz ID is required'),
  ...validateQuiz.map(v => v.optional({ nullable: true })),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    let quiz = await Quiz.findById(req.params.id);
    if (!quiz) return errorResponse(res, 404, 'Quiz not found.');

    // Update fields
    Object.entries(req.body).forEach(([key, value]) => {
      if (value !== undefined) quiz[key] = value;
    });

    await quiz.save();
    const populatedQuiz = await Quiz.findById(quiz._id)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();
    res.json({ success: true, message: 'Quiz updated.', data: populatedQuiz });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to update quiz.', [error.message]);
  }
});

// DELETE quiz by ID
router.delete('/:id', [
  param('id').isMongoId().withMessage('Valid quiz ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const result = await Quiz.findByIdAndDelete(req.params.id).lean();
    if (!result) return errorResponse(res, 404, 'Quiz not found.');
    res.json({ success: true, message: 'Quiz deleted.' });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to delete quiz.', [error.message]);
  }
});

module.exports = router;