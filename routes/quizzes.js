// routes/quizzes.js

const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const Quiz = require('../models/quiz.model');
const { errorResponse, handleDatabaseError, asyncHandler } = require('../utils/errors');
const { auth, adminAuth, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// Validation middleware for create/update
const validateQuiz = [
  body('title')
    .isString()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Title must be 1-100 characters'),
  body('questions')
    .optional()
    .isArray()
    .withMessage('Questions must be an array'),
  body('questions.*.questionText')
    .optional()
    .isString()
    .trim()
    .withMessage('Question text must be a string'),
  body('questions.*.options')
    .optional()
    .isArray()
    .withMessage('Options must be an array'),
  body('questions.*.options.*.text')
    .optional()
    .isString()
    .trim()
    .withMessage('Option text must be a string'),
  body('questions.*.options.*.isCorrect')
    .optional()
    .isBoolean()
    .withMessage('isCorrect must be a boolean'),
  body('category')
    .isMongoId()
    .withMessage('Valid category ID is required'),
  body('difficulty')
    .optional()
    .isIn(['easy', 'medium', 'hard'])
    .withMessage('Invalid difficulty level'),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean'),
  body('timeLimit')
    .optional()
    .isInt({ min: 1, max: 300 })
    .withMessage('Time limit must be between 1 and 300 minutes'),
];

const validateQuizQuery = [
  query('category')
    .optional()
    .isMongoId()
    .withMessage('Valid category ID is required'),
  query('difficulty')
    .optional()
    .isIn(['easy', 'medium', 'hard'])
    .withMessage('Invalid difficulty level'),
  query('search')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('Search query too long'),
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 50 })
    .withMessage('Limit must be between 1 and 50'),
  query('active')
    .optional()
    .isBoolean()
    .withMessage('Active must be a boolean')
];

// GET all quizzes (with optional filters and pagination)
router.get('/', [optionalAuth, ...validateQuizQuery], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const { category, difficulty, search, active } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const filter = {};
    
    // Build filter
    if (category) filter.category = category;
    if (difficulty) filter.difficulty = difficulty;
    if (active !== undefined) filter.isActive = active;
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { 'questions.questionText': { $regex: search, $options: 'i' } },
      ];
    }

    // Default to active quizzes only for non-admin users
    if (!req.user || req.user.role !== 'admin') {
      filter.isActive = true;
    }

    const [data, total] = await Promise.all([
      Quiz.find(filter)
        .populate('category', 'name icon color')
        .populate('createdBy', 'username fullName')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 })
        .lean(),
      Quiz.countDocuments(filter)
    ]);

    const totalPages = Math.ceil(total / limit);

    res.json({ 
      success: true, 
      data,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// GET quiz by ID
router.get('/:id', [
  optionalAuth,
  param('id').isMongoId().withMessage('Valid quiz ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const filter = { _id: req.params.id };
    
    // Non-admin users can only see active quizzes
    if (!req.user || req.user.role !== 'admin') {
      filter.isActive = true;
    }

    const quiz = await Quiz.findOne(filter)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();

    if (!quiz) {
      return errorResponse(res, 404, 'Quiz not found.');
    }

    res.json({ success: true, data: quiz });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST add quiz (Authenticated users)
router.post('/add', [auth, ...validateQuiz], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    // Check if title already exists
    const existingQuiz = await Quiz.findOne({ title: req.body.title });
    if (existingQuiz) {
      return errorResponse(res, 409, 'Quiz title already exists.');
    }

    // Add creator information
    const quizData = {
      ...req.body,
      createdBy: req.user.id,
      createdAt: new Date()
    };

    const quiz = new Quiz(quizData);
    await quiz.save();

    const populatedQuiz = await Quiz.findById(quiz._id)
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();

    res.status(201).json({ 
      success: true, 
      message: 'Quiz added successfully.', 
      data: populatedQuiz 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST update quiz by ID (Admin or quiz creator)
router.post('/update/:id', [
  auth,
  param('id').isMongoId().withMessage('Valid quiz ID is required'),
  ...validateQuiz.map(v => v.optional({ nullable: true })),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const quiz = await Quiz.findById(req.params.id);
    if (!quiz) {
      return errorResponse(res, 404, 'Quiz not found.');
    }

    // Check ownership - only admin or quiz creator can update
    if (req.user.role !== 'admin' && quiz.createdBy?.toString() !== req.user.id) {
      return errorResponse(res, 403, 'You can only update quizzes you created.');
    }

    // Check for duplicate title if changing
    if (req.body.title && req.body.title !== quiz.title) {
      const existingQuiz = await Quiz.findOne({ title: req.body.title });
      if (existingQuiz) {
        return errorResponse(res, 409, 'Quiz title already exists.');
      }
    }

    // Update fields
    const updateData = { ...req.body, updatedAt: new Date() };
    
    // Only admin can change certain fields
    if (req.user.role !== 'admin') {
      delete updateData.isActive;
    }

    const updatedQuiz = await Quiz.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true, runValidators: true }
    )
      .populate('category', 'name icon color')
      .populate('createdBy', 'username fullName')
      .lean();

    res.json({ 
      success: true, 
      message: 'Quiz updated successfully.', 
      data: updatedQuiz 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// DELETE quiz by ID (Admin only)
router.delete('/:id', [
  auth,
  adminAuth,
  param('id').isMongoId().withMessage('Valid quiz ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const quiz = await Quiz.findById(req.params.id);
    if (!quiz) {
      return errorResponse(res, 404, 'Quiz not found.');
    }

    await Quiz.findByIdAndDelete(req.params.id);

    res.json({ 
      success: true, 
      message: 'Quiz deleted successfully.',
      deletedQuiz: {
        id: quiz._id,
        title: quiz.title,
        deletedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST submit quiz answers (Authenticated users)
router.post('/:id/submit', [
  auth,
  param('id').isMongoId().withMessage('Valid quiz ID is required'),
  body('answers').isArray().withMessage('Answers must be an array'),
  body('timeSpent').optional().isInt({ min: 1 }).withMessage('Time spent must be a positive integer')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const quiz = await Quiz.findById(req.params.id).lean();
    if (!quiz) {
      return errorResponse(res, 404, 'Quiz not found.');
    }

    if (!quiz.isActive) {
      return errorResponse(res, 400, 'Quiz is not active.');
    }

    const { answers, timeSpent } = req.body;
    
    // Calculate score
    let correctAnswers = 0;
    let totalQuestions = quiz.questions.length;
    
    answers.forEach((answer, index) => {
      if (quiz.questions[index]) {
        const correctOption = quiz.questions[index].options.find(opt => opt.isCorrect);
        if (correctOption && answer === correctOption.text) {
          correctAnswers++;
        }
      }
    });

    const score = Math.round((correctAnswers / totalQuestions) * 100);
    
    // Create submission record (if you have a submissions model)
    const submission = {
      userId: req.user.id,
      quizId: req.params.id,
      answers,
      score,
      correctAnswers,
      totalQuestions,
      timeSpent: timeSpent || 0,
      submittedAt: new Date()
    };

    res.json({
      success: true,
      message: 'Quiz submitted successfully.',
      results: {
        score,
        correctAnswers,
        totalQuestions,
        percentage: score,
        timeSpent: timeSpent || 0,
        passed: score >= 60 // Assuming 60% is passing
      }
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST toggle quiz status (Admin only)
router.post('/:id/toggle', [
  auth,
  adminAuth,
  param('id').isMongoId().withMessage('Valid quiz ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const quiz = await Quiz.findById(req.params.id);
    if (!quiz) {
      return errorResponse(res, 404, 'Quiz not found.');
    }

    quiz.isActive = !quiz.isActive;
    quiz.updatedAt = new Date();
    await quiz.save();

    const populatedQuiz = await Quiz.findById(quiz._id)
      .populate('category', 'name icon color')
      .lean();

    res.json({ 
      success: true, 
      message: `Quiz ${quiz.isActive ? 'activated' : 'deactivated'} successfully.`,
      data: populatedQuiz
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

module.exports = router;