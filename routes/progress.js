// routes/progress.js

const express = require('express');
const { validationResult } = require('express-validator');
const Progress = require('../models/progress.model');
const { errorResponse } = require('../utils/errors');
const { validateUserId, validateProgressUpdate } = require('../validators/progressValidators');
const auth = require('../middleware/auth'); // <-- Import authentication middleware

const router = express.Router();

// @route   GET /progress
// @desc    Get all progress documents (ADMIN ONLY)
// @access  Private (Admin)
router.get('/', auth, async (req, res) => {
  // Authorization: Only allow admins to access this route
  if (req.user.role !== 'admin') {
    return errorResponse(res, 403, 'Access denied. Admins only.');
  }

  try {
    const allProgress = await Progress.find()
      .populate('user', 'username email')
      .lean();

    res.status(200).json({
      success: true,
      count: allProgress.length,
      data: allProgress,
    });
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch all progress documents.', [error.message]);
  }
});


// @route   GET /progress/user/:userId
// @desc    Get progress of a specific user
// @access  Private
router.get('/user/:userId', [auth, validateUserId], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Invalid user ID.', errors.array());
  
  // Authorization: User can get their own progress, or an admin can get any
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
      return errorResponse(res, 403, 'Not authorized to view this progress.');
  }

  try {
    const progress = await Progress.findOne({ user: req.params.userId })
      .populate('user', 'username email')
      .lean();
    if (!progress) return errorResponse(res, 404, 'Progress not found.');

    res.json({ success: true, data: progress });
  } catch (error) {
    errorResponse(res, 500, 'Failed to fetch progress.', [error.message]);
  }
});


// @route   GET /progress/analytics/:userId
// @desc    Get analytics for a user
// @access  Private
router.get('/analytics/:userId', [auth, validateUserId], async (req, res) => {
    // ... (Authorization check is similar to the one above)
    // ... your existing analytics logic ...
});


// @route   POST /progress/update/:userId
// @desc    Update a user's progress
// @access  Private
router.post('/update/:userId', [auth, validateUserId, validateProgressUpdate], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  // Authorization: User can update their own progress, or an admin can update any
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
      return errorResponse(res, 403, 'Not authorized to update this progress.');
  }
  
  try {
    const progress = await Progress.findOne({ user: req.params.userId });
    if (!progress) return errorResponse(res, 404, 'Progress not found.');

    const updateFields = {};

    if (req.body.timeSpent) {
      updateFields.$inc = { totalStudyTime: req.body.timeSpent };
    }

    if (req.body.score) {
      const currentTotalScore = (progress.averageScore || 0) * (progress.quizzesTaken || 0);
      const newQuizzesTaken = (progress.quizzesTaken || 0) + 1;
      updateFields.averageScore = Math.round((currentTotalScore + req.body.score) / newQuizzesTaken);
      updateFields.quizzesTaken = newQuizzesTaken;
    }

    if (req.body.streakData) {
      updateFields.streak = { ...progress.streak, ...req.body.streakData };
    }

    const updatedProgress = await Progress.findOneAndUpdate(
      { user: req.params.userId },
      updateFields,
      { new: true }
    ).lean();

    res.json({ success: true, message: 'Progress updated.', data: updatedProgress });
  } catch (error) {
    errorResponse(res, 500, 'Failed to update progress.', [error.message]);
  }
});

module.exports = router;

