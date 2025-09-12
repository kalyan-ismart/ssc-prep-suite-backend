// routes/analytics.js
const express = require('express');
const { param, validationResult } = require('express-validator');
const Progress = require('../models/progress.model');
const { errorResponse } = require('../utils/errors');

const router = express.Router();

// GET dashboard analytics for user
router.get('/dashboard/:userId', [
  param('userId').isMongoId().withMessage('Valid user ID is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Invalid user ID.', errors.array());
  }

  try {
    const progress = await Progress.findOne({ user: req.params.userId }).lean();
    if (!progress) return errorResponse(res, 404, 'Progress not found.');

    const data = {
      totalStudyTime: progress.totalStudyTime,
      averageScore: progress.averageScore,
      streak: progress.streak.current,
      goalsCompletion: Math.round((progress.goalsCompleted / progress.totalGoals) * 100) || 0,
    };

    res.json({ success: true, data });
  } catch (error) {
    console.error(error);
    errorResponse(res, 500, 'Failed to fetch analytics.', [error.message]);
  }
});

module.exports = router;