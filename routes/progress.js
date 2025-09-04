const router = require('express').Router();
const { body, param, validationResult, query } = require('express-validator');
const mongoose = require('mongoose');
const Progress = require('../models/progress.model');

/** Error Response Utility */
function errorResponse(res, status, message, errors = []) {
  return res.status(status).json({ success: false, message, errors });
}

/** GET /progress/user/:userId - Get user progress */
router.get('/user/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const progress = await Progress.findOne({ user: req.params.userId })
      .populate('user', 'username email')
      .populate('categoryProgress.category', 'name icon color')
      .populate('toolUsage.tool', 'name toolType')
      .lean();
    if (!progress) return errorResponse(res, 404, 'Progress data not found for user.');
    res.json({ success: true, data: progress });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch progress.', [err.message]);
  }
});

/** GET /progress/analytics/:userId - Get progress analytics (Business Logic Example) */
router.get('/analytics/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const progress = await Progress.findOne({ user: req.params.userId }).lean();
    if (!progress) return errorResponse(res, 404, 'Progress data not found for user.');

    // Example analytics
    const totalTime = progress.totalStudyTime;
    const avgScore = progress.averageScore;
    const streak = progress.streak?.current || 0;
    const goalsCompleted = progress.goalsCompleted;
    const completionRate = progress.totalGoals > 0 ? Math.round((goalsCompleted / progress.totalGoals) * 100) : 0;
    const mostUsedTool = progress.toolUsage?.length
      ? progress.toolUsage.reduce((max, cur) => cur.usageCount > max.usageCount ? cur : max).tool
      : null;
    const topCategory = progress.categoryProgress?.length
      ? progress.categoryProgress.reduce((max, cur) => cur.timeSpent > max.timeSpent ? cur : max).category
      : null;

    res.json({
      success: true,
      data: {
        totalTime,
        avgScore,
        streak,
        goalsCompleted,
        completionRate,
        mostUsedTool,
        topCategory
      }
    });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch analytics.', [err.message]);
  }
});

/** GET /progress/leaderboard - Get leaderboard (Business Logic Example) */
router.get('/leaderboard', [
  query('limit').optional().isInt({ min: 1, max: 100 })
], async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 10;
    // Example: Top users by averageScore
    const leaderboard = await Progress.find({}, 'user averageScore goalsCompleted totalStudyTime')
      .populate('user', 'username fullName')
      .sort({ averageScore: -1, goalsCompleted: -1 })
      .limit(limit)
      .lean();
    res.json({ success: true, data: leaderboard });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch leaderboard.', [err.message]);
  }
});

/** POST /progress/update/:userId - Update user progress (Business Logic Example) */
router.post('/update/:userId', [
  param('userId').custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid user ID.'),
  body('categoryId').optional().custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid category ID.'),
  body('toolId').optional().custom((value) => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid tool ID.'),
  body('score').optional().isInt({ min: 0, max: 100 }),
  body('timeSpent').optional().isInt({ min: 0 }),
  body('streakData').optional().isObject()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    let progress = await Progress.findOne({ user: req.params.userId });
    if (!progress) return errorResponse(res, 404, 'Progress data not found for user.');

    // Example update logic
    if (req.body.timeSpent) progress.totalStudyTime += req.body.timeSpent;
    if (req.body.score) {
      // Update averageScore (simple moving average)
      progress.averageScore = Math.round((progress.averageScore + req.body.score) / 2);
    }
    // Update streak
    if (req.body.streakData) {
      progress.streak.current = req.body.streakData.current || progress.streak.current;
      progress.streak.longest = Math.max(progress.streak.longest, req.body.streakData.longest || 0);
      progress.streak.lastActive = req.body.streakData.lastActive || new Date();
    }
    // Update categoryProgress/toolUsage if provided
    await progress.save();
    res.json({ success: true, message: 'Progress updated successfully!', data: progress });
  } catch (err) {
    errorResponse(res, 500, 'Failed to update progress.', [err.message]);
  }
});

module.exports = router;