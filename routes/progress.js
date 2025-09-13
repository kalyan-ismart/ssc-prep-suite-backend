// routes/progress.js

const express = require('express');
const { validationResult } = require('express-validator');
const Progress = require('../models/progress.model');
const { errorResponse, handleDatabaseError, asyncHandler } = require('../utils/errors');
const { validateUserId, validateProgressUpdate, validateAnalyticsQuery } = require('../validators/progressValidators');
const { auth, adminAuth } = require('../middleware/auth');

const router = express.Router();

// @route GET /progress
// @desc Get all progress documents (ADMIN ONLY)
// @access Private (Admin)
router.get('/', [auth, adminAuth], asyncHandler(async (req, res) => {
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
    return handleDatabaseError(res, error);
  }
}));

// @route GET /progress/user/:userId
// @desc Get progress of a specific user
// @access Private
router.get('/user/:userId', [auth, ...validateUserId], asyncHandler(async (req, res) => {
  // Authorization: User can get their own progress, or an admin can get any
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
    return errorResponse(res, 403, 'Not authorized to view this progress.');
  }

  try {
    const progress = await Progress.findOne({ user: req.params.userId })
      .populate('user', 'username email')
      .lean();

    if (!progress) {
      return errorResponse(res, 404, 'Progress not found.');
    }

    res.json({ success: true, data: progress });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// @route GET /progress/analytics/:userId
// @desc Get analytics for a user
// @access Private
router.get('/analytics/:userId', [auth, ...validateUserId], asyncHandler(async (req, res) => {
  // Authorization: User can get their own analytics, or an admin can get any
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
    return errorResponse(res, 403, 'Not authorized to view this analytics.');
  }

  try {
    const progress = await Progress.findOne({ user: req.params.userId })
      .populate('user', 'username email fullName')
      .lean();

    if (!progress) {
      return errorResponse(res, 404, 'Progress not found.');
    }

    // Calculate analytics data
    const analytics = {
      user: progress.user,
      overview: {
        totalStudyTime: progress.totalStudyTime || 0,
        averageScore: progress.averageScore || 0,
        quizzesTaken: progress.quizzesTaken || 0,
        currentStreak: progress.streak?.currentStreak || 0,
        longestStreak: progress.streak?.longestStreak || 0
      },
      weeklyProgress: calculateWeeklyProgress(progress),
      subjectPerformance: calculateSubjectPerformance(progress),
      streakAnalysis: calculateStreakAnalysis(progress),
      studyPatterns: calculateStudyPatterns(progress),
      improvements: generateImprovementSuggestions(progress)
    };

    res.json({ 
      success: true, 
      data: analytics,
      generatedAt: new Date().toISOString()
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// @route POST /progress/update/:userId
// @desc Update a user's progress
// @access Private
router.post('/update/:userId', [auth, ...validateProgressUpdate], asyncHandler(async (req, res) => {
  // Authorization: User can update their own progress, or an admin can update any
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
    return errorResponse(res, 403, 'Not authorized to update this progress.');
  }

  try {
    const progress = await Progress.findOne({ user: req.params.userId });
    if (!progress) {
      return errorResponse(res, 404, 'Progress not found.');
    }

    const updateFields = {};

    // Update study time
    if (req.body.timeSpent) {
      updateFields.$inc = { totalStudyTime: req.body.timeSpent };
    }

    // Update quiz score and average
    if (req.body.score !== undefined) {
      const currentTotalScore = (progress.averageScore || 0) * (progress.quizzesTaken || 0);
      const newQuizzesTaken = (progress.quizzesTaken || 0) + 1;
      updateFields.averageScore = Math.round((currentTotalScore + req.body.score) / newQuizzesTaken);
      updateFields.quizzesTaken = newQuizzesTaken;
      
      // Update best score if applicable
      if (req.body.score > (progress.bestScore || 0)) {
        updateFields.bestScore = req.body.score;
      }
    }

    // Update streak data
    if (req.body.streakData) {
      const currentStreak = progress.streak || {};
      updateFields.streak = { 
        ...currentStreak, 
        ...req.body.streakData,
        lastUpdated: new Date()
      };
    }

    // Update last activity
    updateFields.lastActivity = new Date();

    const updatedProgress = await Progress.findOneAndUpdate(
      { user: req.params.userId },
      updateFields,
      { new: true, runValidators: true }
    ).populate('user', 'username email').lean();

    res.json({ 
      success: true, 
      message: 'Progress updated successfully.', 
      data: updatedProgress 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// @route POST /progress/bulk-update
// @desc Bulk update progress for multiple users (ADMIN ONLY)
// @access Private (Admin)
router.post('/bulk-update', [auth, adminAuth], asyncHandler(async (req, res) => {
  const { updates } = req.body;

  if (!Array.isArray(updates)) {
    return errorResponse(res, 400, 'Updates must be an array.');
  }

  try {
    const results = [];
    
    for (const update of updates) {
      const { userId, ...progressData } = update;
      
      const updatedProgress = await Progress.findOneAndUpdate(
        { user: userId },
        { $set: progressData, lastActivity: new Date() },
        { new: true, runValidators: true }
      );
      
      results.push({
        userId,
        success: !!updatedProgress,
        data: updatedProgress
      });
    }

    res.json({
      success: true,
      message: `Bulk update completed. ${results.filter(r => r.success).length}/${results.length} updates successful.`,
      results
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// Helper functions for analytics calculations

function calculateWeeklyProgress(progress) {
  // Mock implementation - in real app, you'd calculate from detailed logs
  const daysOfWeek = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  return daysOfWeek.map(day => ({
    day,
    studyTime: Math.floor(Math.random() * 120) + 30, // Mock data
    quizzes: Math.floor(Math.random() * 5)
  }));
}

function calculateSubjectPerformance(progress) {
  // Mock implementation - in real app, you'd calculate from quiz history
  const subjects = ['Quantitative Aptitude', 'English', 'General Knowledge', 'Reasoning'];
  return subjects.map(subject => ({
    subject,
    averageScore: Math.floor(Math.random() * 40) + 60,
    questionsAttempted: Math.floor(Math.random() * 200) + 50,
    accuracy: Math.floor(Math.random() * 30) + 70
  }));
}

function calculateStreakAnalysis(progress) {
  return {
    currentStreak: progress.streak?.currentStreak || 0,
    longestStreak: progress.streak?.longestStreak || 0,
    streakGoal: 30,
    streakHistory: [] // In real app, maintain streak history
  };
}

function calculateStudyPatterns(progress) {
  return {
    preferredStudyTime: 'Evening', // Mock data
    averageSessionLength: Math.floor((progress.totalStudyTime || 0) / Math.max(progress.quizzesTaken || 1, 1)),
    mostActiveDay: 'Sunday',
    consistency: Math.min(((progress.streak?.currentStreak || 0) / 7) * 100, 100)
  };
}

function generateImprovementSuggestions(progress) {
  const suggestions = [];
  
  if ((progress.averageScore || 0) < 70) {
    suggestions.push({
      type: 'performance',
      message: 'Focus on practice tests to improve your average score',
      priority: 'high'
    });
  }
  
  if ((progress.streak?.currentStreak || 0) < 7) {
    suggestions.push({
      type: 'consistency',
      message: 'Try to study daily to build a strong study streak',
      priority: 'medium'
    });
  }
  
  if ((progress.totalStudyTime || 0) < 300) { // Less than 5 hours
    suggestions.push({
      type: 'time',
      message: 'Increase your daily study time to at least 2 hours',
      priority: 'medium'
    });
  }
  
  return suggestions;
}

module.exports = router;