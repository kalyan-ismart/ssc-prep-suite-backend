// routes/progress.js

const express = require('express');
const { validationResult } = require('express-validator');
const validator = require('validator');
const Progress = require('../models/progress.model');
const User = require('../models/user.model');
const Quiz = require('../models/quiz.model');
const { errorResponse, handleDatabaseError, asyncHandler, logSecurityEvent } = require('../utils/errors');
const { validateUserId, validateProgressUpdate, validateAnalyticsQuery } = require('../validators/progressValidators');
const { auth, adminAuth } = require('../middleware/auth');
const nullUndefinedCheck = require('../utils/nullUndefinedCheck');

const router = express.Router();

// Helper function to securely find progress by user ID
const findProgressSecurely = async (userId, populateFields = '') => {
  if (!validator.isMongoId(userId)) {
    throw new Error('Invalid user ID format');
  }
  return Progress.findOne({ user: userId }).populate(populateFields).lean();
};

// @route GET /progress
// @desc Get all progress documents (ADMIN ONLY)
// @access Private (Admin)
router.get('/', [auth, adminAuth], asyncHandler(async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);
    const skip = (page - 1) * limit;

    const [allProgress, total] = await Promise.all([
      Progress.find()
        .populate('user', 'username email fullName')
        .skip(skip)
        .limit(limit)
        .sort({ lastActivity: -1 })
        .lean(),
      Progress.countDocuments()
    ]);

    const totalPages = Math.ceil(total / limit);

    res.status(200).json({
      success: true,
      data: allProgress,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// @route GET /progress/user/:userId
// @desc Get progress of a specific user
// @access Private
router.get('/user/:userId', [auth, ...validateUserId], asyncHandler(async (req, res) => {
  // Authorization check
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
    logSecurityEvent('UNAUTHORIZED_PROGRESS_ACCESS', {
      requesterId: req.user.id,
      targetUserId: req.params.userId
    }, req);
    return errorResponse(res, 403, 'Not authorized to view this progress.');
  }

  try {
    const progress = await findProgressSecurely(req.params.userId, 'user');
    if (!progress) {
      return errorResponse(res, 404, 'Progress not found.');
    }

    res.json({
      success: true,
      data: progress,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// Real analytics implementation
const calculateRealAnalytics = async (progress, userId) => {
  try {
    // Get real data from database
    const [user, recentQuizzes, studyHistory] = await Promise.all([
      User.findById(userId).select('username email fullName createdAt').lean(),
      Quiz.find({ 'submissions.userId': userId })
        .populate('submissions')
        .sort({ 'submissions.submittedAt': -1 })
        .limit(50)
        .lean(),
      Promise.resolve([]) // Placeholder for study history
    ]);

    // Calculate analytics from real data
    const weeklyProgress = calculateWeeklyProgressReal(recentQuizzes, studyHistory);
    const subjectPerformance = calculateSubjectPerformanceReal(recentQuizzes);
    const streakAnalysis = calculateStreakAnalysisReal(progress, recentQuizzes);
    const studyPatterns = calculateStudyPatternsReal(recentQuizzes, studyHistory);
    const improvements = generateImprovementSuggestionsReal(progress, subjectPerformance);

    return {
      user,
      overview: {
        totalStudyTime: progress.totalStudyTime || 0,
        averageScore: progress.averageScore || 0,
        quizzesTaken: progress.quizzesTaken || 0,
        currentStreak: progress.streak?.currentStreak || 0,
        longestStreak: progress.streak?.longestStreak || 0,
        totalQuestions: recentQuizzes.reduce((sum, quiz) => sum + (quiz.questions?.length || 0), 0),
        accuracyRate: calculateOverallAccuracy(recentQuizzes, userId)
      },
      weeklyProgress,
      subjectPerformance,
      streakAnalysis,
      studyPatterns,
      improvements
    };
  } catch (error) {
    console.error('Analytics calculation error:', error);
    throw error;
  }
};

// Real weekly progress calculation
function calculateWeeklyProgressReal(recentQuizzes, studyHistory) {
  const weekData = {};
  const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

  // Initialize week data
  daysOfWeek.forEach(day => {
    weekData[day] = { studyTime: 0, quizzes: 0, scores: [] };
  });

  // Process quiz data
  recentQuizzes.forEach(quiz => {
    if (quiz.submissions) {
      quiz.submissions.forEach(submission => {
        const submissionDate = new Date(submission.submittedAt);
        const dayName = submissionDate.toLocaleDateString('en-US', { weekday: 'long' });
        if (weekData[dayName]) {
          weekData[dayName].quizzes++;
          weekData[dayName].scores.push(submission.score || 0);
          weekData[dayName].studyTime += submission.timeSpent || 0;
        }
      });
    }
  });

  // Convert to array format
  return daysOfWeek.map(day => ({
    day: day.substring(0, 3),
    studyTime: Math.round(weekData[day].studyTime / 60),
    quizzes: weekData[day].quizzes,
    averageScore: weekData[day].scores.length > 0
      ? Math.round(weekData[day].scores.reduce((a, b) => a + b, 0) / weekData[day].scores.length)
      : 0
  }));
}

// Real subject performance calculation
function calculateSubjectPerformanceReal(recentQuizzes) {
  const subjectData = {};

  recentQuizzes.forEach(quiz => {
    const subject = quiz.category?.name || 'General';
    if (!subjectData[subject]) {
      subjectData[subject] = {
        scores: [],
        questionsAttempted: 0,
        timeSpent: 0,
        quizCount: 0
      };
    }

    if (quiz.submissions) {
      quiz.submissions.forEach(submission => {
        subjectData[subject].scores.push(submission.score || 0);
        subjectData[subject].questionsAttempted += quiz.questions?.length || 0;
        subjectData[subject].timeSpent += submission.timeSpent || 0;
        subjectData[subject].quizCount++;
      });
    }
  });

  return Object.keys(subjectData).map(subject => ({
    subject,
    averageScore: subjectData[subject].scores.length > 0
      ? Math.round(subjectData[subject].scores.reduce((a, b) => a + b, 0) / subjectData[subject].scores.length)
      : 0,
    questionsAttempted: subjectData[subject].questionsAttempted,
    accuracy: subjectData[subject].scores.length > 0
      ? Math.round((subjectData[subject].scores.filter(score => score >= 60).length / subjectData[subject].scores.length) * 100)
      : 0,
    timeSpent: Math.round(subjectData[subject].timeSpent / 60),
    quizCount: subjectData[subject].quizCount
  }));
}

// Real streak analysis
function calculateStreakAnalysisReal(progress, recentQuizzes) {
  const streakData = progress.streak || {};
  const recentActivity = recentQuizzes.map(quiz =>
    quiz.submissions?.map(sub => new Date(sub.submittedAt)) || []
  ).flat().sort((a, b) => b - a);

  return {
    currentStreak: streakData.currentStreak || 0,
    longestStreak: streakData.longestStreak || 0,
    streakGoal: 30,
    lastActivity: recentActivity[0] || null,
    streakHistory: calculateStreakHistory(recentActivity),
    daysActive: new Set(recentActivity.map(date =>
      date.toISOString().split('T')[0]
    )).size
  };
}

// Helper function to calculate streak history
function calculateStreakHistory(activityDates) {
  const history = [];
  const uniqueDays = [...new Set(activityDates.map(date =>
    date.toISOString().split('T')[0]
  ))].sort();

  let currentStreak = 0;
  for (let i = 0; i < uniqueDays.length; i++) {
    const currentDate = new Date(uniqueDays[i]);
    const prevDate = i > 0 ? new Date(uniqueDays[i - 1]) : null;

    if (!prevDate || (currentDate - prevDate) / (1000 * 60 * 60 * 24) === 1) {
      currentStreak++;
    } else {
      if (currentStreak > 0) {
        history.push({ streak: currentStreak, endDate: prevDate });
      }
      currentStreak = 1;
    }
  }

  if (currentStreak > 0) {
    history.push({ streak: currentStreak, endDate: new Date(uniqueDays[uniqueDays.length - 1]) });
  }

  return history.slice(-10);
}

// Real study patterns calculation
function calculateStudyPatternsReal(recentQuizzes, studyHistory) {
  const hourCounts = new Array(24).fill(0);
  const dayCounts = {};
  let totalSessions = 0;
  let totalTime = 0;

  recentQuizzes.forEach(quiz => {
    if (quiz.submissions) {
      quiz.submissions.forEach(submission => {
        const date = new Date(submission.submittedAt);
        const hour = date.getHours();
        const dayName = date.toLocaleDateString('en-US', { weekday: 'long' });
        
        hourCounts[hour]++;
        dayCounts[dayName] = (dayCounts[dayName] || 0) + 1;
        totalSessions++;
        totalTime += submission.timeSpent || 0;
      });
    }
  });

  const preferredHour = hourCounts.indexOf(Math.max(...hourCounts));
  const mostActiveDay = Object.keys(dayCounts).reduce((a, b) =>
    dayCounts[a] > dayCounts[b] ? a : b, 'Sunday'
  );

  return {
    preferredStudyTime: getTimeOfDay(preferredHour),
    averageSessionLength: totalSessions > 0 ? Math.round((totalTime / totalSessions) / 60) : 0,
    mostActiveDay,
    consistency: calculateConsistency(recentQuizzes),
    hourlyDistribution: hourCounts,
    totalSessions
  };
}

// Helper functions
function getTimeOfDay(hour) {
  if (hour >= 6 && hour < 12) return 'Morning';
  if (hour >= 12 && hour < 17) return 'Afternoon';
  if (hour >= 17 && hour < 21) return 'Evening';
  return 'Night';
}

function calculateConsistency(recentQuizzes) {
  const uniqueDays = new Set();
  recentQuizzes.forEach(quiz => {
    if (quiz.submissions) {
      quiz.submissions.forEach(submission => {
        const date = new Date(submission.submittedAt);
        uniqueDays.add(date.toISOString().split('T')[0]);
      });
    }
  });

  const daysActive = uniqueDays.size;
  const totalDays = 30;
  return Math.round((daysActive / totalDays) * 100);
}

function calculateOverallAccuracy(recentQuizzes, userId) {
  let totalQuestions = 0;
  let correctAnswers = 0;

  recentQuizzes.forEach(quiz => {
    if (quiz.submissions) {
      quiz.submissions.forEach(submission => {
        totalQuestions += quiz.questions?.length || 0;
        const score = submission.score || 0;
        correctAnswers += Math.round((score / 100) * (quiz.questions?.length || 0));
      });
    }
  });

  return totalQuestions > 0 ? Math.round((correctAnswers / totalQuestions) * 100) : 0;
}

// Real improvement suggestions
function generateImprovementSuggestionsReal(progress, subjectPerformance) {
  const suggestions = [];

  // Analyze average score
  const avgScore = progress.averageScore || 0;
  if (avgScore < 70) {
    suggestions.push({
      type: 'performance',
      message: `Your average score is ${avgScore}%. Focus on practice tests to improve your performance.`,
      priority: 'high',
      actionItems: ['Take more practice quizzes', 'Review incorrect answers', 'Study weak topics']
    });
  }

  // Analyze streak
  const currentStreak = progress.streak?.currentStreak || 0;
  if (currentStreak < 7) {
    suggestions.push({
      type: 'consistency',
      message: 'Build a strong study habit by studying daily.',
      priority: 'medium',
      actionItems: ['Set a daily study reminder', 'Start with 15-minute sessions', 'Track your progress']
    });
  }

  // Analyze study time
  const totalStudyTime = progress.totalStudyTime || 0;
  if (totalStudyTime < 600) {
    suggestions.push({
      type: 'time',
      message: 'Increase your study time to improve your preparation.',
      priority: 'medium',
      actionItems: ['Set aside 30 minutes daily', 'Use study timers', 'Create a study schedule']
    });
  }

  // Analyze subject performance
  const weakSubjects = subjectPerformance
    .filter(subject => subject.averageScore < 60)
    .sort((a, b) => a.averageScore - b.averageScore)
    .slice(0, 2);

  weakSubjects.forEach(subject => {
    suggestions.push({
      type: 'subject',
      message: `Focus on improving ${subject.subject} - current average: ${subject.averageScore}%`,
      priority: 'high',
      actionItems: [
        `Review ${subject.subject} fundamentals`,
        `Practice more ${subject.subject} questions`,
        `Seek additional resources for ${subject.subject}`
      ]
    });
  });

  return suggestions;
}

// @route GET /progress/analytics/:userId
// @desc Get analytics for a user
// @access Private
router.get('/analytics/:userId', [auth, ...validateUserId], asyncHandler(async (req, res) => {
  // Authorization check
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
    logSecurityEvent('UNAUTHORIZED_ANALYTICS_ACCESS', {
      requesterId: req.user.id,
      targetUserId: req.params.userId
    }, req);
    return errorResponse(res, 403, 'Not authorized to view this analytics.');
  }

  try {
    const progress = await findProgressSecurely(req.params.userId, 'user');
    if (!progress) {
      return errorResponse(res, 404, 'Progress not found.');
    }

    // Use real analytics instead of mock data
    const analytics = await calculateRealAnalytics(progress, req.params.userId);

    logSecurityEvent('ANALYTICS_ACCESSED', {
      userId: req.params.userId,
      accessedBy: req.user.id
    }, req);

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
// @desc Update progress for a user
// @access Private
router.post('/update/:userId', [auth, ...validateProgressUpdate], asyncHandler(async (req, res) => {
  // Authorization check
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
    logSecurityEvent('UNAUTHORIZED_PROGRESS_UPDATE', {
      requesterId: req.user.id,
      targetUserId: req.params.userId
    }, req);
    return errorResponse(res, 403, 'Not authorized to update this progress.');
  }

  try {
    const updateData = { ...req.body, lastActivity: new Date() };
    const progress = await Progress.findOneAndUpdate(
      { user: req.params.userId },
      { $set: updateData },
      { new: true, upsert: true, runValidators: true }
    ).populate('user', 'username email fullName').lean();

    logSecurityEvent('PROGRESS_UPDATED', {
      userId: req.params.userId,
      updatedBy: req.user.id,
      fields: Object.keys(updateData)
    }, req);

    res.json({
      success: true,
      data: progress,
      message: 'Progress updated successfully.',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

module.exports = router;