// models/progress.model.js - Progress Tracking Model

const mongoose = require('mongoose');

const progressSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  
  totalStudyTime: {
    type: Number, // in minutes
    default: 0,
    min: 0
  },
  
  averageScore: {
    type: Number, // percentage (0-100)
    default: 0,
    min: 0,
    max: 100
  },
  
  quizzesTaken: {
    type: Number,
    default: 0,
    min: 0
  },
  
  questionsAnswered: {
    type: Number,
    default: 0,
    min: 0
  },
  
  correctAnswers: {
    type: Number,
    default: 0,
    min: 0
  },
  
  streak: {
    currentStreak: {
      type: Number,
      default: 0,
      min: 0
    },
    longestStreak: {
      type: Number,
      default: 0,
      min: 0
    },
    lastStudyDate: {
      type: Date,
      default: null
    }
  },
  
  subjectProgress: [{
    subject: {
      type: String,
      required: true
    },
    totalQuestions: {
      type: Number,
      default: 0
    },
    correctAnswers: {
      type: Number,
      default: 0
    },
    averageScore: {
      type: Number,
      default: 0
    },
    timeSpent: {
      type: Number, // in minutes
      default: 0
    },
    lastAttempted: {
      type: Date,
      default: null
    }
  }],
  
  weeklyGoals: {
    studyTime: {
      type: Number, // in minutes
      default: 420 // 7 hours per week
    },
    quizzes: {
      type: Number,
      default: 10
    }
  },
  
  achievements: [{
    name: {
      type: String,
      required: true
    },
    description: {
      type: String,
      required: true
    },
    unlockedAt: {
      type: Date,
      default: Date.now
    },
    category: {
      type: String,
      enum: ['streak', 'score', 'time', 'quiz', 'special'],
      required: true
    }
  }],
  
  lastActivity: {
    type: Date,
    default: Date.now
  }
  
}, {
  timestamps: true
});

// Indexes
progressSchema.index({ user: 1 });
progressSchema.index({ lastActivity: -1 });
progressSchema.index({ 'streak.currentStreak': -1 });

// Virtual for accuracy rate
progressSchema.virtual('accuracyRate').get(function() {
  if (this.questionsAnswered === 0) return 0;
  return Math.round((this.correctAnswers / this.questionsAnswered) * 100);
});

// Method to update study time
progressSchema.methods.addStudyTime = function(minutes) {
  this.totalStudyTime += minutes;
  this.lastActivity = new Date();
  return this.save();
};

// Method to update quiz stats
progressSchema.methods.addQuizResult = function(score, questionsCount, correctCount, timeSpent) {
  this.quizzesTaken += 1;
  this.questionsAnswered += questionsCount;
  this.correctAnswers += correctCount;
  
  // Recalculate average score
  this.averageScore = Math.round(
    ((this.averageScore * (this.quizzesTaken - 1)) + score) / this.quizzesTaken
  );
  
  if (timeSpent) {
    this.totalStudyTime += timeSpent;
  }
  
  this.lastActivity = new Date();
  return this.save();
};

// Method to update streak
progressSchema.methods.updateStreak = function() {
  const today = new Date();
  const lastStudyDate = this.streak.lastStudyDate;
  
  if (!lastStudyDate) {
    // First study session
    this.streak.currentStreak = 1;
    this.streak.longestStreak = 1;
  } else {
    const diffTime = Math.abs(today - lastStudyDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) {
      // Consecutive day
      this.streak.currentStreak += 1;
      if (this.streak.currentStreak > this.streak.longestStreak) {
        this.streak.longestStreak = this.streak.currentStreak;
      }
    } else if (diffDays > 1) {
      // Streak broken
      this.streak.currentStreak = 1;
    }
    // If same day, don't update streak count
  }
  
  this.streak.lastStudyDate = today;
  return this.save();
};

module.exports = mongoose.model('Progress', progressSchema);