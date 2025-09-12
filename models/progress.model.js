// models/progress.model.js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Progress Schema for SarkariSuccess-Hub
 * Tracks user progress, including streaks, scores, goals.
 * This schema is well-defined and follows best practices. No fixes were needed.
 */
const progressSchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
  },
  categoryProgress: [
    {
      category: {
        type: Schema.Types.ObjectId,
        ref: 'Category',
        index: true,
      },
      completedTools: {
        type: Number,
        default: 0,
        min: 0,
      },
      totalTools: {
        type: Number,
        default: 8,
        min: 0,
      },
      timeSpent: {
        type: Number,
        default: 0,
        min: 0,
      },
      averageScore: {
        type: Number,
        default: 0,
        min: 0,
      },
      lastAccessed: {
        type: Date,
        default: Date.now,
      },
    },
  ],
  toolUsage: [
    {
      tool: {
        type: Schema.Types.ObjectId,
        ref: 'Tool',
        index: true,
      },
      usageCount: {
        type: Number,
        default: 0,
        min: 0,
      },
      timeSpent: {
        type: Number,
        default: 0,
        min: 0,
      },
      scores: [
        {
          score: {
            type: Number,
            min: 0,
          },
          maxScore: {
            type: Number,
            min: 0,
          },
          date: {
            type: Date,
            default: Date.now,
          },
        },
      ],
      lastUsed: {
        type: Date,
        default: Date.now,
      },
    },
  ],
  streak: {
    current: {
      type: Number,
      default: 0,
      min: 0,
    },
    longest: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastActive: {
      type: Date,
      default: Date.now,
    },
  },
  totalStudyTime: {
    type: Number,
    default: 0,
    min: 0,
  },
  averageScore: {
    type: Number,
    default: 0,
    min: 0,
  },
  goalsCompleted: {
    type: Number,
    default: 0,
    min: 0,
  },
  totalGoals: {
    type: Number,
    default: 0,
    min: 0,
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model('Progress', progressSchema);