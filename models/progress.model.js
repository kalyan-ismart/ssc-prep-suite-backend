// models/progress.model.js

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Progress Schema for SarkariSuccess-Hub
 * Tracks user progress across categories and tool usage, including streaks, scores, and goals.
 */
const progressSchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  categoryProgress: [
    {
      category: {
        type: Schema.Types.ObjectId,
        ref: 'Category'
      },
      completedTools: {
        type: Number,
        default: 0
      },
      totalTools: {
        type: Number,
        default: 8
      },
      timeSpent: {
        type: Number,
        default: 0
      },
      averageScore: {
        type: Number,
        default: 0
      },
      lastAccessed: {
        type: Date,
        default: Date.now
      }
    }
  ],
  toolUsage: [
    {
      tool: {
        type: Schema.Types.ObjectId,
        ref: 'Tool'
      },
      usageCount: {
        type: Number,
        default: 0
      },
      timeSpent: {
        type: Number,
        default: 0
      },
      scores: [
        {
          score: Number,
          maxScore: Number,
          date: {
            type: Date,
            default: Date.now
          }
        }
      ],
      lastUsed: {
        type: Date,
        default: Date.now
      }
    }
  ],
  streak: {
    current: {
      type: Number,
      default: 0
    },
    longest: {
      type: Number,
      default: 0
    },
    lastActive: {
      type: Date,
      default: Date.now
    }
  },
  totalStudyTime: {
    type: Number,
    default: 0
  },
  averageScore: {
    type: Number,
    default: 0
  },
  goalsCompleted: {
    type: Number,
    default: 0
  },
  totalGoals: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Progress', progressSchema);
