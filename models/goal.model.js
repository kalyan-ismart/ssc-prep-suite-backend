// models/goal.model.js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Goal Schema for SarkariSuccess-Hub
 * Represents user goals for exam preparation (e.g., study hours, quiz completion).
 */
const goalSchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
    required: true,
    trim: true,
    minlength: 1,
    maxlength: 100,
  },
  target: {
    type: Number,
    required: true,
    min: 1, // e.g., target study hours or number of quizzes
  },
  completed: {
    type: Boolean,
    default: false,
  },
  category: {
    type: Schema.Types.ObjectId,
    ref: 'Category',
    required: true,
  },
  deadline: {
    type: Date,
    required: true,
  },
  progress: {
    type: Number,
    default: 0,
    min: 0, // Tracks progress toward target (e.g., hours studied)
  },
  isActive: {
    type: Boolean,
    default: true,
  },
}, {
  timestamps: true,
});

// Indexes for performance
goalSchema.index({ user: 1 });
goalSchema.index({ category: 1 });
goalSchema.index({ title: 1 });
goalSchema.index({ deadline: 1 });

module.exports = mongoose.model('Goal', goalSchema);