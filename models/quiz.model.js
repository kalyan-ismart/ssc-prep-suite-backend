// models/quiz.model.js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Quiz Schema for SarkariSuccess-Hub
 * Represents a quiz with questions, category, and metadata.
 */
const quizSchema = new Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    minlength: 1,
    maxlength: 100,
  },
  questions: [
    {
      questionText: {
        type: String,
        required: true,
        trim: true,
      },
      options: [
        {
          text: { type: String, required: true, trim: true },
          isCorrect: { type: Boolean, required: true },
        },
      ],
      explanation: {
        type: String,
        trim: true,
        maxlength: 500,
      },
    },
  ],
  category: {
    type: Schema.Types.ObjectId,
    ref: 'Category',
    required: true,
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  difficulty: {
    type: String,
    enum: ['easy', 'medium', 'hard'],
    default: 'medium',
  },
  isActive: {
    type: Boolean,
    default: true,
  },
}, {
  timestamps: true,
});

// Indexes for performance
quizSchema.index({ category: 1 });
quizSchema.index({ createdBy: 1 });
quizSchema.index({ title: 1 });

module.exports = mongoose.model('Quiz', quizSchema);