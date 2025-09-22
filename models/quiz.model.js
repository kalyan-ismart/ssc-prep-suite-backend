// models/quiz.model.js - Quiz Model

const mongoose = require('mongoose');

const optionSchema = new mongoose.Schema({
  text: {
    type: String,
    required: true,
    trim: true
  },
  isCorrect: {
    type: Boolean,
    required: true,
    default: false
  }
}, { _id: false });

const questionSchema = new mongoose.Schema({
  questionText: {
    type: String,
    required: true,
    trim: true
  },
  options: [optionSchema],
  explanation: {
    type: String,
    trim: true
  },
  difficulty: {
    type: String,
    enum: ['easy', 'medium', 'hard'],
    default: 'medium'
  },
  tags: [String]
}, { _id: true });

const quizSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  
  description: {
    type: String,
    trim: true,
    maxlength: 1000
  },
  
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Category',
    required: true
  },
  
  questions: [questionSchema],
  
  difficulty: {
    type: String,
    enum: ['easy', 'medium', 'hard'],
    default: 'medium'
  },
  
  timeLimit: {
    type: Number, // in minutes
    default: 30,
    min: 1,
    max: 300
  },
  
  passingScore: {
    type: Number, // percentage
    default: 60,
    min: 0,
    max: 100
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  tags: [String],
  
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  instructions: {
    type: String,
    trim: true
  },
  
  attempts: {
    type: Number,
    default: 0
  },
  
  averageScore: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  }
  
}, {
  timestamps: true
});

// Indexes
quizSchema.index({ category: 1 });
quizSchema.index({ difficulty: 1 });
quizSchema.index({ isActive: 1 });
quizSchema.index({ createdBy: 1 });
quizSchema.index({ createdAt: -1 });

// Virtual for total questions
quizSchema.virtual('totalQuestions').get(function() {
  return this.questions.length;
});

// Method to get correct answers count
quizSchema.methods.getCorrectAnswersCount = function() {
  return this.questions.reduce((count, question) => {
    return count + question.options.filter(option => option.isCorrect).length;
  }, 0);
};

module.exports = mongoose.model('Quiz', quizSchema);