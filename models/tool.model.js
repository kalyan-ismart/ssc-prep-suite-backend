// models/tool.model.js - Tool Model

const mongoose = require('mongoose');

const toolSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  
  description: {
    type: String,
    required: true,
    trim: true,
    maxlength: 500
  },
  
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Category',
    required: true
  },
  
  toolType: {
    type: String,
    required: true,
    enum: [
      'analytics', 'quiz', 'planner', 'calculator', 
      'tracker', 'ai-assistant', 'simulator', 
      'database', 'practice', 'assessment', 
      'utility', 'interactive'
    ]
  },
  
  icon: {
    type: String,
    trim: true
  },
  
  url: {
    type: String,
    trim: true
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  settings: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  
  tags: [String],
  
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  usageCount: {
    type: Number,
    default: 0
  },
  
  rating: {
    type: Number,
    default: 0,
    min: 0,
    max: 5
  }
  
}, {
  timestamps: true
});

// Indexes
toolSchema.index({ category: 1 });
toolSchema.index({ toolType: 1 });
toolSchema.index({ isActive: 1 });
toolSchema.index({ createdBy: 1 });

module.exports = mongoose.model('Tool', toolSchema);