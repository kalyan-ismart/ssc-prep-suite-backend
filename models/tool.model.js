// models/tool.model.js

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Tool Schema for SarkariSuccess-Hub
 * Supports categories, tool types, tags, usage tracking, and ratings.
 */
const toolSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    required: true,
    maxlength: 500
  },
  category: {
    type: Schema.Types.ObjectId,
    ref: 'Category',
    required: true
  },
  toolType: {
    type: String,
    enum: [
      'analytics',
      'quiz',
      'planner',
      'calculator',
      'tracker',
      'ai-assistant',
      'simulator',
      'database',
      'practice',
      'assessment',
      'utility',
      'interactive'
    ],
    required: true
  },
  icon: {
    type: String,
    default: '🔧'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  settings: {
    type: Schema.Types.Mixed,
    default: {}
  },
  tags: [
    {
      type: String,
      maxlength: 30
    }
  ],
  usageCount: {
    type: Number,
    default: 0
  },
  rating: {
    type: Number,
    min: 0,
    max: 5,
    default: 0
  }
}, {
  timestamps: true
});

// Indexes for performance
toolSchema.index({ name: 1 });
toolSchema.index({ category: 1 });
toolSchema.index({ toolType: 1 });
toolSchema.index({ isActive: 1 });
toolSchema.index({ tags: 1 });

module.exports = mongoose.model('Tool', toolSchema);
