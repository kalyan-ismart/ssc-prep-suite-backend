// models/tool.model.js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Tool Schema for SarkariSuccess-Hub
 * Supports categories, types, tags, usage tracking.
 */
const toolSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
    unique: true, // Implicitly creates an index
  },
  description: {
    type: String,
    required: true,
    maxlength: 500,
  },
  category: {
    type: Schema.Types.ObjectId,
    ref: 'Category',
    required: true,
    index: true, // Field-level index
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
      'interactive',
    ],
    required: true,
    index: true, // Field-level index
  },
  icon: {
    type: String,
    default: '🔧',
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true, // Field-level index
  },
  settings: {
    type: Schema.Types.Mixed,
    default: {},
  },
  tags: [
    {
      type: String,
      maxlength: 30,
      index: true, // Field-level index
    },
  ],
  usageCount: {
    type: Number,
    default: 0,
  },
  rating: {
    type: Number,
    min: 0,
    max: 5,
    default: 0,
  },
}, {
  timestamps: true,
});

// No explicit schema.index() calls needed, as indexes are defined at the field level
module.exports = mongoose.model('Tool', toolSchema);