// models/category.model.js

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Category Schema for SarkariSuccess-Hub
 * Defines the six main categories with icons, colors, and ordering.
 */
const categorySchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    unique: true,
    maxlength: 50
  },
  description: {
    type: String,
    required: true,
    maxlength: 200
  },
  icon: {
    type: String,
    required: true,
    default: '📋'
  },
  color: {
    type: String,
    required: true,
    match: /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/,
    default: '#3B82F6'
  },
  order: {
    type: Number,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Indexes for performance
categorySchema.index({ name: 1 });
categorySchema.index({ order: 1 });
categorySchema.index({ isActive: 1 });

module.exports = mongoose.model('Category', categorySchema);
