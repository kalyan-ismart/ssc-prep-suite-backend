// models/category.model.js

const mongoose = require('mongoose');
const { Schema } = mongoose;

const categorySchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    unique: true,
    maxlength: 50,
    collation: { locale: 'en', strength: 2 }
  },
  description: {
    type: String,
    required: true,
    maxlength: 200
  },
  icon: {
    type: String,
    required: true,
    default: '📋',
    validate: {
      validator: (value) => /^[\u{1F300}-\u{1F6FF}\u{2600}-\u{26FF}]+$/u.test(value),
      message: 'Invalid icon format. Must be a valid emoji.'
    }
  },
  color: {
    type: String,
    required: true,
    default: '#3B82F6',
    match: [/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/, 'Invalid hex color format.']
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
categorySchema.index({ order: 1 });
categorySchema.index({ isActive: 1 });

module.exports = mongoose.model('Category', categorySchema);
