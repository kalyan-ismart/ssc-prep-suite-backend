// models/category.model.js - Category Model

const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    maxlength: 100
  },
  
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  
  icon: {
    type: String,
    trim: true
  },
  
  color: {
    type: String,
    trim: true,
    match: /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  order: {
    type: Number,
    default: 0
  },
  
  parentCategory: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Category',
    default: null
  }
  
}, {
  timestamps: true
});

// Indexes
categorySchema.index({ name: 1 });
categorySchema.index({ isActive: 1 });
categorySchema.index({ order: 1 });

module.exports = mongoose.model('Category', categorySchema);