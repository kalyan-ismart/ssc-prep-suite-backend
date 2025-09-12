// models/examSchedule.model.js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * ExamSchedule Schema for SarkariSuccess-Hub
 * Represents an exam schedule with title, date, and metadata.
 */
const examScheduleSchema = new Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    minlength: 1,
    maxlength: 100,
  },
  date: {
    type: Date,
    required: true,
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500,
  },
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
  isActive: {
    type: Boolean,
    default: true,
  },
}, {
  timestamps: true,
});

// Indexes for performance
examScheduleSchema.index({ date: 1 });
examScheduleSchema.index({ category: 1 });
examScheduleSchema.index({ createdBy: 1 });
examScheduleSchema.index({ title: 1 });

module.exports = mongoose.model('ExamSchedule', examScheduleSchema);