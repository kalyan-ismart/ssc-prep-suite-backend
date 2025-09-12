const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Module Schema for SarkariSuccess-Hub
 * Each module is linked to a user.
 */
const moduleSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  description: {
    type: String,
    required: true,
    trim: true,
    minlength: 5,
    maxlength: 500
  },
  duration: {
    type: Number,
    required: true,
    min: 1,
    max: 1440 // minutes
  },
  date: {
    type: Date,
    required: true
  }
}, {
  timestamps: true,
});

// Compound index for user/date queries
moduleSchema.index({ user: 1, date: -1 });

module.exports = mongoose.model('Module', moduleSchema);
