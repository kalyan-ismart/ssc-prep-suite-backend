const mongoose = require('mongoose');

const Schema = mongoose.Schema;

/**
 * Module Schema for SarkariSuccess-Hub
 * Each module is linked to a user by ObjectId.
 * Added compound index for user/date for faster queries by user/date.
 */
const moduleSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  description: { type: String, required: true, trim: true, minlength: 5, maxlength: 500 },
  duration: { type: Number, required: true, min: 1, max: 1440 }, // minutes, reasonable max
  date: { type: Date, required: true },
}, {
  timestamps: true,
});

// Compound index for user/date queries
moduleSchema.index({ user: 1, date: -1 });

const Module = mongoose.model('Module', moduleSchema);

module.exports = Module;