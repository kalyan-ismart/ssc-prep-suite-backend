const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const moduleSchema = new Schema({
  username: { type: String, required: true },
  description: { type: String, required: true },
  duration: { type: Number, required: true },
  date: { type: Date, required: true },
}, {
  timestamps: true,
});

const Module = mongoose.model('Module', moduleSchema);

module.exports = Module;