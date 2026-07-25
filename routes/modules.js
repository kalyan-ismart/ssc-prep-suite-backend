const router = require('express').Router();
const mongoose = require('mongoose');
let Module = require('../models/module.model');

// Helper: Check if MongoDB is connected
function requireDB(res) {
  if (mongoose.connection.readyState !== 1) {
    res.status(503).json({ error: 'Database connection offline. Please try again shortly.' });
    return false;
  }
  return true;
}

// Helper: Validate MongoDB ObjectId
function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id) && String(new mongoose.Types.ObjectId(id)) === id;
}

// Gets all modules
router.route('/').get(async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }
    const modules = await Module.find().sort({ date: -1 }).lean();
    res.json(modules);
  } catch (err) {
    console.error('Error fetching modules:', err.message);
    res.status(500).json({ error: 'Failed to fetch modules: ' + err.message });
  }
});

// Adds a new module
router.route('/add').post(async (req, res) => {
  try {
    if (!requireDB(res)) return;

    const { username, description, duration, date } = req.body;

    // Input validation
    if (!username || !String(username).trim()) {
      return res.status(400).json({ error: 'Username is required' });
    }
    if (!description || !String(description).trim()) {
      return res.status(400).json({ error: 'Description is required' });
    }
    if (duration === undefined || duration === null || isNaN(Number(duration)) || Number(duration) < 0) {
      return res.status(400).json({ error: 'Duration must be a valid positive number' });
    }
    if (!date || isNaN(new Date(date).getTime())) {
      return res.status(400).json({ error: 'A valid date is required' });
    }

    const newModule = new Module({
      username: String(username).trim(),
      description: String(description).trim(),
      duration: Number(duration),
      date: new Date(date),
    });

    await newModule.save();
    res.json('Module added!');
  } catch (err) {
    console.error('Error adding module:', err.message);
    res.status(400).json({ error: 'Failed to add module: ' + err.message });
  }
});

// Gets a single module by its id
router.route('/:id').get(async (req, res) => {
  try {
    if (!requireDB(res)) return;

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid module ID format' });
    }

    const module = await Module.findById(req.params.id).lean();
    if (!module) return res.status(404).json({ error: 'Module not found' });
    res.json(module);
  } catch (err) {
    console.error('Error fetching module:', err.message);
    res.status(500).json({ error: 'Failed to fetch module: ' + err.message });
  }
});

// Deletes a single module by its id
router.route('/:id').delete(async (req, res) => {
  try {
    if (!requireDB(res)) return;

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid module ID format' });
    }

    const module = await Module.findByIdAndDelete(req.params.id);
    if (!module) return res.status(404).json({ error: 'Module not found' });
    res.json('Module deleted.');
  } catch (err) {
    console.error('Error deleting module:', err.message);
    res.status(500).json({ error: 'Failed to delete module: ' + err.message });
  }
});

// Updates a single module by its id
router.route('/update/:id').post(async (req, res) => {
  try {
    if (!requireDB(res)) return;

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid module ID format' });
    }

    const module = await Module.findById(req.params.id);
    if (!module) return res.status(404).json({ error: 'Module not found' });

    const { username, description, duration, date } = req.body;

    // Input validation
    if (!username || !String(username).trim()) {
      return res.status(400).json({ error: 'Username is required' });
    }
    if (!description || !String(description).trim()) {
      return res.status(400).json({ error: 'Description is required' });
    }

    module.username = String(username).trim();
    module.description = String(description).trim();
    module.duration = Number(duration) || 0;
    module.date = date ? new Date(date) : new Date();

    await module.save();
    res.json('Module updated!');
  } catch (err) {
    console.error('Error updating module:', err.message);
    res.status(400).json({ error: 'Failed to update module: ' + err.message });
  }
});

module.exports = router;