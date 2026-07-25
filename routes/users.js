const router = require('express').Router();
const mongoose = require('mongoose');
let User = require('../models/user.model');

// Gets all users
router.route('/').get(async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }
    const users = await User.find().sort({ username: 1 }).lean();
    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err.message);
    res.status(500).json({ error: 'Failed to fetch users: ' + err.message });
  }
});

// Adds a new user
router.route('/add').post(async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database connection offline. Please try again shortly.' });
    }

    const username = req.body.username ? String(req.body.username).trim() : '';

    // Input validation
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }
    if (username.length > 50) {
      return res.status(400).json({ error: 'Username must be 50 characters or less' });
    }

    // Check for duplicate username before saving
    const existing = await User.findOne({ username: username });
    if (existing) {
      return res.status(409).json({ error: `Username '${username}' already exists. Please choose a different one.` });
    }

    const newUser = new User({ username });
    await newUser.save();
    res.json('User added!');
  } catch (err) {
    console.error('Error adding user:', err.message);

    // Handle MongoDB duplicate key error (race condition)
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Username already exists. Please choose a different one.' });
    }

    res.status(400).json({ error: 'Failed to add user: ' + err.message });
  }
});

module.exports = router;