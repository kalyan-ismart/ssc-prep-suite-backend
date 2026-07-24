const router = require('express').Router();
const mongoose = require('mongoose');
let Module = require('../models/module.model');

// Gets all modules
router.route('/').get((req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.json([]);
  }
  Module.find()
    .then(modules => res.json(modules))
    .catch(err => res.status(400).json('Error: ' + err));
});

// Adds a new module
router.route('/add').post((req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json('Error: Database connection offline. Please start MongoDB or provide ATLAS_URI.');
  }

  const username = req.body.username;
  const description = req.body.description;
  const duration = Number(req.body.duration);
  const date = new Date(req.body.date);

  const newModule = new Module({
    username,
    description,
    duration,
    date,
  });

  newModule.save()
    .then(() => res.json('Module added!'))
    .catch(err => res.status(400).json('Error: ' + err));
});

// Gets a single module by its id
router.route('/:id').get((req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json('Error: Database connection offline.');
  }

  Module.findById(req.params.id)
    .then(module => {
      if (!module) return res.status(404).json('Error: Module not found');
      res.json(module);
    })
    .catch(err => res.status(400).json('Error: ' + err));
});

// Deletes a single module by its id
router.route('/:id').delete((req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json('Error: Database connection offline.');
  }

  Module.findByIdAndDelete(req.params.id)
    .then(module => {
      if (!module) return res.status(404).json('Error: Module not found');
      res.json('Module deleted.');
    })
    .catch(err => res.status(400).json('Error: ' + err));
});

// Updates a single module by its id
router.route('/update/:id').post((req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json('Error: Database connection offline.');
  }

  Module.findById(req.params.id)
    .then(module => {
      if (!module) return res.status(404).json('Error: Module not found');

      module.username = req.body.username;
      module.description = req.body.description;
      module.duration = Number(req.body.duration);
      module.date = new Date(req.body.date);

      module.save()
        .then(() => res.json('Module updated!'))
        .catch(err => res.status(400).json('Error: ' + err));
    })
    .catch(err => res.status(400).json('Error: ' + err));
});

module.exports = router;