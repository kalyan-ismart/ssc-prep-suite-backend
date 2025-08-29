const router = require('express').Router();
let Module = require('../models/module.model');

// Gets all modules (already exists)
router.route('/').get((req, res) => {
  Module.find()
    .then(modules => res.json(modules))
    .catch(err => res.status(400).json('Error: ' + err));
});

// Adds a new module (already exists)
router.route('/add').post((req, res) => {
  const username = req.body.username;
  const description = req.body.description;
  const duration = Number(req.body.duration);
  const date = Date.parse(req.body.date);

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

// --- NEW CODE STARTS HERE ---

// Gets a single module by its id
router.route('/:id').get((req, res) => {
  Module.findById(req.params.id)
    .then(module => res.json(module))
    .catch(err => res.status(400).json('Error: ' + err));
});

// Deletes a single module by its id
router.route('/:id').delete((req, res) => {
  Module.findByIdAndDelete(req.params.id)
    .then(() => res.json('Module deleted.'))
    .catch(err => res.status(400).json('Error: ' + err));
});

// Updates a single module by its id
router.route('/update/:id').post((req, res) => {
  Module.findById(req.params.id)
    .then(module => {
      module.username = req.body.username;
      module.description = req.body.description;
      module.duration = Number(req.body.duration);
      module.date = Date.parse(req.body.date);

      module.save()
        .then(() => res.json('Module updated!'))
        .catch(err => res.status(400).json('Error: ' + err));
    })
    .catch(err => res.status(400).json('Error: ' + err));
});

// --- NEW CODE ENDS HERE ---

module.exports = router;