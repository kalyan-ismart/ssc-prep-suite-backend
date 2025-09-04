const router = require('express').Router();

/**
 * GET /goals
 * Placeholder endpoint for goals.
 */
router.get('/', (req, res) => {
  res.json({ success: true, message: 'Goals endpoint placeholder.' });
});

module.exports = router;