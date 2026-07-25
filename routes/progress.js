const router = require('express').Router();

router.route('/').get((req, res) => {
  try {
    res.json({ message: 'Progress tracking route is active.' });
  } catch (err) {
    console.error('Error in progress route:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
