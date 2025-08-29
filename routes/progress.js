const router = require('express').Router();

router.route('/').get((req, res) => {
  res.json('This is the progress route!');
});

module.exports = router;
