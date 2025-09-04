const router = require('express').Router();

router.get('/', (req, res) => {
  res.json({ success: true, message: 'Quizzes endpoint placeholder.' });
});

module.exports = router;