const router = require('express').Router();

/**
 * GET /exam-schedule
 * Placeholder endpoint for exam schedule.
 */
router.get('/', (req, res) => {
  res.json({ success: true, message: 'ExamSchedule endpoint placeholder.' });
});

module.exports = router;