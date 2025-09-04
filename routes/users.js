const router = require('express').Router();
const bcrypt = require('bcryptjs');
const { body, validationResult, query, param } = require('express-validator');
const User = require('../models/user.model');

/** Utility: Standard error response */
function errorResponse(res, status, message, errors = []) {
  return res.status(status).json({
    success: false,
    message,
    errors
  });
}

/** GET /users - List users with pagination */
router.get('/', [
  query('search').optional().isString().isLength({ max: 100 }),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 })
], async (req, res) => {
  try {
    const search = req.query.search;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    let findQuery = {};
    if (search) {
      findQuery = {
        $or: [
          { username: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { fullName: { $regex: search, $options: 'i' } }
        ]
      };
    }
    const users = await User.find(findQuery, '-password')
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();
    const total = await User.countDocuments(findQuery);
    res.json({ success: true, data: users, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    errorResponse(res, 500, 'Failed to fetch users.', [err.message]);
  }
});

/** POST /users/add - Add user with advanced validation */
router.post('/add', [
  body('username')
    .isString().trim().isLength({ min: 3, max: 32 })
    .withMessage('Username must be 3-32 characters.')
    .matches(/^[a-zA-Z0-9_\-.]+$/).withMessage('Username contains invalid characters.'),
  body('email')
    .isEmail().normalizeEmail().withMessage('Valid email required.'),
  body('password')
    .isString().isLength({ min: 6 }).withMessage('Password must be at least 6 characters.'),
  body('fullName')
    .optional().isString().trim().isLength({ max: 100 }).withMessage('Full name max 100 chars.'),
  body('phone')
    .optional().isString().trim().isLength({ max: 20 }).withMessage('Phone max 20 chars.'),
  body('profilePic')
    .optional().isString().trim(),
  body('role')
    .optional().isIn(['user', 'admin']).withMessage('Role must be user or admin.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());

  const { username, email, password, fullName, phone, profilePic, role } = req.body;
  try {
    const existingUser = await User.findOne({
      $or: [{ username }, { email }]
    }).lean();
    if (existingUser) {
      return errorResponse(res, 409, 'Username or email already exists.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      fullName,
      phone,
      profilePic,
      role
    });

    await newUser.save();
    const { password: pw, ...userWithoutPassword } = newUser.toObject();
    res.status(201).json({ success: true, user: userWithoutPassword, message: 'User added!' });
  } catch (err) {
    errorResponse(res, 500, 'Failed to add user.', [err.message]);
  }
});

/** POST /users/update/:id - Update user with duplicate check */
router.post('/update/:id', [
  param('id').custom((value) => value && value.length === 24).withMessage('Invalid user ID.'),
  body('username')
    .optional().isString().trim().isLength({ min: 3, max: 32 })
    .matches(/^[a-zA-Z0-9_\-.]+$/).withMessage('Username contains invalid characters.'),
  body('email')
    .optional().isEmail().normalizeEmail().withMessage('Valid email required.'),
  body('password')
    .optional().isString().isLength({ min: 6 }).withMessage('Password must be at least 6 characters.'),
  body('fullName')
    .optional().isString().trim().isLength({ max: 100 }).withMessage('Full name max 100 chars.'),
  body('phone')
    .optional().isString().trim().isLength({ max: 20 }).withMessage('Phone max 20 chars.'),
  body('profilePic')
    .optional().isString().trim(),
  body('role')
    .optional().isIn(['user', 'admin']).withMessage('Role must be user or admin.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed.', errors.array());
  try {
    const user = await User.findById(req.params.id);
    if (!user) return errorResponse(res, 404, 'User not found.');

    // Prevent duplicate email/username
    if (req.body.username && req.body.username !== user.username) {
      const exists = await User.findOne({ username: req.body.username, _id: { $ne: user._id } });
      if (exists) return errorResponse(res, 409, 'Username already exists.');
      user.username = req.body.username;
    }
    if (req.body.email && req.body.email !== user.email) {
      const exists = await User.findOne({ email: req.body.email, _id: { $ne: user._id } });
      if (exists) return errorResponse(res, 409, 'Email already exists.');
      user.email = req.body.email;
    }
    if (req.body.password) user.password = await bcrypt.hash(req.body.password, 10);
    if (req.body.fullName) user.fullName = req.body.fullName;
    if (req.body.phone) user.phone = req.body.phone;
    if (req.body.profilePic) user.profilePic = req.body.profilePic;
    if (req.body.role) user.role = req.body.role;
    await user.save();
    const { password: pw, ...userWithoutPassword } = user.toObject();
    res.json({ success: true, message: 'User updated!', user: userWithoutPassword });
  } catch (err) {
    errorResponse(res, 500, 'Failed to update user.', [err.message]);
  }
});

module.exports = router;