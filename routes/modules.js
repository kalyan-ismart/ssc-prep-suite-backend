// routes/modules.js

const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const { body, validationResult } = require('express-validator');
const Module = require('../models/module.model');
const { errorResponse, handleDatabaseError, asyncHandler, logSecurityEvent } = require('../utils/errors');
const { auth, adminAuth, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// Enhanced validation middleware for create/update
const validateModule = [
  body('user')
    .isMongoId()
    .withMessage('Valid user ID is required'),
  body('description')
    .isString()
    .trim()
    .isLength({ min: 5, max: 500 })
    .withMessage('Description must be 5-500 characters')
    .customSanitizer((value) => validator.escape(value)),
  body('duration')
    .isInt({ min: 1, max: 1440 })
    .withMessage('Duration must be 1-1440 minutes'),
  body('date')
    .isISO8601()
    .toDate()
    .withMessage('Valid ISO date is required'),
];

const validateModuleQuery = [
  query('userId')
    .optional()
    .isMongoId()
    .withMessage('Valid user ID is required'),
  query('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Page must be between 1 and 1000'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
];

// GET all modules (optionally filter by user) with enhanced validation
router.get('/', [optionalAuth, ...validateModuleQuery], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const { userId } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const skip = (page - 1) * limit;

    const filter = userId ? { user: userId } : {};

    // Authorization check - users can only see their own modules unless admin
    if (req.user && req.user.role !== 'admin' && userId && req.user.id !== userId) {
      logSecurityEvent('UNAUTHORIZED_MODULE_ACCESS', { 
        requesterId: req.user.id, 
        targetUserId: userId 
      }, req);
      return errorResponse(res, 403, 'Access denied. You can only view your own modules.');
    }

    const [data, total] = await Promise.all([
      Module.find(filter)
        .populate('user', 'username fullName')
        .select('-__v')
        .skip(skip)
        .limit(limit)
        .sort({ date: 1 })
        .lean(),
      Module.countDocuments(filter)
    ]);

    const totalPages = Math.ceil(total / limit);

    res.json({ 
      success: true, 
      data,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// GET module by ID with enhanced security
router.get('/:id', [
  optionalAuth,
  param('id').isMongoId().withMessage('Valid module ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const module = await Module.findById(req.params.id)
      .populate('user', 'username fullName')
      .select('-__v')
      .lean();

    if (!module) {
      return errorResponse(res, 404, 'Module not found.');
    }

    // Authorization check - users can only see their own modules unless admin
    if (req.user && req.user.role !== 'admin' && req.user.id !== module.user._id.toString()) {
      logSecurityEvent('UNAUTHORIZED_MODULE_ACCESS', { 
        requesterId: req.user.id, 
        moduleId: req.params.id,
        moduleOwner: module.user._id 
      }, req);
      return errorResponse(res, 403, 'Access denied. You can only view your own modules.');
    }

    res.json({ success: true, data: module });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST add a module with authentication
router.post('/add', [auth, ...validateModule], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    // Users can only create modules for themselves unless admin
    if (req.user.role !== 'admin' && req.body.user !== req.user.id) {
      logSecurityEvent('UNAUTHORIZED_MODULE_CREATION', { 
        requesterId: req.user.id, 
        targetUserId: req.body.user 
      }, req);
      return errorResponse(res, 403, 'You can only create modules for yourself.');
    }

    const module = new Module(req.body);
    await module.save();

    const populatedModule = await Module.findById(module._id)
      .populate('user', 'username fullName')
      .select('-__v')
      .lean();

    logSecurityEvent('MODULE_CREATED', { 
      moduleId: module._id, 
      createdBy: req.user.id,
      targetUserId: req.body.user
    }, req);

    res.status(201).json({ 
      success: true, 
      message: 'Module added successfully.', 
      data: populatedModule 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// POST update module by ID with enhanced security
router.post('/update/:id', [
  auth,
  param('id').isMongoId().withMessage('Valid module ID is required'),
  ...validateModule.map(v => v.optional({ nullable: true })),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const module = await Module.findById(req.params.id);
    if (!module) {
      return errorResponse(res, 404, 'Module not found.');
    }

    // Authorization check - users can only update their own modules unless admin
    if (req.user.role !== 'admin' && req.user.id !== module.user.toString()) {
      logSecurityEvent('UNAUTHORIZED_MODULE_UPDATE', { 
        requesterId: req.user.id, 
        moduleId: req.params.id,
        moduleOwner: module.user 
      }, req);
      return errorResponse(res, 403, 'You can only update your own modules.');
    }

    // Prevent users from changing module ownership unless admin
    if (req.body.user && req.user.role !== 'admin' && req.body.user !== req.user.id) {
      delete req.body.user;
    }

    // Update fields if provided
    const updateData = {};
    if (req.body.user) updateData.user = req.body.user;
    if (req.body.description) updateData.description = req.body.description;
    if (req.body.duration) updateData.duration = req.body.duration;
    if (req.body.date) updateData.date = req.body.date;
    updateData.updatedAt = new Date();

    const updatedModule = await Module.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true, runValidators: true }
    )
      .populate('user', 'username fullName')
      .select('-__v')
      .lean();

    logSecurityEvent('MODULE_UPDATED', { 
      moduleId: req.params.id, 
      updatedBy: req.user.id 
    }, req);

    res.json({ 
      success: true, 
      message: 'Module updated successfully.', 
      data: updatedModule 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

// DELETE module by ID with enhanced security
router.delete('/:id', [
  auth,
  param('id').isMongoId().withMessage('Valid module ID is required'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  try {
    const module = await Module.findById(req.params.id);
    if (!module) {
      return errorResponse(res, 404, 'Module not found.');
    }

    // Authorization check - users can only delete their own modules unless admin
    if (req.user.role !== 'admin' && req.user.id !== module.user.toString()) {
      logSecurityEvent('UNAUTHORIZED_MODULE_DELETE', { 
        requesterId: req.user.id, 
        moduleId: req.params.id,
        moduleOwner: module.user 
      }, req);
      return errorResponse(res, 403, 'You can only delete your own modules.');
    }

    await Module.findByIdAndDelete(req.params.id);

    logSecurityEvent('MODULE_DELETED', { 
      moduleId: req.params.id, 
      deletedBy: req.user.id 
    }, req);

    res.json({ 
      success: true, 
      message: 'Module deleted successfully.' 
    });
  } catch (error) {
    return handleDatabaseError(res, error);
  }
}));

module.exports = router;