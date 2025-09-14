// routes/ai.js - Compatible with OpenAI v3.3.0

const express = require('express');
const { body, validationResult } = require('express-validator');
const { Configuration, OpenAIApi } = require('openai');
const { errorResponse, handleDatabaseError, asyncHandler, logSecurityEvent } = require('../utils/errors');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Initialize OpenAI API (v3.3.0 syntax)
const configuration = new Configuration({
  apiKey: process.env.OPENAI_API_KEY,
});
const openai = new OpenAIApi(configuration);

// Validation middleware
const validateChatRequest = [
  body('message')
    .isString()
    .trim()
    .isLength({ min: 1, max: 1000 })
    .withMessage('Message must be 1-1000 characters'),
  body('context')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Context must be less than 500 characters'),
];

// @route POST /ai/chat
// @desc Chat with OpenAI
// @access Private
router.post('/chat', [auth, ...validateChatRequest], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  const { message, context } = req.body;

  try {
    // Check if API key is configured
    if (!process.env.OPENAI_API_KEY) {
      return errorResponse(res, 500, 'OpenAI API key not configured.');
    }

    // Prepare the prompt
    const systemPrompt = context || "You are a helpful assistant for government exam preparation and educational content.";
    const prompt = `${systemPrompt}\n\nUser: ${message}\nAssistant:`;

    // Make OpenAI API call (v3.3.0 syntax)
    const completion = await openai.createCompletion({
      model: "text-davinci-003",
      prompt: prompt,
      max_tokens: 500,
      temperature: 0.7,
      top_p: 1,
      frequency_penalty: 0,
      presence_penalty: 0,
    });

    const aiResponse = completion.data.choices[0]?.text?.trim();

    if (!aiResponse) {
      return errorResponse(res, 500, 'No response from OpenAI.');
    }

    // Log AI usage for monitoring
    logSecurityEvent('AI_CHAT_REQUEST', {
      userId: req.user.id,
      messageLength: message.length,
      responseLength: aiResponse.length
    }, req);

    res.json({
      success: true,
      data: {
        message: aiResponse,
        model: "text-davinci-003",
        usage: {
          prompt_tokens: completion.data.usage?.prompt_tokens || 0,
          completion_tokens: completion.data.usage?.completion_tokens || 0,
          total_tokens: completion.data.usage?.total_tokens || 0,
        }
      }
    });

  } catch (error) {
    // Handle OpenAI API errors
    if (error.response?.status === 401) {
      return errorResponse(res, 401, 'Invalid OpenAI API key.');
    }
    if (error.response?.status === 429) {
      return errorResponse(res, 429, 'OpenAI API rate limit exceeded.');
    }
    if (error.response?.status === 400) {
      return errorResponse(res, 400, 'Invalid request to OpenAI API.');
    }

    console.error('OpenAI API Error:', error.message);
    return errorResponse(res, 500, 'AI service temporarily unavailable.');
  }
}));

// @route POST /ai/summarize
// @desc Summarize text content
// @access Private  
router.post('/summarize', [
  auth,
  body('text')
    .isString()
    .trim()
    .isLength({ min: 10, max: 5000 })
    .withMessage('Text must be 10-5000 characters')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  const { text } = req.body;

  try {
    if (!process.env.OPENAI_API_KEY) {
      return errorResponse(res, 500, 'OpenAI API key not configured.');
    }

    const prompt = `Please provide a concise summary of the following text:\n\n${text}\n\nSummary:`;

    const completion = await openai.createCompletion({
      model: "text-davinci-003",
      prompt: prompt,
      max_tokens: 300,
      temperature: 0.3,
      top_p: 1,
      frequency_penalty: 0,
      presence_penalty: 0,
    });

    const summary = completion.data.choices[0]?.text?.trim();

    if (!summary) {
      return errorResponse(res, 500, 'No response from OpenAI.');
    }

    logSecurityEvent('AI_SUMMARIZE_REQUEST', {
      userId: req.user.id,
      textLength: text.length,
      summaryLength: summary.length
    }, req);

    res.json({
      success: true,
      data: {
        summary: summary,
        original_length: text.length,
        summary_length: summary.length,
        compression_ratio: Math.round((summary.length / text.length) * 100)
      }
    });

  } catch (error) {
    console.error('OpenAI API Error:', error.message);
    return handleDatabaseError(res, error);
  }
}));

// @route GET /ai/health
// @desc Check AI service health
// @access Private
router.get('/health', auth, asyncHandler(async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.json({
        success: false,
        status: 'error',
        message: 'OpenAI API key not configured'
      });
    }

    res.json({
      success: true,
      status: 'healthy',
      service: 'OpenAI API v3.3.0',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    return errorResponse(res, 500, 'AI service health check failed.');
  }
}));

module.exports = router;