// routes/ai.js - Updated for OpenAI v4+ API

const express = require('express');
const { body, validationResult } = require('express-validator');
const OpenAI = require('openai'); // v4+ syntax
const { errorResponse, handleDatabaseError, asyncHandler, logSecurityEvent } = require('../utils/errors');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Initialize OpenAI API (v4+ syntax)
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

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

// @route GET /ai/health
// @desc Check AI service health
// @access Public (NO AUTH REQUIRED)
router.get('/health', asyncHandler(async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.json({
        success: false,
        status: 'error',
        message: 'OpenAI API key not configured'
      });
    }

    // Test OpenAI connection with a minimal request
    try {
      const testResponse = await openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [{ role: "user", content: "Hello" }],
        max_tokens: 5,
        temperature: 0
      });

      res.json({
        success: true,
        status: 'healthy',
        service: 'OpenAI API v4+',
        model: 'gpt-3.5-turbo',
        timestamp: new Date().toISOString(),
        authentication: 'Health check - no auth required'
      });
    } catch (openaiError) {
      console.error('OpenAI connection test failed:', openaiError.message);
      return res.json({
        success: false,
        status: 'error',
        message: 'OpenAI API connection failed',
        details: openaiError.message
      });
    }

  } catch (error) {
    console.error('Health check error:', error.message);
    return errorResponse(res, 500, 'AI service health check failed.');
  }
}));

// @route POST /ai/chat
// @desc Chat with OpenAI
// @access Private (Auth Required)
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

    // Prepare the system prompt
    const systemPrompt = context || "You are a helpful AI assistant specializing in government exam preparation. Provide clear, accurate, and educational responses to help users succeed in their studies.";

    // Create messages array for chat completion
    const messages = [
      { role: "system", content: systemPrompt },
      { role: "user", content: message }
    ];

    console.log('📤 Sending request to OpenAI:', { model: 'gpt-3.5-turbo', messageCount: messages.length });

    // Make OpenAI API call (v4+ syntax)
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: messages,
      max_tokens: 500,
      temperature: 0.7,
      top_p: 1,
      frequency_penalty: 0,
      presence_penalty: 0,
    });

    const aiResponse = completion.choices[0]?.message?.content?.trim();

    if (!aiResponse) {
      console.error('❌ No response content from OpenAI');
      return errorResponse(res, 500, 'No response from OpenAI.');
    }

    console.log('✅ OpenAI response received:', { responseLength: aiResponse.length });

    // Log AI usage for monitoring
    if (logSecurityEvent) {
      logSecurityEvent('AI_CHAT_REQUEST', {
        userId: req.user.id,
        messageLength: message.length,
        responseLength: aiResponse.length
      }, req);
    }

    res.json({
      success: true,
      data: {
        message: aiResponse,
        model: "gpt-3.5-turbo",
        usage: {
          prompt_tokens: completion.usage?.prompt_tokens || 0,
          completion_tokens: completion.usage?.completion_tokens || 0,
          total_tokens: completion.usage?.total_tokens || 0,
        }
      }
    });

  } catch (error) {
    console.error('❌ OpenAI API Error:', {
      message: error.message,
      status: error.status || error.response?.status,
      code: error.code,
      type: error.type
    });

    // Handle specific OpenAI API errors
    if (error.status === 401 || error.code === 'invalid_api_key') {
      return errorResponse(res, 401, 'Invalid OpenAI API key.');
    }

    if (error.status === 429 || error.code === 'rate_limit_exceeded') {
      return errorResponse(res, 429, 'OpenAI API rate limit exceeded. Please try again in a few minutes.');
    }

    if (error.status === 400 || error.code === 'invalid_request_error') {
      return errorResponse(res, 400, 'Invalid request to OpenAI API.');
    }

    if (error.status === 404) {
      return errorResponse(res, 500, 'OpenAI API endpoint not found. Please check API configuration.');
    }

    // Generic error for other cases
    return errorResponse(res, 500, 'AI service temporarily unavailable.');
  }
}));

// @route POST /ai/summarize
// @desc Summarize text content
// @access Private (Auth Required)
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

    const messages = [
      { 
        role: "system", 
        content: "You are an expert at summarizing text content. Provide clear, concise summaries that capture the key points and main ideas." 
      },
      { 
        role: "user", 
        content: `Please provide a concise summary of the following text:\n\n${text}` 
      }
    ];

    console.log('📤 Sending summarization request to OpenAI');

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: messages,
      max_tokens: 300,
      temperature: 0.3,
      top_p: 1,
      frequency_penalty: 0,
      presence_penalty: 0,
    });

    const summary = completion.choices[0]?.message?.content?.trim();

    if (!summary) {
      console.error('❌ No summary content from OpenAI');
      return errorResponse(res, 500, 'No response from OpenAI.');
    }

    console.log('✅ Summary generated:', { summaryLength: summary.length });

    if (logSecurityEvent) {
      logSecurityEvent('AI_SUMMARIZE_REQUEST', {
        userId: req.user.id,
        textLength: text.length,
        summaryLength: summary.length
      }, req);
    }

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
    console.error('❌ OpenAI Summarization Error:', error.message);
    
    // Handle specific errors
    if (error.status === 401) {
      return errorResponse(res, 401, 'Invalid OpenAI API key.');
    }
    if (error.status === 429) {
      return errorResponse(res, 429, 'OpenAI API rate limit exceeded.');
    }
    if (error.status === 400) {
      return errorResponse(res, 400, 'Invalid request to OpenAI API.');
    }

    return errorResponse(res, 500, 'AI summarization service temporarily unavailable.');
  }
}));

// @route POST /ai/study-help
// @desc Get study help for government exams
// @access Private (Auth Required)
router.post('/study-help', [
  auth,
  body('topic')
    .isString()
    .trim()
    .isLength({ min: 2, max: 200 })
    .withMessage('Topic must be 2-200 characters'),
  body('examType')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Exam type must be less than 100 characters'),
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(res, 422, 'Validation failed.', errors.array());
  }

  const { topic, examType } = req.body;

  try {
    if (!process.env.OPENAI_API_KEY) {
      return errorResponse(res, 500, 'OpenAI API key not configured.');
    }

    const systemPrompt = `You are an expert tutor specializing in Indian government competitive exams (SSC, UPSC, Banking, Railway, etc.). 
    Provide detailed, accurate study guidance including:
    - Key concepts and definitions
    - Important points to remember
    - Tips for exam preparation
    - Common question patterns
    - Memory techniques where applicable`;

    const userMessage = examType 
      ? `Explain "${topic}" for ${examType} exam preparation. Include key points, important facts, and study tips.`
      : `Explain "${topic}" for government exam preparation. Include key points, important facts, and study tips.`;

    const messages = [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage }
    ];

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: messages,
      max_tokens: 800,
      temperature: 0.5,
    });

    const studyHelp = completion.choices[0]?.message?.content?.trim();

    if (!studyHelp) {
      return errorResponse(res, 500, 'No response from OpenAI.');
    }

    res.json({
      success: true,
      data: {
        topic: topic,
        examType: examType || 'General',
        studyHelp: studyHelp,
        model: "gpt-3.5-turbo"
      }
    });

  } catch (error) {
    console.error('❌ Study Help API Error:', error.message);
    return errorResponse(res, 500, 'Study help service temporarily unavailable.');
  }
}));

module.exports = router;