const express = require('express');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { Configuration, OpenAIApi } = require('openai');
const { errorResponse } = require('../utils/errors');
require('dotenv').config();

const router = express.Router();

// Validate environment variables
if (!process.env.OPENAI_KEY) {
  throw new Error('OPENAI_KEY is not set in environment variables.');
}

// Initialize OpenAI client
const openai = new OpenAIApi(new Configuration({
  apiKey: process.env.OPENAI_KEY,
}));

const AI_MODEL = process.env.AI_MODEL || 'gpt-4'; // Externalized model name

// Rate limiters
const studyAssistantLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
const doubtSolverLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });
const questionGeneratorLimiter = rateLimit({ windowMs: 60 * 1000, max: 3 });

// Validation middleware
const validatePrompt = body('prompt').isString().isLength({ min: 1 }).withMessage('Prompt is required');
const validateQuestion = body('question').isString().isLength({ min: 1 }).withMessage('Question is required');
const validateTopic = body('topic').isString().isLength({ min: 1 }).withMessage('Topic is required');

// POST /ai/study-assistant
router.post(
  '/study-assistant',
  studyAssistantLimiter,
  validatePrompt,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 422, 'Validation failed', errors.array());
    }

    try {
      const { prompt } = req.body;
      const completion = await openai.createChatCompletion({
        model: AI_MODEL,
        messages: [{ role: 'user', content: prompt }],
      });

      const answer = completion?.data?.choices?.[0]?.message?.content;
      if (!answer) throw new Error('Invalid response from OpenAI');

      return res.json({ success: true, data: { answer } });
    } catch (err) {
      const errorMessage = process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message;
      return errorResponse(res, 500, 'AI generation failed', [errorMessage]);
    }
  }
);

// POST /ai/doubt-solver
router.post(
  '/doubt-solver',
  doubtSolverLimiter,
  validateQuestion,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 422, 'Validation failed', errors.array());
    }

    try {
      const { question } = req.body;
      const completion = await openai.createChatCompletion({
        model: AI_MODEL,
        messages: [{ role: 'user', content: `Explain and solve: ${question}` }],
      });

      const solution = completion?.data?.choices?.[0]?.message?.content;
      if (!solution) throw new Error('Invalid response from OpenAI');

      return res.json({ success: true, data: { solution } });
    } catch (err) {
      const errorMessage = process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message;
      return errorResponse(res, 500, 'AI generation failed', [errorMessage]);
    }
  }
);

// POST /ai/question-generator
router.post(
  '/question-generator',
  questionGeneratorLimiter,
  validateTopic,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 422, 'Validation failed', errors.array());
    }

    try {
      const { topic } = req.body;
      const completion = await openai.createChatCompletion({
        model: AI_MODEL,
        messages: [
          { role: 'system', content: 'Generate 5 multiple-choice questions with 4 options each.' },
          { role: 'user', content: `Topic: ${topic}` },
        ],
      });

      const questions = completion?.data?.choices?.[0]?.message?.content;
      if (!questions) throw new Error('Invalid response from OpenAI');

      return res.json({ success: true, data: { questions } });
    } catch (err) {
      const errorMessage = process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message;
      return errorResponse(res, 500, 'AI generation failed', [errorMessage]);
    }
  }
);

module.exports = router;