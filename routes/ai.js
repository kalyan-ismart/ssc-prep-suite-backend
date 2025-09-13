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

const AI_MODEL = process.env.AI_MODEL || 'gpt-4';

// --- RATE LIMITERS ---
// General limiter for less frequent tools
const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 }); 
const studyAssistantLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
const doubtSolverLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });
const questionGeneratorLimiter = rateLimit({ windowMs: 60 * 1000, max: 3 });


// --- VALIDATION MIDDLEWARE ---
const validatePrompt = body('prompt').isString().trim().isLength({ min: 1 }).withMessage('Prompt is required');
const validateQuestion = body('question').isString().trim().isLength({ min: 1 }).withMessage('Question is required');
const validateTopic = body('topic').isString().trim().isLength({ min: 1 }).withMessage('Topic is required');
const validateDetails = body('details').isString().trim().isLength({ min: 1 }).withMessage('Details are required');
const validateInput = body('input').isString().trim().isLength({ min: 1 }).withMessage('Input is required');
const validateText = body('text').isString().trim().isLength({ min: 1 }).withMessage('Text is required');
const validateVoiceInput = body('voiceInput').isString().trim().isLength({ min: 1 }).withMessage('Voice input is required');


// --- HELPER FOR AI CALLS ---
const performAICall = async (messages, res) => {
  try {
    const completion = await openai.createChatCompletion({
      model: AI_MODEL,
      messages: messages,
    });

    const content = completion?.data?.choices?.[0]?.message?.content;
    if (!content) throw new Error('Invalid response from OpenAI');

    return content;
  } catch (err) {
    console.error('OpenAI API Error:', err.response ? err.response.data : err.message);
    const errorMessage = process.env.NODE_ENV === 'production' ? 'An error occurred with the AI service' : err.message;
    errorResponse(res, 500, 'AI generation failed', [errorMessage]);
    return null;
  }
};


// --- EXISTING ROUTES ---

// POST /ai/study-assistant
router.post('/study-assistant', studyAssistantLimiter, validatePrompt, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed', errors.array());
  
  const answer = await performAICall([{ role: 'user', content: req.body.prompt }], res);
  if (answer) res.json({ success: true, data: { answer } });
});

// POST /ai/doubt-solver
router.post('/doubt-solver', doubtSolverLimiter, validateQuestion, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed', errors.array());

  const solution = await performAICall([{ role: 'user', content: `Explain and solve: ${req.body.question}` }], res);
  if (solution) res.json({ success: true, data: { solution } });
});

// POST /ai/question-generator
router.post('/question-generator', questionGeneratorLimiter, validateTopic, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed', errors.array());

  const questions = await performAICall([
    { role: 'system', content: 'You are a helpful assistant that generates multiple-choice questions.' },
    { role: 'user', content: `Generate 5 multiple-choice questions on the topic of "${req.body.topic}". Provide 4 options for each and indicate the correct answer.` }
  ], res);
  if (questions) res.json({ success: true, data: { questions } });
});


// --- NEWLY ADDED ROUTES ---

// POST /ai/performance-predictor
router.post('/performance-predictor', generalLimiter, validateDetails, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed', errors.array());

    const prediction = await performAICall([
        { role: 'system', content: 'You are a helpful assistant that predicts student performance.' },
        { role: 'user', content: `Based on these details, predict the performance: ${req.body.details}` }
    ], res);
    if (prediction) res.json({ success: true, data: { prediction } });
});

// POST /ai/study-recommendation
router.post('/study-recommendation', generalLimiter, validateInput, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed', errors.array());

    const recommendations = await performAICall([
        { role: 'system', content: 'You are a helpful study advisor.' },
        { role: 'user', content: `Provide study recommendations for the following topic/question: ${req.body.input}` }
    ], res);
    if (recommendations) res.json({ success: true, data: { recommendations: recommendations.split('\n') } }); // Split into an array
});

// POST /ai/content-summarizer
router.post('/content-summarizer', generalLimiter, validateText, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed', errors.array());

    const summary = await performAICall([
        { role: 'system', content: 'You are a helpful assistant that summarizes text.' },
        { role: 'user', content: `Summarize the following content: ${req.body.text}` }
    ], res);
    if (summary) res.json({ success: true, data: { summary } });
});

// POST /ai/smart-flashcards
router.post('/smart-flashcards', generalLimiter, validateTopic, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed', errors.array());

    const flashcards = await performAICall([
        { role: 'system', content: 'You are a helpful assistant that creates flashcards.' },
        { role: 'user', content: `Generate 5 flashcards (question/answer format) for the topic: ${req.body.topic}` }
    ], res);
    if (flashcards) res.json({ success: true, data: { flashcards: flashcards.split('\n') } }); // Split into an array
});

// POST /ai/voice-assistant
router.post('/voice-assistant', studyAssistantLimiter, validateVoiceInput, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return errorResponse(res, 422, 'Validation failed', errors.array());

    const response = await performAICall([
        { role: 'system', content: 'You are a helpful voice assistant.' },
        { role: 'user', content: req.body.voiceInput }
    ], res);
    if (response) res.json({ success: true, data: { response } });
});


module.exports = router;
