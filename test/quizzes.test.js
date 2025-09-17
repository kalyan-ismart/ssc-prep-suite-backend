// tests/quizzes.test.js
const request = require('supertest');
const app = require('../server');
const Quiz = require('../models/quiz.model');
const User = require('../models/user.model');
const Category = require('../models/category.model');

describe('Quizzes API', () => {
  let authToken;
  let adminToken;
  let testUser;
  let adminUser;
  let testCategory;
  let testQuiz;

  beforeAll(async () => {
    // Create test category
    testCategory = await Category.create({
      name: 'Test Mathematics',
      description: 'Test category for mathematics',
      icon: 'calculator',
      color: '#3b82f6'
    });

    // Create test user
    testUser = await User.create({
      username: 'testuser_quiz',
      email: 'testquiz@example.com',
      password: '$2b$14$hashedpassword', // Pre-hashed for testing
      fullName: 'Test Quiz User',
      role: 'user'
    });

    // Create admin user
    adminUser = await User.create({
      username: 'admin_quiz',
      email: 'adminquiz@example.com',
      password: '$2b$14$hashedpassword',
      fullName: 'Admin Quiz User',
      role: 'admin'
    });

    // Get auth tokens
    const loginRes = await request(app)
      .post('/api/users/login')
      .send({
        email: 'testquiz@example.com',
        password: 'TestPassword123!'
      });
    authToken = loginRes.body.accessToken;

    const adminLoginRes = await request(app)
      .post('/api/users/login')
      .send({
        email: 'adminquiz@example.com',
        password: 'TestPassword123!'
      });
    adminToken = adminLoginRes.body.accessToken;
  });

  afterAll(async () => {
    // Cleanup test data
    await Quiz.deleteMany({});
    await User.deleteMany({ email: { $in: ['testquiz@example.com', 'adminquiz@example.com'] } });
    await Category.findByIdAndDelete(testCategory._id);
  });

  beforeEach(async () => {
    // Create a test quiz for each test
    testQuiz = await Quiz.create({
      title: 'Test Quiz Mathematics',
      category: testCategory._id,
      difficulty: 'medium',
      questions: [
        {
          questionText: 'What is 2 + 2?',
          options: [
            { text: '4', isCorrect: true },
            { text: '3', isCorrect: false },
            { text: '5', isCorrect: false }
          ]
        },
        {
          questionText: 'What is 10% of 100?',
          options: [
            { text: '10', isCorrect: true },
            { text: '1', isCorrect: false },
            { text: '100', isCorrect: false }
          ]
        }
      ],
      timeLimit: 60,
      isActive: true,
      createdBy: testUser._id
    });
  });

  afterEach(async () => {
    // Clean up test quiz after each test
    await Quiz.findByIdAndDelete(testQuiz._id);
  });

  describe('GET /api/quizzes', () => {
    it('should get all active quizzes without authentication', async () => {
      const res = await request(app).get('/api/quizzes');
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
      expect(res.body.pagination).toBeDefined();
      expect(res.body.pagination.page).toBe(1);
      expect(res.body.pagination.limit).toBe(10);
    });

    it('should filter quizzes by category', async () => {
      const res = await request(app)
        .get(`/api/quizzes?category=${testCategory._id}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.every(quiz => quiz.category.id === testCategory._id.toString())).toBe(true);
    });

    it('should filter quizzes by difficulty', async () => {
      const res = await request(app)
        .get('/api/quizzes?difficulty=medium');
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.every(quiz => quiz.difficulty === 'medium')).toBe(true);
    });

    it('should search quizzes by title', async () => {
      const res = await request(app)
        .get('/api/quizzes?search=Mathematics');
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    });

    it('should validate pagination parameters', async () => {
      const res = await request(app)
        .get('/api/quizzes?page=0&limit=101');
      
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });
  });

  describe('GET /api/quizzes/:id', () => {
    it('should get quiz by valid ID', async () => {
      const res = await request(app)
        .get(`/api/quizzes/${testQuiz._id}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe(testQuiz._id.toString());
      expect(res.body.data.title).toBe('Test Quiz Mathematics');
      expect(res.body.data.questions).toBeDefined();
      expect(res.body.data.questions.length).toBe(2);
    });

    it('should return 404 for non-existent quiz ID', async () => {
      const nonExistentId = '60d0fe4f5311236168a109ca';
      const res = await request(app)
        .get(`/api/quizzes/${nonExistentId}`);
      
      expect(res.statusCode).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Quiz not found.');
    });

    it('should return 422 for invalid quiz ID format', async () => {
      const res = await request(app)
        .get('/api/quizzes/invalid-id');
      
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/quizzes/add', () => {
    const validQuizData = {
      title: 'New Test Quiz',
      category: null, // Will be set in beforeEach
      difficulty: 'easy',
      questions: [
        {
          questionText: 'What is 1 + 1?',
          options: [
            { text: '2', isCorrect: true },
            { text: '1', isCorrect: false },
            { text: '3', isCorrect: false }
          ]
        }
      ],
      timeLimit: 30,
      isActive: true
    };

    beforeEach(() => {
      validQuizData.category = testCategory._id;
    });

    it('should create quiz with valid data and authentication', async () => {
      const res = await request(app)
        .post('/api/quizzes/add')
        .set('Authorization', `Bearer ${authToken}`)
        .send(validQuizData);
      
      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Quiz added successfully.');
      expect(res.body.data.title).toBe(validQuizData.title);
      expect(res.body.data.createdBy.username).toBe(testUser.username);

      // Cleanup
      await Quiz.findByIdAndDelete(res.body.data.id);
    });

    it('should require authentication', async () => {
      const res = await request(app)
        .post('/api/quizzes/add')
        .send(validQuizData);
      
      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should validate required fields', async () => {
      const invalidQuizData = { ...validQuizData };
      delete invalidQuizData.title;
      delete invalidQuizData.category;

      const res = await request(app)
        .post('/api/quizzes/add')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidQuizData);
      
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });

    it('should prevent duplicate quiz titles', async () => {
      const duplicateQuizData = {
        ...validQuizData,
        title: testQuiz.title
      };

      const res = await request(app)
        .post('/api/quizzes/add')
        .set('Authorization', `Bearer ${authToken}`)
        .send(duplicateQuizData);
      
      expect(res.statusCode).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Quiz title already exists.');
    });
  });

  describe('POST /api/quizzes/update/:id', () => {
    it('should update quiz by creator', async () => {
      const updateData = {
        title: 'Updated Test Quiz',
        difficulty: 'hard'
      };

      const res = await request(app)
        .post(`/api/quizzes/update/${testQuiz._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.title).toBe(updateData.title);
      expect(res.body.data.difficulty).toBe(updateData.difficulty);
    });

    it('should update quiz by admin', async () => {
      const updateData = {
        title: 'Admin Updated Quiz',
        isActive: false
      };

      const res = await request(app)
        .post(`/api/quizzes/update/${testQuiz._id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send(updateData);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.title).toBe(updateData.title);
    });

    it('should prevent unauthorized quiz updates', async () => {
      // Create another user
      const anotherUser = await User.create({
        username: 'another_user',
        email: 'another@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Another User',
        role: 'user'
      });

      const anotherUserLogin = await request(app)
        .post('/api/users/login')
        .send({
          email: 'another@example.com',
          password: 'TestPassword123!'
        });

      const res = await request(app)
        .post(`/api/quizzes/update/${testQuiz._id}`)
        .set('Authorization', `Bearer ${anotherUserLogin.body.accessToken}`)
        .send({ title: 'Unauthorized Update' });
      
      expect(res.statusCode).toBe(403);
      expect(res.body.success).toBe(false);

      // Cleanup
      await User.findByIdAndDelete(anotherUser._id);
    });
  });

  describe('POST /api/quizzes/:id/submit', () => {
    it('should submit quiz answers and calculate score', async () => {
      const submissionData = {
        answers: ['4', '10'],
        timeSpent: 45
      };

      const res = await request(app)
        .post(`/api/quizzes/${testQuiz._id}/submit`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(submissionData);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Quiz submitted successfully.');
      expect(res.body.results.score).toBe(100);
      expect(res.body.results.correctAnswers).toBe(2);
      expect(res.body.results.totalQuestions).toBe(2);
      expect(res.body.results.passed).toBe(true);
    });

    it('should calculate partial score for incorrect answers', async () => {
      const submissionData = {
        answers: ['3', '10'], // First answer wrong, second correct
        timeSpent: 30
      };

      const res = await request(app)
        .post(`/api/quizzes/${testQuiz._id}/submit`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(submissionData);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.results.score).toBe(50);
      expect(res.body.results.correctAnswers).toBe(1);
    });

    it('should require authentication for quiz submission', async () => {
      const submissionData = {
        answers: ['4', '10'],
        timeSpent: 45
      };

      const res = await request(app)
        .post(`/api/quizzes/${testQuiz._id}/submit`)
        .send(submissionData);
      
      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should validate answers array length', async () => {
      const submissionData = {
        answers: ['4'], // Only one answer for two questions
        timeSpent: 45
      };

      const res = await request(app)
        .post(`/api/quizzes/${testQuiz._id}/submit`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(submissionData);
      
      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid number of answers provided.');
    });
  });

  describe('DELETE /api/quizzes/:id', () => {
    it('should delete quiz as admin', async () => {
      const res = await request(app)
        .delete(`/api/quizzes/${testQuiz._id}`)
        .set('Authorization', `Bearer ${adminToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Quiz deleted successfully.');

      // Verify quiz is deleted
      const deletedQuiz = await Quiz.findById(testQuiz._id);
      expect(deletedQuiz).toBeNull();
    });

    it('should require admin role for deletion', async () => {
      const res = await request(app)
        .delete(`/api/quizzes/${testQuiz._id}`)
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(403);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/quizzes/:id/toggle', () => {
    it('should toggle quiz status as admin', async () => {
      expect(testQuiz.isActive).toBe(true);

      const res = await request(app)
        .post(`/api/quizzes/${testQuiz._id}/toggle`)
        .set('Authorization', `Bearer ${adminToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Quiz deactivated successfully.');
      expect(res.body.data.isActive).toBe(false);
    });

    it('should require admin role for toggling status', async () => {
      const res = await request(app)
        .post(`/api/quizzes/${testQuiz._id}/toggle`)
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(403);
      expect(res.body.success).toBe(false);
    });
  });
});