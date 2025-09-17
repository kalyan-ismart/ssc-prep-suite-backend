// tests/models.test.js
const mongoose = require('mongoose');
const User = require('../models/user.model');
const Quiz = require('../models/quiz.model');
const Category = require('../models/category.model');
const Goal = require('../models/goal.model');
const Progress = require('../models/progress.model');
const Tool = require('../models/tool.model');
const ExamSchedule = require('../models/examSchedule.model');
const Module = require('../models/module.model');

describe('Database Models', () => {
  beforeAll(async () => {
    // Connect to test database if not already connected
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.ATLAS_URI || 'mongodb://localhost:27017/test', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
    }
  });

  afterAll(async () => {
    // Clean up test data
    await Promise.all([
      User.deleteMany({ email: { $regex: /test.*@example\.com/ } }),
      Quiz.deleteMany({ title: { $regex: /^Test/ } }),
      Category.deleteMany({ name: { $regex: /^Test/ } }),
      Goal.deleteMany({ title: { $regex: /^Test/ } }),
      Progress.deleteMany({}),
      Tool.deleteMany({ name: { $regex: /^Test/ } }),
      ExamSchedule.deleteMany({ examName: { $regex: /^Test/ } }),
      Module.deleteMany({ title: { $regex: /^Test/ } })
    ]);
  });

  describe('User Model', () => {
    it('should create user with valid data', async () => {
      const userData = {
        username: 'testuser',
        email: 'testuser@example.com',
        password: '$2b$14$hashedpasswordhere',
        fullName: 'Test User',
        role: 'user'
      };

      const user = new User(userData);
      const savedUser = await user.save();

      expect(savedUser.username).toBe(userData.username);
      expect(savedUser.email).toBe(userData.email);
      expect(savedUser.role).toBe('user');
      expect(savedUser.tokenVersion).toBe(0);
      expect(savedUser.createdAt).toBeDefined();
    });

    it('should enforce unique email constraint', async () => {
      const userData1 = {
        username: 'user1',
        email: 'duplicate@example.com',
        password: '$2b$14$hashedpassword1',
        fullName: 'User One'
      };

      const userData2 = {
        username: 'user2',
        email: 'duplicate@example.com',
        password: '$2b$14$hashedpassword2',
        fullName: 'User Two'
      };

      await new User(userData1).save();

      await expect(new User(userData2).save()).rejects.toThrow();
    });

    it('should validate email format', async () => {
      const userData = {
        username: 'testuser2',
        email: 'invalid-email',
        password: '$2b$14$hashedpassword',
        fullName: 'Test User 2'
      };

      const user = new User(userData);
      await expect(user.save()).rejects.toThrow();
    });

    it('should set default role to user', async () => {
      const userData = {
        username: 'defaultrole',
        email: 'defaultrole@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Default Role User'
      };

      const user = new User(userData);
      const savedUser = await user.save();

      expect(savedUser.role).toBe('user');
    });

    it('should validate role enum', async () => {
      const userData = {
        username: 'invalidrole',
        email: 'invalidrole@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Invalid Role User',
        role: 'superuser'
      };

      const user = new User(userData);
      await expect(user.save()).rejects.toThrow();
    });
  });

  describe('Category Model', () => {
    it('should create category with valid data', async () => {
      const categoryData = {
        name: 'Test Mathematics',
        description: 'Test category for mathematics questions',
        icon: 'calculator',
        color: '#3b82f6'
      };

      const category = new Category(categoryData);
      const savedCategory = await category.save();

      expect(savedCategory.name).toBe(categoryData.name);
      expect(savedCategory.description).toBe(categoryData.description);
      expect(savedCategory.icon).toBe(categoryData.icon);
      expect(savedCategory.color).toBe(categoryData.color);
      expect(savedCategory.createdAt).toBeDefined();
    });

    it('should enforce unique name constraint', async () => {
      const categoryData1 = {
        name: 'Test Duplicate',
        description: 'First category',
        icon: 'book',
        color: '#ef4444'
      };

      const categoryData2 = {
        name: 'Test Duplicate',
        description: 'Second category',
        icon: 'pen',
        color: '#10b981'
      };

      await new Category(categoryData1).save();
      await expect(new Category(categoryData2).save()).rejects.toThrow();
    });

    it('should require name field', async () => {
      const categoryData = {
        description: 'Category without name',
        icon: 'question',
        color: '#8b5cf6'
      };

      const category = new Category(categoryData);
      await expect(category.save()).rejects.toThrow();
    });
  });

  describe('Quiz Model', () => {
    let testCategory;
    let testUser;

    beforeAll(async () => {
      testCategory = await new Category({
        name: 'Test Quiz Category',
        description: 'Category for quiz testing',
        icon: 'quiz',
        color: '#f59e0b'
      }).save();

      testUser = await new User({
        username: 'quizuser',
        email: 'quizuser@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Quiz User'
      }).save();
    });

    afterAll(async () => {
      await Category.findByIdAndDelete(testCategory._id);
      await User.findByIdAndDelete(testUser._id);
    });

    it('should create quiz with valid data', async () => {
      const quizData = {
        title: 'Test Quiz',
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
          }
        ],
        timeLimit: 60,
        isActive: true,
        createdBy: testUser._id
      };

      const quiz = new Quiz(quizData);
      const savedQuiz = await quiz.save();

      expect(savedQuiz.title).toBe(quizData.title);
      expect(savedQuiz.difficulty).toBe('medium');
      expect(savedQuiz.questions).toHaveLength(1);
      expect(savedQuiz.questions[0].options).toHaveLength(3);
      expect(savedQuiz.isActive).toBe(true);
    });

    it('should validate difficulty enum', async () => {
      const quizData = {
        title: 'Invalid Difficulty Quiz',
        category: testCategory._id,
        difficulty: 'extreme',
        questions: [{
          questionText: 'Test question',
          options: [{ text: 'Test', isCorrect: true }]
        }],
        createdBy: testUser._id
      };

      const quiz = new Quiz(quizData);
      await expect(quiz.save()).rejects.toThrow();
    });

    it('should require at least one correct answer per question', async () => {
      const quizData = {
        title: 'No Correct Answer Quiz',
        category: testCategory._id,
        questions: [{
          questionText: 'Test question',
          options: [
            { text: 'Option 1', isCorrect: false },
            { text: 'Option 2', isCorrect: false }
          ]
        }],
        createdBy: testUser._id
      };

      const quiz = new Quiz(quizData);
      const validationError = quiz.validateSync();
      expect(validationError).toBeDefined();
    });

    it('should set default values', async () => {
      const minimalQuizData = {
        title: 'Minimal Quiz',
        category: testCategory._id,
        questions: [{
          questionText: 'Test question',
          options: [{ text: 'Test', isCorrect: true }]
        }],
        createdBy: testUser._id
      };

      const quiz = new Quiz(minimalQuizData);
      const savedQuiz = await quiz.save();

      expect(savedQuiz.difficulty).toBe('medium');
      expect(savedQuiz.timeLimit).toBe(30);
      expect(savedQuiz.isActive).toBe(true);
    });
  });

  describe('Goal Model', () => {
    let testUser;

    beforeAll(async () => {
      testUser = await new User({
        username: 'goaluser',
        email: 'goaluser@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Goal User'
      }).save();
    });

    afterAll(async () => {
      await User.findByIdAndDelete(testUser._id);
    });

    it('should create goal with valid data', async () => {
      const goalData = {
        userId: testUser._id,
        title: 'Test Goal',
        target: 50,
        completed: false,
        category: 'Mathematics',
        dueDate: new Date('2024-12-31')
      };

      const goal = new Goal(goalData);
      const savedGoal = await goal.save();

      expect(savedGoal.title).toBe(goalData.title);
      expect(savedGoal.target).toBe(goalData.target);
      expect(savedGoal.completed).toBe(false);
      expect(savedGoal.category).toBe('Mathematics');
    });

    it('should validate target range', async () => {
      const invalidGoalData = {
        userId: testUser._id,
        title: 'Invalid Target Goal',
        target: 0, // Below minimum
        category: 'Test'
      };

      const goal = new Goal(invalidGoalData);
      await expect(goal.save()).rejects.toThrow();
    });

    it('should require userId reference', async () => {
      const goalData = {
        title: 'No User Goal',
        target: 25,
        category: 'Test'
      };

      const goal = new Goal(goalData);
      await expect(goal.save()).rejects.toThrow();
    });
  });

  describe('Progress Model', () => {
    let testUser;
    let testQuiz;
    let testModule;

    beforeAll(async () => {
      testUser = await new User({
        username: 'progressuser',
        email: 'progressuser@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Progress User'
      }).save();

      const category = await new Category({
        name: 'Test Progress Category',
        description: 'Category for progress testing',
        icon: 'chart',
        color: '#06b6d4'
      }).save();

      testQuiz = await new Quiz({
        title: 'Test Progress Quiz',
        category: category._id,
        questions: [{
          questionText: 'Test question',
          options: [{ text: 'Test', isCorrect: true }]
        }],
        createdBy: testUser._id
      }).save();

      testModule = await new Module({
        user: testUser._id,
        title: 'Test Progress Module',
        description: 'Module for progress testing',
        duration: 60,
        date: new Date()
      }).save();
    });

    afterAll(async () => {
      await User.findByIdAndDelete(testUser._id);
      await Quiz.findByIdAndDelete(testQuiz._id);
      await Module.findByIdAndDelete(testModule._id);
    });

    it('should create progress record with quiz', async () => {
      const progressData = {
        user: testUser._id,
        quiz: testQuiz._id,
        score: 85,
        date: new Date(),
        timeSpent: 45
      };

      const progress = new Progress(progressData);
      const savedProgress = await progress.save();

      expect(savedProgress.score).toBe(85);
      expect(savedProgress.timeSpent).toBe(45);
      expect(savedProgress.user.toString()).toBe(testUser._id.toString());
    });

    it('should create progress record with module', async () => {
      const progressData = {
        user: testUser._id,
        module: testModule._id,
        score: 92,
        date: new Date(),
        timeSpent: 30
      };

      const progress = new Progress(progressData);
      const savedProgress = await progress.save();

      expect(savedProgress.score).toBe(92);
      expect(savedProgress.module.toString()).toBe(testModule._id.toString());
    });

    it('should validate score range', async () => {
      const invalidProgressData = {
        user: testUser._id,
        quiz: testQuiz._id,
        score: 150, // Above maximum
        date: new Date()
      };

      const progress = new Progress(invalidProgressData);
      await expect(progress.save()).rejects.toThrow();
    });
  });

  describe('Tool Model', () => {
    let testCategory;
    let testUser;

    beforeAll(async () => {
      testCategory = await new Category({
        name: 'Test Tool Category',
        description: 'Category for tool testing',
        icon: 'tool',
        color: '#ef4444'
      }).save();

      testUser = await new User({
        username: 'tooluser',
        email: 'tooluser@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Tool User'
      }).save();
    });

    afterAll(async () => {
      await Category.findByIdAndDelete(testCategory._id);
      await User.findByIdAndDelete(testUser._id);
    });

    it('should create tool with valid data', async () => {
      const toolData = {
        name: 'Test Calculator',
        description: 'A test calculation tool',
        category: testCategory._id,
        url: 'https://example.com/calculator',
        createdBy: testUser._id,
        isActive: true
      };

      const tool = new Tool(toolData);
      const savedTool = await tool.save();

      expect(savedTool.name).toBe(toolData.name);
      expect(savedTool.description).toBe(toolData.description);
      expect(savedTool.url).toBe(toolData.url);
      expect(savedTool.isActive).toBe(true);
    });

    it('should validate URL format', async () => {
      const invalidToolData = {
        name: 'Invalid URL Tool',
        description: 'Tool with invalid URL',
        category: testCategory._id,
        url: 'not-a-valid-url',
        createdBy: testUser._id
      };

      const tool = new Tool(invalidToolData);
      await expect(tool.save()).rejects.toThrow();
    });

    it('should require category reference', async () => {
      const toolData = {
        name: 'No Category Tool',
        description: 'Tool without category',
        url: 'https://example.com/tool',
        createdBy: testUser._id
      };

      const tool = new Tool(toolData);
      await expect(tool.save()).rejects.toThrow();
    });
  });

  describe('ExamSchedule Model', () => {
    it('should create exam schedule with valid data', async () => {
      const examData = {
        examName: 'Test SSC CGL 2024',
        date: new Date('2024-07-15'),
        duration: 180,
        description: 'Test exam schedule'
      };

      const examSchedule = new ExamSchedule(examData);
      const savedExam = await examSchedule.save();

      expect(savedExam.examName).toBe(examData.examName);
      expect(savedExam.duration).toBe(examData.duration);
      expect(savedExam.createdAt).toBeDefined();
    });

    it('should validate duration range', async () => {
      const invalidExamData = {
        examName: 'Invalid Duration Exam',
        date: new Date('2024-06-15'),
        duration: 0 // Below minimum
      };

      const examSchedule = new ExamSchedule(invalidExamData);
      await expect(examSchedule.save()).rejects.toThrow();
    });

    it('should require exam name and date', async () => {
      const incompleteExamData = {
        duration: 120,
        description: 'Incomplete exam data'
      };

      const examSchedule = new ExamSchedule(incompleteExamData);
      await expect(examSchedule.save()).rejects.toThrow();
    });
  });

  describe('Module Model', () => {
    let testUser;

    beforeAll(async () => {
      testUser = await new User({
        username: 'moduleuser',
        email: 'moduleuser@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Module User'
      }).save();
    });

    afterAll(async () => {
      await User.findByIdAndDelete(testUser._id);
    });

    it('should create module with valid data', async () => {
      const moduleData = {
        user: testUser._id,
        title: 'Test Module',
        description: 'A test study module',
        duration: 90,
        date: new Date()
      };

      const module = new Module(moduleData);
      const savedModule = await module.save();

      expect(savedModule.title).toBe(moduleData.title);
      expect(savedModule.duration).toBe(moduleData.duration);
      expect(savedModule.user.toString()).toBe(testUser._id.toString());
    });

    it('should validate duration range', async () => {
      const invalidModuleData = {
        user: testUser._id,
        title: 'Invalid Duration Module',
        description: 'Module with invalid duration',
        duration: 1500, // Above maximum
        date: new Date()
      };

      const module = new Module(invalidModuleData);
      await expect(module.save()).rejects.toThrow();
    });

    it('should require user reference', async () => {
      const moduleData = {
        title: 'No User Module',
        description: 'Module without user',
        duration: 60,
        date: new Date()
      };

      const module = new Module(moduleData);
      await expect(module.save()).rejects.toThrow();
    });
  });

  describe('Model Relationships', () => {
    let testUser, testCategory, testQuiz;

    beforeAll(async () => {
      testUser = await new User({
        username: 'relationuser',
        email: 'relationuser@example.com',
        password: '$2b$14$hashedpassword',
        fullName: 'Relation User'
      }).save();

      testCategory = await new Category({
        name: 'Test Relation Category',
        description: 'Category for relationship testing',
        icon: 'relation',
        color: '#8b5cf6'
      }).save();

      testQuiz = await new Quiz({
        title: 'Test Relation Quiz',
        category: testCategory._id,
        questions: [{
          questionText: 'Test question',
          options: [{ text: 'Test', isCorrect: true }]
        }],
        createdBy: testUser._id
      }).save();
    });

    afterAll(async () => {
      await Quiz.findByIdAndDelete(testQuiz._id);
      await Category.findByIdAndDelete(testCategory._id);
      await User.findByIdAndDelete(testUser._id);
    });

    it('should populate quiz with category and creator', async () => {
      const quiz = await Quiz.findById(testQuiz._id)
        .populate('category', 'name icon color')
        .populate('createdBy', 'username fullName');

      expect(quiz.category.name).toBe('Test Relation Category');
      expect(quiz.createdBy.username).toBe('relationuser');
    });

    it('should maintain referential integrity', async () => {
      // Create progress record referencing the quiz
      const progress = await new Progress({
        user: testUser._id,
        quiz: testQuiz._id,
        score: 88,
        date: new Date(),
        timeSpent: 35
      }).save();

      // Populate the progress with user and quiz data
      const populatedProgress = await Progress.findById(progress._id)
        .populate('user', 'username email')
        .populate('quiz', 'title difficulty');

      expect(populatedProgress.user.username).toBe('relationuser');
      expect(populatedProgress.quiz.title).toBe('Test Relation Quiz');

      // Cleanup
      await Progress.findByIdAndDelete(progress._id);
    });
  });
});