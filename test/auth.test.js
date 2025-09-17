// tests/auth.test.js
const request = require('supertest');
const app = require('../server');
const User = require('../models/user.model');
const jwt = require('jsonwebtoken');

describe('Authentication', () => {
  let testUserId;

  afterAll(async () => {
    // Cleanup test users
    await User.deleteMany({ email: { $regex: /test.*@example\.com/ } });
  });

  describe('POST /api/users/register', () => {
    const validUserData = {
      username: 'testuser123',
      email: 'testuser123@example.com',
      password: 'SecurePassword123!',
      fullName: 'Test User'
    };

    afterEach(async () => {
      // Clean up created user after each test
      await User.findOneAndDelete({ email: validUserData.email });
    });

    it('should register user with valid data', async () => {
      const res = await request(app)
        .post('/api/users/register')
        .send(validUserData);

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('User registered successfully');
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.body.user.username).toBe(validUserData.username);
      expect(res.body.user.email).toBe(validUserData.email);
      expect(res.body.user.role).toBe('user');
      expect(res.body.user.password).toBeUndefined();
    });

    it('should reject weak passwords', async () => {
      const weakPasswordData = {
        ...validUserData,
        email: 'weakpass@example.com',
        password: 'weak123' // Too short and no uppercase/special char
      };

      const res = await request(app)
        .post('/api/users/register')
        .send(weakPasswordData);

      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
      expect(res.body.errors).toBeDefined();
    });

    it('should reject common passwords', async () => {
      const commonPasswordData = {
        ...validUserData,
        email: 'common@example.com',
        password: 'Password123!' // Common pattern
      };

      const res = await request(app)
        .post('/api/users/register')
        .send(commonPasswordData);

      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });

    it('should reject invalid email formats', async () => {
      const invalidEmailData = {
        ...validUserData,
        email: 'invalid-email'
      };

      const res = await request(app)
        .post('/api/users/register')
        .send(invalidEmailData);

      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });

    it('should reject duplicate username', async () => {
      // First registration
      await request(app)
        .post('/api/users/register')
        .send(validUserData);

      // Attempt duplicate username
      const duplicateUsernameData = {
        ...validUserData,
        email: 'different@example.com'
      };

      const res = await request(app)
        .post('/api/users/register')
        .send(duplicateUsernameData);

      expect(res.statusCode).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Username already exists.');
    });

    it('should reject duplicate email', async () => {
      // First registration
      await request(app)
        .post('/api/users/register')
        .send(validUserData);

      // Attempt duplicate email
      const duplicateEmailData = {
        ...validUserData,
        username: 'differentuser'
      };

      const res = await request(app)
        .post('/api/users/register')
        .send(duplicateEmailData);

      expect(res.statusCode).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Email already registered.');
    });
  });

  describe('POST /api/users/login', () => {
    const loginUserData = {
      username: 'logintest',
      email: 'logintest@example.com',
      password: 'LoginPassword123!',
      fullName: 'Login Test User'
    };

    beforeAll(async () => {
      // Create user for login tests
      const registerRes = await request(app)
        .post('/api/users/register')
        .send(loginUserData);
      
      testUserId = registerRes.body.user.id;
    });

    afterAll(async () => {
      await User.findByIdAndDelete(testUserId);
    });

    it('should login with valid credentials', async () => {
      const res = await request(app)
        .post('/api/users/login')
        .send({
          email: loginUserData.email,
          password: loginUserData.password
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Login successful');
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.body.user.email).toBe(loginUserData.email);
      expect(res.body.user.lastLogin).toBeDefined();
    });

    it('should reject invalid email', async () => {
      const res = await request(app)
        .post('/api/users/login')
        .send({
          email: 'nonexistent@example.com',
          password: loginUserData.password
        });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid credentials.');
    });

    it('should reject invalid password', async () => {
      const res = await request(app)
        .post('/api/users/login')
        .send({
          email: loginUserData.email,
          password: 'wrongpassword'
        });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid credentials.');
    });

    it('should validate required fields', async () => {
      const res = await request(app)
        .post('/api/users/login')
        .send({
          email: loginUserData.email
          // Missing password
        });

      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/users/refresh', () => {
    let refreshToken;
    let userId;

    beforeAll(async () => {
      // Register and login to get refresh token
      const registerRes = await request(app)
        .post('/api/users/register')
        .send({
          username: 'refreshtest',
          email: 'refreshtest@example.com',
          password: 'RefreshPassword123!',
          fullName: 'Refresh Test User'
        });

      refreshToken = registerRes.body.refreshToken;
      userId = registerRes.body.user.id;
    });

    afterAll(async () => {
      await User.findByIdAndDelete(userId);
    });

    it('should refresh tokens with valid refresh token', async () => {
      const res = await request(app)
        .post('/api/users/refresh')
        .send({ refreshToken });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.body.refreshToken).not.toBe(refreshToken); // Should be rotated
    });

    it('should reject missing refresh token', async () => {
      const res = await request(app)
        .post('/api/users/refresh')
        .send({});

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Refresh token required.');
    });

    it('should reject invalid refresh token', async () => {
      const res = await request(app)
        .post('/api/users/refresh')
        .send({ refreshToken: 'invalid.token.here' });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid refresh token.');
    });

    it('should reject expired refresh token', async () => {
      // Create an expired token
      const expiredToken = jwt.sign(
        { userId, type: 'refresh', iat: Math.floor(Date.now() / 1000) - 1000 },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '-1d' }
      );

      const res = await request(app)
        .post('/api/users/refresh')
        .send({ refreshToken: expiredToken });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/users/logout', () => {
    let accessToken;
    let userId;

    beforeAll(async () => {
      const registerRes = await request(app)
        .post('/api/users/register')
        .send({
          username: 'logouttest',
          email: 'logouttest@example.com',
          password: 'LogoutPassword123!',
          fullName: 'Logout Test User'
        });

      accessToken = registerRes.body.accessToken;
      userId = registerRes.body.user.id;
    });

    afterAll(async () => {
      await User.findByIdAndDelete(userId);
    });

    it('should logout successfully with valid token', async () => {
      const res = await request(app)
        .post('/api/users/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Logged out successfully.');
    });

    it('should require authentication', async () => {
      const res = await request(app)
        .post('/api/users/logout');

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject invalid token', async () => {
      const res = await request(app)
        .post('/api/users/logout')
        .set('Authorization', 'Bearer invalid.token.here');

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/users/change-password', () => {
    let accessToken;
    let userId;

    beforeAll(async () => {
      const registerRes = await request(app)
        .post('/api/users/register')
        .send({
          username: 'passwordtest',
          email: 'passwordtest@example.com',
          password: 'OldPassword123!',
          fullName: 'Password Test User'
        });

      accessToken = registerRes.body.accessToken;
      userId = registerRes.body.user.id;
    });

    afterAll(async () => {
      await User.findByIdAndDelete(userId);
    });

    it('should change password with valid current password', async () => {
      const res = await request(app)
        .post('/api/users/change-password')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          currentPassword: 'OldPassword123!',
          newPassword: 'NewPassword456!',
          confirmPassword: 'NewPassword456!'
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Password changed successfully. Please log in again.');
    });

    it('should reject invalid current password', async () => {
      const res = await request(app)
        .post('/api/users/change-password')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          currentPassword: 'WrongPassword!',
          newPassword: 'NewPassword456!',
          confirmPassword: 'NewPassword456!'
        });

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Current password is incorrect.');
    });

    it('should validate password confirmation', async () => {
      const res = await request(app)
        .post('/api/users/change-password')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          currentPassword: 'OldPassword123!',
          newPassword: 'NewPassword456!',
          confirmPassword: 'DifferentPassword!'
        });

      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });

    it('should require authentication', async () => {
      const res = await request(app)
        .post('/api/users/change-password')
        .send({
          currentPassword: 'OldPassword123!',
          newPassword: 'NewPassword456!',
          confirmPassword: 'NewPassword456!'
        });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  describe('JWT Token Validation', () => {
    it('should reject malformed tokens', async () => {
      const res = await request(app)
        .get('/api/users/me')
        .set('Authorization', 'Bearer malformed.token');

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid token. Access denied.');
    });

    it('should reject expired tokens', async () => {
      // Create an expired token
      const expiredToken = jwt.sign(
        { user: { id: 'test', role: 'user' }, iat: Math.floor(Date.now() / 1000) - 1000 },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' }
      );

      const res = await request(app)
        .get('/api/users/me')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Token has expired. Please login again.');
    });

    it('should accept valid tokens', async () => {
      // First register a user to get a valid token
      const registerRes = await request(app)
        .post('/api/users/register')
        .send({
          username: 'tokentest',
          email: 'tokentest@example.com',
          password: 'TokenPassword123!',
          fullName: 'Token Test User'
        });

      const res = await request(app)
        .get('/api/users/me')
        .set('Authorization', `Bearer ${registerRes.body.accessToken}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);

      // Cleanup
      await User.findByIdAndDelete(registerRes.body.user.id);
    });
  });
});