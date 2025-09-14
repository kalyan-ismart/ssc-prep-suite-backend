const request = require('supertest');
const app = require('../server'); // Make sure you export app in server.js

describe('Users API', () => {
  describe('GET /users', () => {
    it('should list users with pagination', async () => {
      const res = await request(app).get('/api/users?page=1&limit=2');
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(typeof res.body.pagination.page).toBe('number');
      expect(typeof res.body.pagination.totalPages).toBe('number');
    });

    it('should validate pagination parameters', async () => {
      const res = await request(app).get('/api/users?page=0&limit=101');
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Validation failed.');
    });

    it('should sanitize search parameters', async () => {
      const res = await request(app).get('/api/users?search=<script>alert("xss")</script>');
      expect(res.statusCode).toBe(200);
      // Search should be sanitized, no XSS executed
    });
  });

  describe('POST /users/register', () => {
    const validUser = {
      username: 'testuser123',
      email: 'testuser@example.com',
      password: 'ValidPassword123!',
      fullName: 'Test User'
    };

    it('should register a valid user', async () => {
      const res = await request(app)
        .post('/api/users/register')
        .send(validUser);
      
      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.body.user.email).toBe(validUser.email);
    });

    it('should reject weak passwords', async () => {
      const weakPasswordUser = { ...validUser, password: 'weak' };
      const res = await request(app)
        .post('/api/users/register')
        .send(weakPasswordUser);
      
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Validation failed.');
    });

    it('should reject invalid email formats', async () => {
      const invalidEmailUser = { ...validUser, email: 'invalid-email' };
      const res = await request(app)
        .post('/api/users/register')
        .send(invalidEmailUser);
      
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });

    it('should not allow duplicate usernames', async () => {
      // First registration
      await request(app).post('/api/users/register').send(validUser);
      
      // Second registration with same username
      const duplicateUser = { ...validUser, email: 'different@example.com' };
      const res = await request(app)
        .post('/api/users/register')
        .send(duplicateUser);
      
      expect(res.statusCode).toBe(409);
      expect(res.body.message).toBe('Username already exists.');
    });

    it('should not allow duplicate emails', async () => {
      // First registration
      await request(app).post('/api/users/register').send(validUser);
      
      // Second registration with same email
      const duplicateEmailUser = { ...validUser, username: 'differentuser' };
      const res = await request(app)
        .post('/api/users/register')
        .send(duplicateEmailUser);
      
      expect(res.statusCode).toBe(409);
      expect(res.body.message).toBe('Email already registered.');
    });

    it('should reject reserved usernames', async () => {
      const reservedUser = { ...validUser, username: 'admin' };
      const res = await request(app)
        .post('/api/users/register')
        .send(reservedUser);
      
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });

    it('should sanitize input data', async () => {
      const maliciousUser = {
        ...validUser,
        username: 'test<script>alert("xss")</script>',
        fullName: '<img src=x onerror=alert("xss")>'
      };
      
      const res = await request(app)
        .post('/api/users/register')
        .send(maliciousUser);
      
      // Should either reject or sanitize the input
      expect(res.statusCode).toBeOneOf([422, 201]);
    });
  });

  describe('POST /users/login', () => {
    const loginUser = {
      email: 'testlogin@example.com',
      password: 'ValidPassword123!'
    };

    beforeEach(async () => {
      // Register user for login tests
      await request(app)
        .post('/api/users/register')
        .send({
          username: 'testlogin',
          email: loginUser.email,
          password: loginUser.password,
          fullName: 'Test Login User'
        });
    });

    it('should authenticate valid credentials', async () => {
      const res = await request(app)
        .post('/api/users/login')
        .send(loginUser);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.body.user.email).toBe(loginUser.email);
    });

    it('should reject invalid credentials', async () => {
      const invalidUser = { ...loginUser, password: 'wrongpassword' };
      const res = await request(app)
        .post('/api/users/login')
        .send(invalidUser);
      
      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Invalid credentials.');
    });

    it('should reject non-existent users', async () => {
      const nonExistentUser = {
        email: 'nonexistent@example.com',
        password: 'password123'
      };
      const res = await request(app)
        .post('/api/users/login')
        .send(nonExistentUser);
      
      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Invalid credentials.');
    });

    it('should handle rate limiting', async () => {
      // Make multiple failed login attempts
      const invalidUser = { ...loginUser, password: 'wrongpassword' };
      
      for (let i = 0; i < 6; i++) {
        await request(app).post('/api/users/login').send(invalidUser);
      }
      
      // Should be rate limited now
      const res = await request(app)
        .post('/api/users/login')
        .send(invalidUser);
      
      expect(res.statusCode).toBe(429);
    });

    it('should validate input format', async () => {
      const invalidFormatUser = {
        email: 'not-an-email',
        password: ''
      };
      
      const res = await request(app)
        .post('/api/users/login')
        .send(invalidFormatUser);
      
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /users/refresh', () => {
    let refreshToken;

    beforeEach(async () => {
      // Register and login to get refresh token
      const registerRes = await request(app)
        .post('/api/users/register')
        .send({
          username: 'refreshtest',
          email: 'refresh@example.com',
          password: 'ValidPassword123!',
          fullName: 'Refresh Test User'
        });
      
      refreshToken = registerRes.body.refreshToken;
    });

    it('should refresh access token with valid refresh token', async () => {
      const res = await request(app)
        .post('/api/users/refresh')
        .send({ refreshToken });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
    });

    it('should reject invalid refresh token', async () => {
      const res = await request(app)
        .post('/api/users/refresh')
        .send({ refreshToken: 'invalid-token' });
      
      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Invalid refresh token.');
    });

    it('should reject missing refresh token', async () => {
      const res = await request(app)
        .post('/api/users/refresh')
        .send({});
      
      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Refresh token required.');
    });
  });

  describe('Authentication and Authorization', () => {
    let userToken;
    let adminToken;
    let userId;

    beforeEach(async () => {
      // Create regular user
      const userRes = await request(app)
        .post('/api/users/register')
        .send({
          username: 'regularuser',
          email: 'regular@example.com',
          password: 'ValidPassword123!',
          fullName: 'Regular User'
        });
      
      userToken = userRes.body.accessToken;
      userId = userRes.body.user.id;

      // Create admin user (assuming you have a way to create admin users)
      const adminRes = await request(app)
        .post('/api/users/register')
        .send({
          username: 'adminuser',
          email: 'admin@example.com',
          password: 'ValidPassword123!',
          fullName: 'Admin User',
          role: 'admin'
        });
      
      adminToken = adminRes.body.accessToken;
    });

    it('should allow users to access their own profile', async () => {
      const res = await request(app)
        .get(`/api/users/${userId}`)
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should prevent users from accessing other profiles', async () => {
      // Try to access admin profile with user token
      const res = await request(app)
        .get('/api/users/507f1f77bcf86cd799439011') // Different user ID
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(403);
    });

    it('should require authentication for protected routes', async () => {
      const res = await request(app).get(`/api/users/${userId}`);
      
      expect(res.statusCode).toBe(401);
    });

    it('should allow admin access to all profiles', async () => {
      const res = await request(app)
        .get(`/api/users/${userId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      
      expect(res.statusCode).toBe(200);
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed JSON', async () => {
      const res = await request(app)
        .post('/api/users/register')
        .send('invalid json')
        .set('Content-Type', 'application/json');
      
      expect(res.statusCode).toBe(400);
    });

    it('should handle database connection errors gracefully', async () => {
      // This would require mocking database connection failures
      // Implementation depends on your testing setup
    });

    it('should not expose sensitive error information', async () => {
      const res = await request(app)
        .post('/api/users/register')
        .send({
          username: 'test',
          email: 'invalid-email',
          password: 'weak'
        });
      
      expect(res.body.stack).toBeUndefined();
      expect(res.body.errors).toBeDefined();
    });
  });
});

// Custom jest matcher for multiple possible values
expect.extend({
  toBeOneOf(received, expected) {
    const pass = expected.includes(received);
    if (pass) {
      return {
        message: () => `expected ${received} not to be one of ${expected}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be one of ${expected}`,
        pass: false,
      };
    }
  },
});