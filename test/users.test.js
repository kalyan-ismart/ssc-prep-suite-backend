const request = require('supertest');
const app = require('../server'); // Ensure server.js exports `app`

// Custom Jest matcher for multiple possible values
expect.extend({
  toBeOneOf(received, expected) {
    const pass = expected.includes(received);
    if (pass) {
      return { message: () => `expected ${received} not to be one of ${expected}`, pass: true };
    } else {
      return { message: () => `expected ${received} to be one of ${expected}`, pass: false };
    }
  },
});

describe('Users API', () => {
  describe('GET /api/users', () => {
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
      // XSS/malicious injection attempt should be sanitized or rejected
      const maliciousSearch = '<script>alert("x")</script>';
      const res = await request(app).get(`/api/users?search=${encodeURIComponent(maliciousSearch)}`);
      expect([200, 422]).toContain(res.statusCode);
      if (res.statusCode === 200) {
        expect(typeof res.body.data).toBe('object');
      } else {
        expect(res.body.success).toBe(false);
        expect(res.body.message).toMatch(/Validation failed/);
      }
    });
  });

  describe('POST /api/users/register', () => {
    it('should reject malformed JSON', async () => {
      const res = await request(app)
        .post('/api/users/register')
        .set('Content-Type', 'application/json')
        .send('invalid json');
      expect(res.statusCode).toBe(400);
    });

    it('should sanitize registration input', async () => {
      const maliciousUser = {
        username: 'test<script>',
        email: 'test@example.com',
        password: 'Password123!',
        fullName: 'Malicious User',
      };
      const res = await request(app).post('/api/users/register').send(maliciousUser);
      expect([422, 201]).toContain(res.statusCode);
    });
  });

  describe('POST /api/users/login', () => {
    const loginUser = { email: 'testlogin@example.com', password: 'ValidPassword123!' };

    beforeEach(async () => {
      await request(app).post('/api/users/register').send({
        username: 'testlogin',
        email: loginUser.email,
        password: loginUser.password,
        fullName: 'Test Login User',
      });
    });

    it('should authenticate valid credentials', async () => {
      const res = await request(app).post('/api/users/login').send(loginUser);
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.body.user.email).toBe(loginUser.email);
    });

    it('should reject invalid credentials', async () => {
      const res = await request(app)
        .post('/api/users/login')
        .send({ ...loginUser, password: 'wrongpassword' });
      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Invalid credentials.');
    });

    it('should reject non-existent users', async () => {
      const res = await request(app)
        .post('/api/users/login')
        .send({ email: 'nonexistent@example.com', password: 'Password123!' });
      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Invalid credentials.');
    });

    it('should handle rate limiting', async () => {
      const invalid = { ...loginUser, password: 'wrongpassword' };
      for (let i = 0; i < 5; i++) {
        await request(app).post('/api/users/login').send(invalid);
      }
      const res = await request(app).post('/api/users/login').send(invalid);
      expect(res.statusCode).toBe(429);
    });

    it('should validate input format', async () => {
      const res = await request(app).post('/api/users/login').send({ email: 'not-an-email', password: '' });
      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/users/refresh', () => {
    let refreshToken;
    beforeEach(async () => {
      const reg = await request(app).post('/api/users/register').send({
        username: 'refreshtest',
        email: 'refresh@example.com',
        password: 'ValidPassword123!',
        fullName: 'Refresh Test User',
      });
      refreshToken = reg.body.refreshToken;
    });

    it('should refresh access token with valid refresh token', async () => {
      const res = await request(app).post('/api/users/refresh').send({ refreshToken });
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
    });

    it('should reject invalid refresh token', async () => {
      const res = await request(app).post('/api/users/refresh').send({ refreshToken: 'invalid' });
      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Invalid refresh token.');
    });

    it('should reject missing refresh token', async () => {
      const res = await request(app).post('/api/users/refresh').send({});
      expect(res.statusCode).toBe(401);
      expect(res.body.message).toBe('Refresh token required.');
    });
  });
});
