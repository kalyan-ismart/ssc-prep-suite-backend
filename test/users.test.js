const request = require('supertest');
const app = require('../server'); // Make sure you export app in server.js

describe('Users API', () => {
  it('should list users with pagination', async () => {
    const res = await request(app).get('/users?page=1&limit=2');
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(typeof res.body.page).toBe('number');
    expect(typeof res.body.pages).toBe('number');
  });

  it('should not add duplicate user', async () => {
    const user = {
      username: 'testuser',
      email: 'testuser@example.com',
      password: 'password123'
    };
    await request(app).post('/users/add').send(user);
    const res = await request(app).post('/users/add').send(user);
    expect(res.statusCode).toBe(409); // Should be conflict on duplicate
  });
});