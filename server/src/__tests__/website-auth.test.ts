/**
 * Regression tests for the public Website auth routes.
 * Database calls are mocked; no MySQL is required.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import request from 'supertest'
import {
  createWebsiteTestApp,
  mockBcryptCompare,
  mockQuery,
} from './test-helper'

let app: any

beforeEach(async () => {
  app = await createWebsiteTestApp()
  mockBcryptCompare(true)
})

describe('POST /api/website/auth/register', () => {
  it('returns 409 when the email is already registered', async () => {
    mockQuery.mockResolvedValueOnce([{ id: 11 }])

    const response = await request(app)
      .post('/api/website/auth/register')
      .send({
        email: 'existing@example.com',
        password: 'valid-test-password',
        display_name: 'Existing user',
      })

    expect(response.status).toBe(409)
    expect(response.body.error.code).toBe('CONFLICT')
    expect(response.body.error.message).toBe('Email already registered')
  })
})

describe('POST /api/website/auth/login', () => {
  it('returns 401 instead of 500 when a legacy user has no password hash', async () => {
    mockQuery.mockResolvedValueOnce([{
      id: 7,
      password_hash: null,
      display_name: 'Legacy user',
      avatar_url: null,
      subscription: 'free',
    }])

    const response = await request(app)
      .post('/api/website/auth/login')
      .send({ email: 'legacy@example.com', password: 'valid-test-password' })

    expect(response.status).toBe(401)
    expect(response.body.error.code).toBe('UNAUTHORIZED')
    expect(response.body.error.message).toBe('Invalid credentials')
  })

  it('returns 401 instead of 500 when the stored password hash is corrupted', async () => {
    const bcrypt = await import('bcryptjs')
    vi.mocked(bcrypt.default.compare).mockRejectedValueOnce(new Error('Invalid hash'))
    mockQuery.mockResolvedValueOnce([{
      id: 8,
      password_hash: 'not-a-bcrypt-hash',
      display_name: 'Corrupt user',
      avatar_url: null,
      subscription: 'free',
    }])

    const response = await request(app)
      .post('/api/website/auth/login')
      .send({ email: 'corrupt@example.com', password: 'valid-test-password' })

    expect(response.status).toBe(401)
    expect(response.body.error.code).toBe('UNAUTHORIZED')
  })

  it('returns a token for a valid password hash', async () => {
    mockQuery.mockResolvedValueOnce([{
      id: 9,
      password_hash: '$2a$10$valid-test-hash',
      display_name: 'Website user',
      avatar_url: null,
      subscription: 'free',
    }])

    const response = await request(app)
      .post('/api/website/auth/login')
      .send({ email: ' USER@EXAMPLE.COM ', password: 'valid-test-password' })

    expect(response.status).toBe(200)
    expect(response.body.token).toEqual(expect.any(String))
    expect(response.body.user.display_name).toBe('Website user')
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('FROM website_users WHERE email = ?'),
      ['user@example.com'],
    )
  })
})
