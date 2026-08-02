import { test, expect } from '@playwright/test'

test.describe('Admin — Login page', () => {
  // NOTE: These tests assume the API server (localhost:3001) is NOT running.
  // If the server is up, the login flow will redirect on success instead
  // of showing an error. Use page.route() in CI to stub the fetch if needed.
  test.use({ baseURL: 'http://localhost:5173' })

  test.beforeEach(async ({ page }) => {
    await page.goto('/')
  })

  test('renders login form', async ({ page }) => {
    // Logo / title
    await expect(page.locator('h1')).toContainText('Predator')

    // Subtitle
    await expect(page.getByText('Панель администратора')).toBeVisible()

    // Form fields
    await expect(page.getByLabel('Логин')).toBeVisible()
    await expect(page.getByLabel('Пароль')).toBeVisible()

    // Submit button
    await expect(page.getByRole('button', { name: 'Войти' })).toBeVisible()
  })

  test('shows validation error on empty submit', async ({ page }) => {
    // Click submit without filling fields
    await page.getByRole('button', { name: 'Войти' }).click()

    // Error message should appear
    await expect(page.getByRole('alert')).toContainText('логин')
  })

  test('shows error after submitting credentials (no backend)', async ({ page }) => {
    // Fill in credentials
    await page.getByLabel('Логин').fill('admin')
    await page.getByLabel('Пароль').fill('wrong-password')

    // Click submit
    await page.getByRole('button', { name: 'Войти' }).click()

    // An error alert must appear (server unreachable in e2e context).
    // Loading state "Вход..." may flash too fast to catch — accept either outcome.
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 15_000 })
  })

  test('login form has autofocus on username', async ({ page }) => {
    const usernameInput = page.getByLabel('Логин')
    await expect(usernameInput).toBeFocused()
  })

  test('typing clears error message', async ({ page }) => {
    // Trigger error first
    await page.getByRole('button', { name: 'Войти' }).click()
    await expect(page.getByRole('alert')).toBeVisible()

    // Type in username — error should clear
    await page.getByLabel('Логин').fill('a')
    await expect(page.getByRole('alert')).not.toBeVisible()
  })
})
