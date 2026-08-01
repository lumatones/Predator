import { test, expect } from '@playwright/test'

test.describe('Website — Hero landing page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
  })

  test('renders headline and CTA', async ({ page }) => {
    // Main headline
    await expect(page.locator('h1')).toContainText('основание')

    // CTA button to Players registry — use .first() because multiple
    // links match "реестр" (navbar, hero CTA, footer)
    const cta = page.getByRole('link', { name: /реестр/i }).first()
    await expect(cta).toBeVisible()
    await expect(cta).toHaveAttribute('href', '/players')
  })

  test('renders navigation links', async ({ page }) => {
    // Navbar links — scope to <nav> to avoid footer duplicates
    const navbar = page.getByRole('navigation')
    await expect(navbar.getByRole('link', { name: 'Реестр игроков' })).toBeVisible()
    await expect(navbar.getByRole('link', { name: 'Обновления' })).toBeVisible()
  })

  test('renders Evidence orb (interactive diagram)', async ({ page }) => {
    // The evidence orb is the signature interactive element
    const orb = page.locator('[aria-label*="Интерактивная карта"]')
    await expect(orb).toBeVisible()

    // Signal buttons exist
    await expect(page.getByRole('button', { name: /Файлы/ })).toBeVisible()
    await expect(page.getByRole('button', { name: /Память/ })).toBeVisible()
    await expect(page.getByRole('button', { name: /Поведение/ })).toBeVisible()
  })

  test('renders stats section', async ({ page }) => {
    // Stats cards below the hero
    await expect(page.getByText('Профили проверены')).toBeVisible()
    await expect(page.getByText('Серверы подключены')).toBeVisible()
    await expect(page.getByText('Проверки завершены')).toBeVisible()
    await expect(page.getByText('Сигналы риска')).toBeVisible()
  })

  test('renders three-step method section', async ({ page }) => {
    await expect(page.getByText('Собрать состояние')).toBeVisible()
    await expect(page.getByText('Сопоставить сигналы')).toBeVisible()
    await expect(page.getByText('Показать основания')).toBeVisible()
  })

  test('CTA for server operators links to login', async ({ page }) => {
    const loginLink = page.getByRole('link', { name: /доступ/i })
    await expect(loginLink).toBeVisible()
    await expect(loginLink).toHaveAttribute('href', '/login')
  })
})
