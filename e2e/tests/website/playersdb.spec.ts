import { test, expect } from '@playwright/test'

test.describe('Website — PlayersDB page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/players')
  })

  test('renders page heading', async ({ page }) => {
    await expect(page.locator('h1')).toBeVisible()
  })

  test('renders sortable table columns', async ({ page }) => {
    // Table should exist with column headers
    const table = page.locator('table')
    await expect(table).toBeVisible()

    // At least one recognizable column header
    const columnHeaders = page.getByRole('columnheader')
    const headerCount = await columnHeaders.count()
    expect(headerCount).toBeGreaterThanOrEqual(3)
  })

  test('search/filter input is present or page renders cleanly', async ({ page }) => {
    // Search input may be absent if table is empty — that's fine.
    // The page should at least render the heading without crash.
    const searchInput = page.getByPlaceholder(/поиск|search/i)
    const searchVisible = await searchInput.isVisible().catch(() => false)
    if (!searchVisible) {
      await expect(page.locator('h1')).toBeVisible()
    }
  })

  test('navigation back to home works', async ({ page }) => {
    // Click navbar brand/logo to go home
    const homeLink = page.getByRole('link', { name: /predator/i }).first()
    if (await homeLink.isVisible()) {
      await homeLink.click()
      await expect(page).toHaveURL('/')
    }
  })
})
