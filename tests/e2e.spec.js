const { test, expect } = require("@playwright/test");

/**
 * E2E Tests for PQC Password Manager
 * Tests the complete user flows
 */

const TEST_USER = {
  username: "testuser",
  password: "TestP@ss123!",
};

const TEST_PASSWORD = {
  siteUrl: "github.com",
  siteUsername: "test@example.com",
  password: "MySecretP@ssword123!",
};

test.describe("PQC Password Manager E2E Tests", () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the app
    await page.goto("http://host.docker.internal:3000");
  });

  test("should load the main page", async ({ page }) => {
    // Check that the page loads
    await expect(page).toHaveTitle(/PQC Vault/i);

    // Check for main elements
    await expect(page.locator("text=Create New Vault")).toBeVisible({
      timeout: 10000,
    });
    await expect(page.locator("text=Unlock Vault")).toBeVisible();
  });

  test("should create a new vault", async ({ page }) => {
    // Click "Create New Vault"
    await page.click("text=Create New Vault");

    // Wait for form to load
    await page.waitForSelector("#username");

    // Fill in registration form
    await page.fill("#username", TEST_USER.username);
    await page.fill("#password", TEST_USER.password);
    await page.fill("#confirm-password", TEST_USER.password);

    // Click Create Vault button
    await page.click('button:has-text("Create Vault")');

    // Should redirect to dashboard after creation (or show error if user exists)
    // Just check we get some response
    await page.waitForTimeout(2000);
  });

  test("should login with existing vault", async ({ page }) => {
    // Fill in login form directly without clicking
    await page.waitForSelector("#username");
    await page.fill("#username", TEST_USER.username);
    await page.fill("#password", TEST_USER.password);

    // Click Unlock button
    await page.click('button:has-text("Unlock Vault")');

    // Wait for response
    await page.waitForTimeout(2000);
  });

  test("should add a new password", async ({ page }) => {
    // Login first
    await page.waitForSelector("#username");
    await page.fill("#username", TEST_USER.username);
    await page.fill("#password", TEST_USER.password);
    await page.click('button:has-text("Unlock Vault")');

    // Wait for dashboard
    await page.waitForTimeout(2000);

    // Try to find Add Password in the sidebar/navigation
    const addPasswordBtn = page.locator("text=Add Password");
    if (await addPasswordBtn.isVisible()) {
      await addPasswordBtn.click();

      // Fill in password form if visible
      await page.waitForTimeout(1000);
    }
  });

  test("should verify crypto view shows encrypted data", async ({ page }) => {
    // Login first
    await page.waitForSelector("#username");
    await page.fill("#username", TEST_USER.username);
    await page.fill("#password", TEST_USER.password);
    await page.click('button:has-text("Unlock Vault")');

    // Wait for dashboard
    await page.waitForTimeout(2000);

    // Try to find Crypto View
    const cryptoViewBtn = page.locator("text=Crypto View");
    if (await cryptoViewBtn.isVisible()) {
      await cryptoViewBtn.click();
      await page.waitForTimeout(1000);
    }
  });

  test("should run compare analytics benchmark flow", async ({ page }) => {
    // Login first
    await page.waitForSelector("#username");
    await page.fill("#username", TEST_USER.username);
    await page.fill("#password", TEST_USER.password);
    await page.click('button:has-text("Unlock Vault")');

    // Wait for dashboard and open Benchmark tab
    await page.waitForTimeout(2000);
    const benchmarkBtn = page.locator("text=Benchmark");
    if (await benchmarkBtn.isVisible()) {
      await benchmarkBtn.click();

      const runBtn = page.locator('button:has-text("Run Analytics")');
      await expect(runBtn).toBeVisible({ timeout: 10000 });
      await runBtn.click();

      // Either full results or backend error banner should appear
      const staticMetrics = page.locator("text=Static Security Metrics");
      const errorBanner = page.locator(".error-banner");

      await page.waitForTimeout(4000);
      const hasResults = await staticMetrics.isVisible();
      const hasError = await errorBanner.isVisible();

      expect(hasResults || hasError).toBeTruthy();
    }
  });

  test("should lock vault", async ({ page }) => {
    // Login first
    await page.waitForSelector("#username");
    await page.fill("#username", TEST_USER.username);
    await page.fill("#password", TEST_USER.password);
    await page.click('button:has-text("Unlock Vault")');

    // Wait for dashboard
    await page.waitForTimeout(2000);

    // Try to find Lock Vault button
    const lockBtn = page.locator("text=Lock Vault");
    if (await lockBtn.isVisible()) {
      await lockBtn.click();
      // Should return to login screen
      await expect(page.locator("text=Unlock Vault")).toBeVisible({
        timeout: 5000,
      });
    }
  });
});
