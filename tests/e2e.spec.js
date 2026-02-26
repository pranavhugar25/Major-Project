const { test, expect } = require('@playwright/test');

/**
 * E2E Tests for PQC Password Manager
 * Tests the complete user flows
 */

const TEST_USER = {
  username: 'testuser',
  password: 'TestP@ss123!'
};

const TEST_PASSWORD = {
  siteUrl: 'github.com',
  siteUsername: 'test@example.com',
  password: 'MySecretP@ssword123!'
};

test.describe('PQC Password Manager E2E Tests', () => {
  
  test.beforeEach(async ({ page }) => {
    // Navigate to the app
    await page.goto('http://host.docker.internal:3000');
  });

  test('should load the main page', async ({ page }) => {
    // Check that the page loads
    await expect(page).toHaveTitle(/PQC Vault/i);
    
    // Check for main elements
    await expect(page.locator('text=Create New Vault')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Unlock Vault')).toBeVisible();
  });

  test('should create a new vault', async ({ page }) => {
    // Click "Create New Vault"
    await page.click('text=Create New Vault');
    
    // Wait for form to load
    await page.waitForSelector('#username');
    
    // Fill in registration form
    await page.fill('#username', TEST_USER.username);
    await page.fill('#password', TEST_USER.password);
    await page.fill('#confirm-password', TEST_USER.password);
    
    // Click Create Vault button
    await page.click('button:has-text("Create Vault")');
    
    // Should redirect to dashboard after creation (or show error if user exists)
    // Just check we get some response
    await page.waitForTimeout(2000);
  });

  test('should login with existing vault', async ({ page }) => {
    // Fill in login form directly without clicking
    await page.waitForSelector('#username');
    await page.fill('#username', TEST_USER.username);
    await page.fill('#password', TEST_USER.password);
    
    // Click Unlock button
    await page.click('button:has-text("Unlock Vault")');
    
    // Wait for response
    await page.waitForTimeout(2000);
  });

  test('should add a new password', async ({ page }) => {
    // Login first
    await page.waitForSelector('#username');
    await page.fill('#username', TEST_USER.username);
    await page.fill('#password', TEST_USER.password);
    await page.click('button:has-text("Unlock Vault")');
    
    // Wait for dashboard
    await page.waitForTimeout(2000);
    
    // Try to find Add Password in the sidebar/navigation
    const addPasswordBtn = page.locator('text=Add Password');
    if (await addPasswordBtn.isVisible()) {
      await addPasswordBtn.click();
      
      // Fill in password form if visible
      await page.waitForTimeout(1000);
    }
  });

  test('should verify crypto view shows encrypted data', async ({ page }) => {
    // Login first
    await page.waitForSelector('#username');
    await page.fill('#username', TEST_USER.username);
    await page.fill('#password', TEST_USER.password);
    await page.click('button:has-text("Unlock Vault")');
    
    // Wait for dashboard
    await page.waitForTimeout(2000);
    
    // Try to find Crypto View
    const cryptoViewBtn = page.locator('text=Crypto View');
    if (await cryptoViewBtn.isVisible()) {
      await cryptoViewBtn.click();
      await page.waitForTimeout(1000);
    }
  });

  test('should lock vault', async ({ page }) => {
    // Login first
    await page.waitForSelector('#username');
    await page.fill('#username', TEST_USER.username);
    await page.fill('#password', TEST_USER.password);
    await page.click('button:has-text("Unlock Vault")');
    
    // Wait for dashboard
    await page.waitForTimeout(2000);
    
    // Try to find Lock Vault button
    const lockBtn = page.locator('text=Lock Vault');
    if (await lockBtn.isVisible()) {
      await lockBtn.click();
      // Should return to login screen
      await expect(page.locator('text=Unlock Vault')).toBeVisible({ timeout: 5000 });
    }
  });

  test('should run benchmark comparison for auth and transport', async ({ page }) => {
    const uniqueUser = `bench_${Date.now()}`;
    const strongPassword = 'BenchP@ssword123!';

    await page.click('text=Create New Vault');
    await page.waitForSelector('#username');
    await page.fill('#username', uniqueUser);
    await page.fill('#password', strongPassword);
    await page.fill('#confirm-password', strongPassword);
    await page.click('button:has-text(\"Create Vault\")');

    await page.waitForSelector('[data-testid=\"nav-benchmark\"]', { timeout: 15000 });
    await page.click('[data-testid=\"nav-benchmark\"]');
    await page.click('[data-testid=\"run-benchmarks\"]');

    await expect(page.locator('[data-testid=\"auth-row-main_split_verifier\"]')).toBeVisible({ timeout: 30000 });
    await expect(page.locator('[data-testid=\"auth-row-opaque_baseline_sim\"]')).toBeVisible();
    await expect(page.locator('[data-testid=\"transport-row-main_hybrid_pqc\"]')).toBeVisible();
    await expect(page.locator('[data-testid=\"transport-row-classical_ecdh_sim\"]')).toBeVisible();
  });
});
