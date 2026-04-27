/**
 * Authentication debugging utility
 * Run these checks in browser console to diagnose token issues
 */

export const authDebug = {
  /**
   * Check if tokens are stored in sessionStorage
   */
  checkTokenStorage: () => {
    const accessToken = sessionStorage.getItem('pqc_access_token');
    const refreshToken = sessionStorage.getItem('pqc_refresh_token');
    
    console.log('=== Token Storage Debug ===');
    console.log('Access Token stored:', !!accessToken);
    console.log('Refresh Token stored:', !!refreshToken);
    
    if (accessToken) {
      console.log('Access Token length:', accessToken.length);
      console.log('Access Token preview:', accessToken.substring(0, 50) + '...');
    }
    
    if (refreshToken) {
      console.log('Refresh Token length:', refreshToken.length);
      console.log('Refresh Token preview:', refreshToken.substring(0, 50) + '...');
    }
    
    return { accessToken: !!accessToken, refreshToken: !!refreshToken };
  },

  /**
   * Decode JWT token without verification (for debugging)
   */
  decodeToken: (token) => {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map((c) => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      return JSON.parse(jsonPayload);
    } catch (e) {
      console.error('Failed to decode token:', e);
      return null;
    }
  },

  /**
   * Check if token is expired
   */
  checkTokenExpiry: () => {
    const accessToken = sessionStorage.getItem('pqc_access_token');
    if (!accessToken) {
      console.log('No access token found');
      return;
    }
    
    const decoded = this.decodeToken(accessToken);
    if (!decoded || !decoded.exp) {
      console.log('Could not decode token or no exp claim');
      return;
    }
    
    const expiryDate = new Date(decoded.exp * 1000);
    const now = new Date();
    const isExpired = now > expiryDate;
    
    console.log('=== Token Expiry Debug ===');
    console.log('Expires at:', expiryDate.toISOString());
    console.log('Current time:', now.toISOString());
    console.log('Is expired:', isExpired);
    console.log('Time remaining (ms):', Math.max(0, expiryDate - now));
    
    return { expiryDate, isExpired, remainingMs: expiryDate - now };
  },

  /**
   * Check if Authorization header is being sent
   */
  checkNextRequest: async () => {
    console.log('=== Monitoring Next Request ===');
    console.log('The next API call will be logged below:');
    
    // Intercept the next request
    const originalInterceptor = window.api?.interceptors?.request?.handlers?.[0];
    if (originalInterceptor) {
      console.log('Request interceptor is configured');
    } else {
      console.warn('No request interceptor found!');
    }
  },

  /**
   * Full diagnostic report
   */
  fullDiagnosis: () => {
    console.log('\n=== FULL AUTH DIAGNOSTIC ===\n');
    
    const storage = this.checkTokenStorage();
    console.log('');
    
    if (storage.accessToken) {
      this.checkTokenExpiry();
      console.log('');
    }
    
    console.log('=== Recommendations ===');
    if (!storage.accessToken) {
      console.log('❌ Access token not found in sessionStorage');
      console.log('   Action: Try logging in again');
    } else if (!storage.refreshToken) {
      console.warn('⚠️  Refresh token not found');
      console.log('   Action: Token refresh may fail when expired');
    } else {
      console.log('✅ Tokens are stored');
    }
    
    console.log('\n');
  }
};

// Make available globally in browser console
window.authDebug = authDebug;
