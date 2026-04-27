# 401 Unauthorized Error - Troubleshooting Guide

## Quick Diagnosis

If you're getting a **401 error when trying to add/view passwords**, follow these steps:

### Step 1: Check Token Storage (30 seconds)

1. Open **Browser DevTools** (Press `F12`)
2. Go to **Application** → **Session Storage**
3. Look for `pqc_access_token` and `pqc_refresh_token`

**Expected:** Both tokens should be present after login  
**If missing:** Token wasn't stored → Go to **Fix #1** below

### Step 2: Check Token Expiry (30 seconds)

1. Open **Browser DevTools Console** (Press `F12` → **Console**)
2. Paste and run:
   ```javascript
   window.authDebug.fullDiagnosis()
   ```
3. Read the output

**Expected:** Shows token details and remaining time  
**If expired:** Token expired (15 min max) → Go to **Fix #2** below

### Step 3: Check Network Headers (1 minute)

1. Open **DevTools** → **Network** tab
2. Perform an action that fails (add password)
3. Click on the failed `/passwords/add` request
4. Go to **Headers** tab
5. Scroll to **Request Headers** section

**Expected:** You should see:
```
Authorization: Bearer eyJhbGciOi...
```

**If missing:** Header not being sent → Go to **Fix #3** below

---

## Fixes

### Fix #1: Token Not Stored After Login

**Problem:** Login succeeded but tokens weren't saved to sessionStorage

**Solution:**
1. **Check browser privacy settings:**
   - Some browsers block sessionStorage in private mode
   - Try in normal (non-private) mode

2. **Clear and retry:**
   ```javascript
   // In browser console:
   sessionStorage.clear();
   ```
   Then refresh page and login again

3. **Check for console errors:**
   - Open DevTools → **Console** tab
   - Look for any red error messages during login
   - Share those errors if none of above work

---

### Fix #2: Token Expired

**Problem:** Token has expired (max 15 minutes of inactivity)

**Solution:**
1. **Refresh the page:**
   ```
   Press Ctrl+R (Windows) or Cmd+R (Mac)
   ```

2. **If still expired after refresh, logout and login again:**
   ```javascript
   // In browser console:
   sessionStorage.clear();
   ```
   Then refresh and login again

**Note:** Token auto-refresh should happen, but if it fails, you'll need to login again.

---

### Fix #3: Authorization Header Not Being Sent

**Problem:** Token exists but isn't being added to requests

**Solution:**

1. **Check API base URL:**
   - Open browser console
   - Paste: `console.log(process.env.REACT_APP_API_URL)`
   - Should show: `http://localhost:5000/api`
   - If different or undefined, backend URL is wrong

2. **Verify interceptor is working:**
   ```javascript
   // In browser console:
   window.authDebug.checkTokenStorage();
   ```

3. **Check backend CORS headers:**
   - In Network tab, look for the failed request
   - Go to **Response Headers**
   - Look for `access-control-allow-headers`
   - Should include `Authorization`

   If CORS is blocking Authorization header, you'll see:
   ```
   Access to XMLHttpRequest has been blocked by CORS policy
   ```

---

## Advanced Debugging

### View Full Token Details

```javascript
// In browser console:
const token = sessionStorage.getItem('pqc_access_token');
console.log('Decoded token:', window.authDebug.decodeToken(token));
```

Expected output includes:
```javascript
{
  user_id: "12345...",
  exp: 1234567890,
  iat: 1234567890,
  type: "session",
  ...
}
```

### Check Backend Response

In Network tab, click failed request → **Response** tab. You should see error message:

- `"Missing authentication token"` → Token not in header
- `"Invalid token format"` → Wrong format (use `Bearer <token>`)
- `"Session expired"` → Token too old
- `"Invalid or expired token"` → Token validation failed

### Check Backend Logs

In the Flask backend terminal, look for auth validation logs:
```
werkzeug - INFO: POST /api/passwords/add 401
```

If you see this, check your `backend/.env` file for `SECRET_KEY`:
```bash
# Should either be set or use default
SECRET_KEY=your-secret-key
```

---

## If Nothing Works

1. **Full reset:**
   ```bash
   # Terminal 1: Stop backend (Ctrl+C)
   # Terminal 2: Stop frontend (Ctrl+C)
   
   # Clear data:
   rm -rf backend/instance  # Windows: rmdir backend\instance /s
   
   # Restart both:
   # Backend: python app.py
   # Frontend: npm start
   ```

2. **Restart browser:**
   - Close all tabs
   - Restart browser completely
   - Clear cache: Ctrl+Shift+Delete → Cookies and Cached Images

3. **Check ports:**
   - Backend should be on `http://localhost:5000`
   - Frontend should be on `http://localhost:3000`
   - Test backend: Visit `http://localhost:5000` in browser (should see JSON response)

4. **Post terminal output:** If none of the above work, run this and share output:
   ```javascript
   window.authDebug.fullDiagnosis()
   ```

---

## Still Stuck?

Share the output of:

1. Browser console at login time (any red errors?)
2. Result of `window.authDebug.fullDiagnosis()` 
3. Backend logs during the failed request
4. What exactly happens when you try to add a password:
   - What error message appears?
   - Does it attempt the request?
   - What's shown in Network tab?
