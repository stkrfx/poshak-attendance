# POSHAK GO BACKEND — LOCAL & RENDER API TESTING GUIDE

## 1. Prerequisites

1. Install the **REST Client** extension (`humao.rest-client`) in Visual Studio Code.

2. Copy `.env.example` to `.env` inside `backend/`:

   ```bash
   cp .env.example .env
   ```

3. Fill in the following environment variables in your `.env` file:
   - `DATABASE_URL` (Neon PostgreSQL)
   - `USER_JWT_SECRET`
   - `SUPER_JWT_SECRET`
   - `SUPER_SETUP_SECRET`

4. Start the server:

   ```bash
   go run ./cmd/server
   ```

## 2. Step-by-Step Testing Order

### A. Admin API Testing

1. Open `api_tests/admin.http`.

2. Click **Send Request** on Step 1 (`POST /api/v1/super/setup`) to create your Developer account in the `super_users` table.

3. Click **Send Request** on Step 2 (`POST /api/v1/super/login`) and copy the `super_token` value into `@superToken` at the top of `admin.http`.

4. Click **Send Request** on Step 3 (`POST /api/v1/super/users`) to create an employee whose name matches Column A of your Google Sheet (e.g., `Sajan 2`).

5. Click **Send Request** on Step 5 (`POST /api/v1/super/attendance/sync`) to pull the employee's attendance from Google Sheets.

### B. User API Testing

1. Open `api_tests/user.http`.

2. Click **Send Request** on Step 3 (`POST /api/v1/auth/login`) using the employee's credentials:
   - **Mobile number:** `9876543210`
   - **Password:** `EmployeePass123`

3. Copy the following values from the JSON response into the corresponding variables at the top of `user.http`:
   - `access_token` → `@accessToken`
   - `refresh_token` → `@refreshToken`
   - `session_id` → `@sessionId`

4. Run Steps 4 through 19 to verify the following features:
   - One-time DOB locking
   - Email OTP verification
   - Attendance calendar retrieval
   - Document uploads
   - Multi-device session logout
