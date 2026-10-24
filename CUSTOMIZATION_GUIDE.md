# DEVELOPER CUSTOMIZATION CHECKLIST (stkrfx)

Before deploying `backend/` to Render, configure the following environment variables in your Render Web Service dashboard.

## 1. Database Configuration

- **`DATABASE_URL`**: Your Neon PostgreSQL pooled or direct connection string.

## 2. JWT Secrets

- **`USER_JWT_SECRET`** and **`SUPER_JWT_SECRET`**: Generate two distinct random 64-character hexadecimal secrets.

  Generate each secret using the following command:

  ```bash
  openssl rand -hex 32
  ```

  Make sure both secrets are different.

## 3. Developer Account Setup

- **`SUPER_SETUP_SECRET`**: A secret passphrase used once with `POST /api/v1/super/setup` to create your Developer account.

## 4. Google Sheets Integration

- **`GOOGLE_SPREADSHEET_ID`**: The ID from your Google Sheet URL.

  Example URL:

  ```text
  https://docs.google.com/spreadsheets/d/<SPREADSHEET_ID>/edit
  ```

  Replace `<SPREADSHEET_ID>` with the actual ID of your Google Sheet.

- **`GOOGLE_SHEETS_CREDENTIALS_JSON`**: Paste the entire contents of your Google Cloud Service Account JSON file as a single-line string.

  **Important:** Share your Google Sheet with the `client_email` address specified in this JSON file.

## 5. Firebase Authentication

- **`FIREBASE_SERVICE_ACCOUNT_JSON`**: Paste the entire contents of your Firebase Admin SDK Service Account JSON file as a single-line string.

  This allows the backend to verify Android Firebase Phone Auth ID tokens.

## 6. Email OTP Configuration

- **`SMTP_EMAIL`**: Your Gmail address used to send email OTPs.

- **`SMTP_APP_PASSWORD`**: Your 16-character Google App Password used for sending 6-digit email OTPs.
