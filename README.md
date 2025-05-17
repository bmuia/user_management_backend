# User Management Backend API

This document describes the API endpoints for the user management backend, built with Django and REST Framework. This API provides the core functionalities for user registration, authentication, profile management, and administrative user control.

## Base URL

The base URL for all API endpoints is: `[Your Backend Base URL]` (e.g., `http://localhost:8000/` or `https://user-management-backend.example.com/`).

## Authentication

This API uses JWT (JSON Web Tokens) for authentication. Upon successful login (`POST /accounts/login/`), the API returns `access` and `refresh` tokens. The `access` token is used for authenticating subsequent requests by including it in the `Authorization` header as a Bearer token (e.g., `Authorization: Bearer <access_token>`). The `refresh` token is used to obtain a new `access` token when the current one expires (`POST /accounts/token/refresh/`).

## API Endpoints

### Accounts

* **`POST /accounts/pre-register/`**
    * **Description:** Registers a new user by creating a temporary record and sending a verification email to the provided address.
    * **Request Body:**
        ```json
        {
            "email": "user@example.com",
            "password": "secure_password",
            "password2": "secure_password"
        }
        ```
    * **Response (Success - 200 OK):**
        ```json
        {
            "message": "Verification email sent. Please check your inbox."
        }
        ```
    * **Response (Error - 400 Bad Request):** Returns validation errors.

* **`POST /accounts/verify-email/`**
    * **Description:** Verifies a user's email using a token received via email. Upon successful verification, the user account is activated.
    * **Request Body:**
        ```json
        {
            "token": "verification_token_from_email"
        }
        ```
    * **Response (Success - 200 OK or 201 Created):**
        ```json
        {
            "message": "Email successfully verified."
        }
        ```
        or
        ```json
        {
            "message": "Email verified and registration successful."
        }
        ```
    * **Response (Error - 400 Bad Request):** Returns errors for invalid or expired tokens.

* **`POST /accounts/login/`**
    * **Description:** Authenticates a user with their email and password. Returns `access` and `refresh` tokens upon successful authentication.
    * **Request Body:**
        ```json
        {
            "email": "user@example.com",
            "password": "secure_password"
        }
        ```
    * **Response (Success - 200 OK):**
        ```json
        {
            "access": "access_token",
            "refresh": "refresh_token"
        }
        ```
    * **Response (Error - 401 Unauthorized):** Invalid credentials.
    * **Response (Error - 403 Forbidden):** User account is inactive.

* **`POST /accounts/token/refresh/`**
    * **Description:** Exchanges a valid `refresh` token for a new `access` token. The `refresh` token can be provided in the request body or as a `refresh_token` cookie.
    * **Request Body (optional if cookie is used):**
        ```json
        {
            "refresh": "refresh_token"
        }
        ```
    * **Response (Success - 200 OK):**
        ```json
        {
            "access": "new_access_token"
        }
        ```
    * **Response (Error - 401 Unauthorized):** Invalid or blacklisted refresh token.

* **`POST /accounts/logout/`**
    * **Description:** Blacklists the provided `refresh` token, effectively logging the user out. Requires authentication.
    * **Request Body:**
        ```json
        {
            "refresh_token": "refresh_token_to_blacklist"
        }
        ```
    * **Response (Success - 200 OK):**
        ```json
        {
            "message": "Logout successful"
        }
        ```
    * **Response (Error - 400 Bad Request):** Refresh token is required or invalid.
    * **Authentication:** Requires a valid `access` token in the `Authorization` header.

* **`GET /accounts/me/`**
    * **Description:** Retrieves the profile information of the authenticated user.
    * **Response (Success - 200 OK):** Returns user profile data (e.g., email).
    * **Authentication:** Requires a valid `access` token in the `Authorization` header.

* **`PUT /accounts/me/`**
    * **Description:** Updates the profile information of the authenticated user.
    * **Request Body:** User profile data to update (e.g., `{"first_name": "New", "last_name": "Name"}`).
    * **Response (Success - 200 OK):** Returns the updated user profile data.
    * **Authentication:** Requires a valid `access` token in the `Authorization` header.

* **`DELETE /accounts/me/`**
    * **Description:** Deactivates the authenticated user's account.
    * **Response (Success - 204 No Content):** Account deactivated successfully.
    * **Authentication:** Requires a valid `access` token in the `Authorization` header.

### Admin

* **`GET /accounts/profiles/`**
    * **Description:** Lists all non-administrator user profiles. Requires administrator privileges.
    * **Response (Success - 200 OK):** Returns a list of user profile data.
    * **Response (Error - 403 Forbidden):** Permission denied (user is not an administrator).
    * **Authentication:** Requires a valid `access` token in the `Authorization` header and the user must be a staff member (`is_staff=True`).

* **`POST /accounts/admin/register/user/`**
    * **Description:** Creates a new user account by an administrator.
    * **Request Body:** User registration data (same as `POST /accounts/pre-register/`).
    * **Response (Success - 201 Created):**
        ```json
        {
            "message": "User Created"
        }
        ```
    * **Response (Error - 400 Bad Request):** Returns validation errors.
    * **Authentication:** Requires a valid `access` token in the `Authorization` header and the user must be a staff member (`is_staff=True`).

* **`PUT /accounts/admin/<user_id>/update/`**
    * **Description:** Updates the information of a specific user (identified by `user_id` in the URL) by an administrator.
    * **Request Body:** User data to update (e.g., `{"is_active": false, "is_staff": true}`).
    * **Response (Success - 200 OK):**
        ```json
        {
            "message": "User updated successfully."
        }
        ```
    * **Response (Error - 400 Bad Request):** Returns validation errors.
    * **Response (Error - 404 Not Found):** User with the given ID does not exist.
    * **Response (Error - 403 Forbidden):** Permission denied (user is not an administrator).
    * **Authentication:** Requires a valid `access` token in the `Authorization` header and the user must be a staff member (`is_staff=True`).

### Password Reset

* **`POST /accounts/reset-password/`**
    * **Description:** Initiates the password reset process by sending a reset link to the provided email address.
    * **Request Body:**
        ```json
        {
            "email": "user@example.com"
        }
        ```
    * **Response (Success - 200 OK):**
        ```json
        {
            "message": "Password reset email sent"
        }
        ```
    * **Response (Error - 404 Not Found):** User with this email does not exist.
    * **Response (Error - 400 Bad Request):** Email is required.

* **`POST /accounts/password-reset-confirm/`**
    * **Description:** Confirms the password reset using a token received via email and sets a new password for the user.
    * **Request Body:**
        ```json
        {
            "token": "reset_token_from_email",
            "new_password": "new_secure_password"
        }
        ```
    * **Response (Success - 200 OK):**
        ```json
        {
            "message": "Password reset successfully"
        }
        ```
    * **Response (Error - 400 Bad Request):** Invalid or expired token, or new password is required.

## Error Handling

The API returns standard HTTP status codes to indicate the outcome of requests. Error responses typically include a JSON body with a `detail` key or specific error messages related to the request.

## Further Notes

* Ensure that your frontend application correctly handles the authentication flow, including storing and sending JWT tokens.
* Implement appropriate error handling on the frontend to provide informative feedback to the user.
* Consider implementing rate limiting and other security measures to protect your API.