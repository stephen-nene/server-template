# server-template
- basic login Django server

# server-template
- basic login Django server

## Authentication API Endpoints

This server provides a set of RESTful API endpoints for user authentication and management. The base path for these endpoints is `/profile/`.

| Endpoint | Method | Description |
|---|---|---|
| `auth/signup` | `POST` | Registers a new user. Requires `email`, `username`, and `password`. |
| `auth/login` | `POST` | Logs in a user with `email` and `password`, returning JWT access and refresh tokens. |
| `auth/logout/` | `POST` | Logs out the user by blacklisting their refresh token. Requires a valid `refresh` token. |
| `auth/refresh` | `POST` | Refreshes an expired access token using a valid `refresh` token. |
| `auth/verify/` | `POST` | Verifies that an access token is still valid. |
| `auth/me` | `GET` | Retrieves the profile information for the currently authenticated user. |
| `auth/password-reset` | `POST` | Initiates the password reset process. Requires the user's `email`. |
| `auth/activate/resend` | `POST` | Resends the account activation email. Requires the user's `email`. |
| `auth/update-email` | `POST` | Allows a logged-in user to update their email address. Requires the `new_email`. |

### User Management

| Endpoint | Method | Description |
|---|---|---|
| `users/` | `GET` | Lists all users (admin only). |
| `users/<id>/` | `GET` | Retrieves a specific user's details (admin only). |

