# SecureAPI

SecureAPI is a Python-based REST API template built with Flask, designed with security in mind. It includes built-in security headers, input validation, rate limiting, and secure password hashing to serve as a foundation for secure web applications. This guide explains how to set up, run, and use the API.

## 📋 Features

- **Security Headers**: Includes CSP, HSTS, X-Frame-Options, and more to protect against common web attacks.
- **Input Validation**: Sanitizes inputs to prevent XSS and injection attacks.
- **Rate Limiting**: Prevents abuse with configurable request limits.
- **Secure Authentication**: Uses hashed passwords for user authentication.
- **Logging**: Tracks requests and errors for monitoring and debugging.

## 🛠️ Prerequisites

- **Python 3.6+** installed on your system.
- A working internet connection for dependency installation.
- Basic knowledge of command-line interfaces and HTTP requests.
- (Optional) A tool like `curl` or Postman for testing API endpoints.

## 🚀 Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/liamcarter0111/SecureAPI.git
   cd SecureAPI
   ```

2. **Install Dependencies**:
   The API requires Flask, Flask-Limiter, and Werkzeug. Install them using pip:
   ```bash
   pip install flask flask-limiter werkzeug
   ```

3. **Verify Setup**:
   Ensure the script is ready to run:
   ```bash
   python3 app.py --help
   ```

## 🏃‍♂️ Running the API

1. **Start the API**:
   Run the Flask application with an ad-hoc SSL context for HTTPS:
   ```bash
   python3 app.py
   ```

   The API will be available at `https://0.0.0.0:5000`. Note: The ad-hoc SSL is for development only; use a proper certificate in production.

2. **Access the Health Check**:
   Verify the API is running:
   ```bash
   curl https://localhost:5000/api/v1/health --insecure
   ```

   Expected Response:
   ```json
   {"status": "API is running"}
   ```

## 📡 API Endpoints

### 1. Health Check
- **URL**: `/api/v1/health`
- **Method**: GET
- **Description**: Checks if the API is running.
- **Example**:
  ```bash
  curl https://localhost:5000/api/v1/health --insecure
  ```
- **Response**:
  ```json
  {"status": "API is running"}
  ```

### 2. Login
- **URL**: `/api/v1/login`
- **Method**: POST
- **Description**: Authenticates a user with username and password.
- **Rate Limit**: 5 requests per minute.
- **Request Body**:
  ```json
  {
    "username": "admin",
    "password": "securepassword123"
  }
  ```
- **Example**:
  ```bash
  curl -X POST https://localhost:5000/api/v1/login --insecure -H "Content-Type: application/json" -d '{"username":"admin","password":"securepassword123"}'
  ```
- **Success Response**:
  ```json
  {"message": "Login successful", "token": "dummy-jwt-token"}
  ```
- **Error Response**:
  ```json
  {"error": "Invalid credentials"}
  ```

### 3. Create User
- **URL**: `/api/v1/user`
- **Method**: POST
- **Description**: Creates a new user with a username and password.
- **Rate Limit**: 10 requests per minute.
- **Request Body**:
  ```json
  {
    "username": "newuser",
    "password": "mypassword123"
  }
  ```
- **Constraints**:
  - Username: 3-20 characters, alphanumeric and underscores only.
  - Password: No specific constraints (add your own in production).
- **Example**:
  ```bash
  curl -X POST https://localhost:5000/api/v1/user --insecure -H "Content-Type: application/json" -d '{"username":"newuser","password":"mypassword123"}'
  ```
- **Success Response**:
  ```json
  {"message": "User newuser created successfully"}
  ```
- **Error Response**:
  ```json
  {"error": "Username already exists"}
  ```

## 🔒 Security Features

- **Content-Security-Policy (CSP)**: Restricts resources to trusted sources.
- **Strict-Transport-Security (HSTS)**: Enforces HTTPS connections.
- **X-Frame-Options**: Prevents clickjacking.
- **Input Sanitization**: Strips dangerous characters to mitigate XSS and injection.
- **Rate Limiting**: Protects against brute-force and DoS attacks.
- **Password Hashing**: Uses Werkzeug’s secure hashing for passwords.

## ⚠️ Important Notes

- **Development Only**: The ad-hoc SSL context is not suitable for production. Use a proper SSL certificate (e.g., Let’s Encrypt) in production.
- **In-Memory Database**: User data is stored in memory for demo purposes. Use a persistent database (e.g., SQLite, PostgreSQL) in production.
- **Rate Limits**: Adjust limits in `app.py` based on your needs.
- **Logging**: Check logs for debugging and monitoring security events.

## 🐛 Troubleshooting

- **Error: "Connection refused"**:
  - Ensure the API is running (`python3 app.py`).
  - Verify the port (5000) is not blocked by a firewall.
- **Error: "ModuleNotFoundError"**:
  - Install dependencies: `pip install flask flask-limiter werkzeug`.
- **Error: "SSL certificate verify failed"**:
  - Use `--insecure` with `curl` for development or configure a valid SSL certificate.

## 📬 Feedback

Found a bug or have a suggestion? Open an issue on the [GitHub repository](https://github.com/liamcarter0111/SecureAPI) or reach out at [liamcarter0111@outlook.com](mailto:liamcarter0111@outlook.com).

Secure your APIs and happy coding! 🔒
