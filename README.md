Auth System API

A robust backend authentication system built with Python and Flask. This project demonstrates secure user registration, token-based authentication, and best practices for protecting API endpoints.
🚀 Features

LIVE RENDER DEPLOYMENT - https://auth-system-3aan.onrender.com/auth/

    User Registration: Secure password hashing using Werkzeug.

    JWT Authentication: Stateless authentication using JSON Web Tokens.

    Rate Limiting: Protection against brute-force attacks.

    Environment Safety: Secure management of API keys and secrets.


🛠 Tech Stack

    Language: Python 3.x

    Framework: Flask

    Database: SQLite (Development) / PostgreSQL (Production)

    Deployment: Render


## 📸 System Walkthrough

### 1️⃣ /register route
Testing user registration 
![Registration](assets/Screenshot%20from%202026-04-24%2020-35-47.png)

### 2️⃣ /register route
Testing bad request 
![registration](assets/Screenshot%20from%202026-04-24%2020-36-43.png)

### 3️⃣ /register route
Testing rate limiter for preventing brute force attacks
![Architecture](assets/Screenshot%20from%202026-04-24%2020-37-15.png)

### 4️⃣ /login route
User login for acquiring access and refresh token
![Routes](assets/Screenshot%20from%202026-04-24%2020-37-50.png)

### 5️⃣ /refresh route
Getting a new access token using a refresh token
![Security](assets/Screenshot%20from%202026-04-24%2020-38-47.png)

### 6️⃣ /logout route
Logging out and token revoked 
![Deployment](assets/Screenshot%20from%202026-04-24%2020-39-14.png)

