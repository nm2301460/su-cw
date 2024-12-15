# TKH Student Union Backend

This is the backend server for the TKH Student Union website. It provides APIs for user authentication, comments, events, and store management.

## Features

- User authentication with JWT
- Comments management
- Events calendar
- Store items management
- Admin privileges
- SQLite database
- Security features (CORS, Helmet, Rate Limiting)

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a .env file with the following variables:
```
PORT=2526
FRONTEND_URL=http://localhost:3001
JWT_SECRET=your_jwt_secret_key_here
NODE_ENV=development
```

3. Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

## API Endpoints

### Authentication
- POST /auth/register - Register a new user
- POST /auth/login - Login user

### Comments
- GET /comments - Get all comments
- POST /comments - Create a new comment
- DELETE /comments/:id - Delete a comment (Admin only)

### Events
- GET /events - Get all events
- POST /events - Create a new event (Admin only)

### Store
- GET /store-items - Get all available store items
- POST /store-items - Add a new store item (Admin only)
- DELETE /store-items/:id - Remove a store item (Admin only)

## Security

The backend implements several security measures:
- JWT for authentication
- HTTP-only cookies
- CORS configuration
- Rate limiting
- Helmet for HTTP headers
- Password hashing
- Input validation

## Database

Uses SQLite3 with the following tables:
- students
- comments
- events
- store_items
