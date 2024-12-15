require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

// Initialize Express Server
const server = express();
const port = process.env.PORT || 2526;

// Database Connection
const db = new sqlite3.Database('tkh_student_union.db');

// Middleware
server.use(express.json());
server.use(cookieParser());
server.use(cors({
    origin: 'http://localhost:3001',
    credentials: true
}));

// Basic security middleware
server.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
server.use(morgan('dev'));

// Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

// Token Generation
const generateToken = (id, isAdmin) => {
    return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET || 'fallback_secret_key', { 
        expiresIn: '1h',
        algorithm: 'HS256'
    });
};

// Token Verification Middleware
const verifyToken = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key');
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// Admin Privilege Middleware
const requireAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
    next();
};

// Admin middleware to check if user is admin
const isAdmin = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: 'Forbidden - Admin access required' });
    }
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized - Invalid token' });
  }
};

// Database Initialization
const initializeDatabase = () => {
    db.serialize(() => {
        // Drop existing tables if they exist
        db.run("DROP TABLE IF EXISTS item_feedback");
        db.run("DROP TABLE IF EXISTS store_items");
        db.run("DROP TABLE IF EXISTS events");
        db.run("DROP TABLE IF EXISTS students");
        db.run("DROP TABLE IF EXISTS comments");
        db.run("DROP TABLE IF EXISTS transactions");
        db.run("DROP TABLE IF EXISTS transaction_items");

        // Create tables with proper schema
        db.run(`
            CREATE TABLE students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                isAdmin INTEGER DEFAULT 0,
                profilePicture TEXT,
                bio TEXT,
                major TEXT,
                graduationYear INTEGER,
                interests TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        db.run(`
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                date DATE NOT NULL,
                time TIME NOT NULL,
                location TEXT NOT NULL,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES students(id)
            )
        `);

        db.run(`
            CREATE TABLE store_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL,
                category TEXT NOT NULL,
                imageUrl TEXT NOT NULL,
                stock INTEGER DEFAULT 0,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES students(id)
            )
        `);

        db.run(`
            CREATE TABLE item_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                comment TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (item_id) REFERENCES store_items(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES students(id) ON DELETE CASCADE
            )
        `);

        db.run(`
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                studentId INTEGER NOT NULL,
                date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (studentId) REFERENCES students(id) ON DELETE CASCADE
            )
        `);

        db.run(`
            CREATE TABLE transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES students(id) ON DELETE CASCADE
            )
        `);

        db.run(`
            CREATE TABLE transaction_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
                FOREIGN KEY (item_id) REFERENCES store_items(id) ON DELETE CASCADE
            )
        `);

        // Insert default admin user
        const defaultAdminPassword = bcrypt.hashSync('admin123', 12);
        db.run(`
            INSERT INTO students (name, email, password, isAdmin)
            VALUES (?, ?, ?, ?)
        `, ['Admin User', 'admin@tkh.edu', defaultAdminPassword, 1]);
    });
};

// Initialize database on server start
initializeDatabase();

// Auth Routes
server.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM students WHERE email = ?', [email], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate token
        const token = generateToken(user.id, user.isAdmin === 1);
        
        // Set cookie
        res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 3600000 // 1 hour
        });

        res.json({
            success: true,
            userId: user.id,
            isAdmin: user.isAdmin === 1
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

server.post('/api/auth/logout', (req, res) => {
    res.clearCookie('authToken');
    res.json({ success: true });
});

server.post('/auth/register', [
    body('name').trim().isLength({ min: 2 }),
    body('email').isEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    try {
        // Validation
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        const { name, email, password, isAdmin } = req.body;

        // Check if email exists
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM students WHERE email = ?', [email], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Insert new user
        const userId = await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO students (name, email, password, isAdmin) VALUES (?, ?, ?, ?)',
                [name, email, hashedPassword, isAdmin ? 1 : 0],
                function(err) {
                    if (err) reject(err);
                    resolve(this.lastID);
                }
            );
        });

        // Generate token
        const token = generateToken(userId, isAdmin);
        
        // Set cookie
        res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000 // 1 hour
        });

        // Send response
        res.status(201).json({
            success: true,
            message: 'Registration successful',
            userId: userId,
            isAdmin: isAdmin ? true : false
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

server.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        db.get('SELECT * FROM students WHERE email = ?', [email], async (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = generateToken(user.id, user.isAdmin === 1);
            
            res.cookie('authToken', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 3600000
            });

            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    isAdmin: user.isAdmin === 1
                }
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Comments Routes
server.get('/api/comments', async (req, res) => {
    try {
        const comments = await new Promise((resolve, reject) => {
            db.all(
                `SELECT c.*, s.name as userName 
                FROM comments c 
                LEFT JOIN students s ON c.studentId = s.id 
                ORDER BY c.date DESC`,
                [],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json({ success: true, comments });
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: 'Could not fetch comments' });
    }
});

server.post('/api/comments', verifyToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content || content.trim() === '') {
            return res.status(400).json({ error: 'Comment content is required' });
        }

        const result = await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO comments (content, studentId) VALUES (?, ?)',
                [content.trim(), req.user.id],
                function(err) {
                    if (err) reject(err);
                    resolve(this.lastID);
                }
            );
        });

        res.status(201).json({
            success: true,
            message: 'Comment posted successfully',
            commentId: result
        });
    } catch (error) {
        console.error('Error posting comment:', error);
        res.status(500).json({ error: 'Failed to post comment' });
    }
});

server.delete('/api/comments/:id', verifyToken, async (req, res) => {
    try {
        const { id: commentId } = req.params;
        
        // Check if user is admin or comment owner
        const comment = await new Promise((resolve, reject) => {
            db.get('SELECT studentId FROM comments WHERE id = ?', [commentId], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!comment) {
            return res.status(404).json({ error: 'Comment not found' });
        }

        if (!req.user.isAdmin && comment.studentId !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized to delete this comment' });
        }

        await new Promise((resolve, reject) => {
            db.run('DELETE FROM comments WHERE id = ?', [commentId], (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        res.json({
            success: true,
            message: 'Comment deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ error: 'Failed to delete comment' });
    }
});

// Events Routes
server.get('/events', (req, res) => {
    db.all('SELECT * FROM events ORDER BY date ASC', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Could not fetch events' });
        }
        res.json(rows);
    });
});

server.post('/events', verifyToken, requireAdmin, (req, res) => {
    const { title, description, location, date, createdBy } = req.body;

    db.run(
        'INSERT INTO events (title, description, location, date, createdBy) VALUES (?, ?, ?, ?, ?)',
        [title, description, location, date, createdBy],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to create event' });
            }
            res.status(201).json({
                message: 'Event created successfully',
                eventId: this.lastID
            });
        }
    );
});

// Admin Routes - Events
server.post('/api/events', isAdmin, [
  body('title').trim().notEmpty(),
  body('description').trim().notEmpty(),
  body('date').isDate(),
  body('time').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
  body('location').trim().notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { title, description, date, time, location } = req.body;
    
    const result = await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO events (title, description, date, time, location) VALUES (?, ?, ?, ?, ?)',
        [title, description, date, time, location],
        function(err) {
          if (err) reject(err);
          resolve(this.lastID);
        }
      );
    });

    res.status(201).json({ 
      message: 'Event created successfully',
      eventId: result
    });
  } catch (error) {
    console.error('Error creating event:', error);
    res.status(500).json({ error: 'Failed to create event' });
  }
});

server.get('/api/events', async (req, res) => {
  try {
    const events = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM events ORDER BY date ASC', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    res.json({ events });
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

server.delete('/api/events/:id', isAdmin, async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM events WHERE id = ?', [req.params.id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    res.json({ message: 'Event deleted successfully' });
  } catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).json({ error: 'Failed to delete event' });
  }
});

// Store Routes
server.get('/store-items', (req, res) => {
    const searchQuery = req.query.search || '';
    const query = searchQuery 
        ? 'SELECT * FROM store_items WHERE available = 1 AND (name LIKE ? OR description LIKE ? OR category LIKE ?)'
        : 'SELECT * FROM store_items WHERE available = 1';
    const params = searchQuery 
        ? [`%${searchQuery}%`, `%${searchQuery}%`, `%${searchQuery}%`]
        : [];

    db.all(query, params, (err, items) => {
        if (err) {
            return res.status(500).json({ error: 'Could not fetch store items' });
        }
        res.json(items);
    });
});

server.get('/store-items/:id/feedback', (req, res) => {
    const itemId = req.params.id;
    db.all(
        `SELECT f.*, s.name as user_name 
         FROM item_feedback f 
         JOIN students s ON f.user_id = s.id 
         WHERE f.item_id = ? 
         ORDER BY f.created_at DESC`,
        [itemId],
        (err, feedback) => {
            if (err) {
                return res.status(500).json({ error: 'Could not fetch feedback' });
            }
            res.json(feedback);
        }
    );
});

server.post('/store-items/:id/feedback', verifyToken, (req, res) => {
    const itemId = req.params.id;
    const { rating, comment } = req.body;
    const userId = req.user.id;

    db.serialize(() => {
        // Add the feedback
        db.run(
            'INSERT INTO item_feedback (item_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
            [itemId, userId, rating, comment],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to add feedback' });
                }

                // Update the item's average rating
                db.run(
                    `UPDATE store_items 
                     SET rating = (
                         SELECT AVG(rating) 
                         FROM item_feedback 
                         WHERE item_id = ?
                     ),
                     reviews_count = (
                         SELECT COUNT(*) 
                         FROM item_feedback 
                         WHERE item_id = ?
                     )
                     WHERE id = ?`,
                    [itemId, itemId, itemId],
                    (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Failed to update item rating' });
                        }
                        res.status(201).json({ message: 'Feedback added successfully' });
                    }
                );
            }
        );
    });
});

server.post('/store-items', verifyToken, requireAdmin, (req, res) => {
    const { name, description, price, category } = req.body;

    db.run(
        'INSERT INTO store_items (name, description, price, category, available) VALUES (?, ?, ?, ?, 1)',
        [name, description, price, category],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to add item' });
            }
            res.status(201).json({
                message: 'Item added successfully',
                itemId: this.lastID
            });
        }
    );
});

server.delete('/store-items/:id', verifyToken, requireAdmin, (req, res) => {
    const itemId = req.params.id;
    
    db.run('UPDATE store_items SET available = 0 WHERE id = ?', [itemId], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to remove item' });
        }
        res.json({ message: 'Item removed successfully' });
    });
});

// Admin Routes - Store Items
server.post('/api/store/items', isAdmin, [
  body('name').trim().notEmpty(),
  body('description').trim().notEmpty(),
  body('price').isFloat({ min: 0 }),
  body('category').trim().notEmpty(),
  body('imageUrl').isURL()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { name, description, price, category, imageUrl } = req.body;
    
    const result = await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO store_items (name, description, price, category, imageUrl) VALUES (?, ?, ?, ?, ?)',
        [name, description, price, category, imageUrl],
        function(err) {
          if (err) reject(err);
          resolve(this.lastID);
        }
      );
    });

    res.status(201).json({ 
      message: 'Store item created successfully',
      itemId: result
    });
  } catch (error) {
    console.error('Error creating store item:', error);
    res.status(500).json({ error: 'Failed to create store item' });
  }
});

server.get('/api/store/items', async (req, res) => {
  try {
    const items = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM store_items', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    res.json({ items });
  } catch (error) {
    console.error('Error fetching store items:', error);
    res.status(500).json({ error: 'Failed to fetch store items' });
  }
});

server.delete('/api/store/items/:id', isAdmin, async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM store_items WHERE id = ?', [req.params.id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    res.json({ message: 'Store item deleted successfully' });
  } catch (error) {
    console.error('Error deleting store item:', error);
    res.status(500).json({ error: 'Failed to delete store item' });
  }
});

// Store Routes
server.get('/api/store/items', async (req, res) => {
    try {
        const items = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM store_items', [], (err, rows) => {
                if (err) reject(err);
                resolve(rows);
            });
        });
        
        res.json({ items });
    } catch (error) {
        console.error('Error fetching store items:', error);
        res.status(500).json({ error: 'Failed to fetch store items' });
    }
});

server.get('/api/store/items/search', async (req, res) => {
    try {
        const searchQuery = req.query.q;
        if (!searchQuery) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        const items = await new Promise((resolve, reject) => {
            const searchTerm = `%${searchQuery}%`;
            db.all(
                `SELECT * FROM store_items 
                WHERE name LIKE ? 
                OR description LIKE ? 
                OR category LIKE ?`,
                [searchTerm, searchTerm, searchTerm],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json({ items });
    } catch (error) {
        console.error('Error searching store items:', error);
        res.status(500).json({ error: 'Failed to search store items' });
    }
});

server.get('/api/store/items/:id', async (req, res) => {
    try {
        const item = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM store_items WHERE id = ?', [req.params.id], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }

        res.json({ item });
    } catch (error) {
        console.error('Error fetching store item:', error);
        res.status(500).json({ error: 'Failed to fetch store item' });
    }
});

server.get('/api/store/items/:id/feedback', async (req, res) => {
    try {
        const feedback = await new Promise((resolve, reject) => {
            db.all(
                `SELECT f.*, s.name as user_name 
                FROM item_feedback f 
                JOIN students s ON f.user_id = s.id 
                WHERE f.item_id = ? 
                ORDER BY f.created_at DESC`,
                [req.params.id],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json({ feedback });
    } catch (error) {
        console.error('Error fetching item feedback:', error);
        res.status(500).json({ error: 'Failed to fetch item feedback' });
    }
});

server.post('/api/store/items/:id/feedback', verifyToken, async (req, res) => {
    try {
        const { rating, comment } = req.body;

        await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO item_feedback (item_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
                [req.params.id, req.user.id, rating, comment],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        res.status(201).json({ success: true, message: 'Feedback submitted successfully' });
    } catch (error) {
        console.error('Error submitting feedback:', error);
        res.status(500).json({ error: 'Failed to submit feedback' });
    }
});

// Profile Routes
server.get('/api/profile/:id', verifyToken, async (req, res) => {
    try {
        const profile = await new Promise((resolve, reject) => {
            db.get(
                `SELECT id, name, email, profilePicture, bio, major, graduationYear, interests, created_at, isAdmin 
                FROM students WHERE id = ?`,
                [req.params.id],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        if (!profile) {
            return res.status(404).json({ error: 'Profile not found' });
        }

        res.json({ profile });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

server.put('/api/profile', verifyToken, [
    body('name').trim().notEmpty(),
    body('email').isEmail(),
    body('bio').optional().trim(),
    body('major').optional().trim(),
    body('graduationYear').optional().isInt({ min: 2000, max: 2100 }),
    body('interests').optional().trim(),
    body('profilePicture').optional().isURL()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        const { name, email, bio, major, graduationYear, interests, profilePicture } = req.body;

        // Check if email is already taken by another user
        if (email !== req.user.email) {
            const existingUser = await new Promise((resolve, reject) => {
                db.get('SELECT id FROM students WHERE email = ? AND id != ?', 
                    [email, req.user.id], 
                    (err, row) => {
                        if (err) reject(err);
                        resolve(row);
                    }
                );
            });

            if (existingUser) {
                return res.status(400).json({ error: 'Email already in use' });
            }
        }

        // Update profile
        await new Promise((resolve, reject) => {
            db.run(
                `UPDATE students 
                SET name = ?, email = ?, bio = ?, major = ?, graduationYear = ?, 
                    interests = ?, profilePicture = ?
                WHERE id = ?`,
                [name, email, bio, major, graduationYear, interests, profilePicture, req.user.id],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        // Fetch updated profile
        const updatedProfile = await new Promise((resolve, reject) => {
            db.get(
                `SELECT id, name, email, profilePicture, bio, major, graduationYear, 
                        interests, created_at, isAdmin 
                FROM students WHERE id = ?`,
                [req.user.id],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        res.json({ 
            message: 'Profile updated successfully',
            profile: updatedProfile
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Admin Routes
server.post('/api/admin/events', verifyToken, async (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }

    try {
        const { title, description, date, time, location } = req.body;

        const result = await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO events (title, description, date, time, location, created_by) VALUES (?, ?, ?, ?, ?, ?)',
                [title, description, date, time, location, req.user.id],
                function(err) {
                    if (err) reject(err);
                    resolve(this.lastID);
                }
            );
        });

        res.status(201).json({
            success: true,
            eventId: result,
            message: 'Event created successfully'
        });
    } catch (error) {
        console.error('Error creating event:', error);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

server.delete('/api/admin/events/:id', verifyToken, async (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }

    try {
        await new Promise((resolve, reject) => {
            db.run('DELETE FROM events WHERE id = ?', [req.params.id], (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        res.json({ success: true, message: 'Event deleted successfully' });
    } catch (error) {
        console.error('Error deleting event:', error);
        res.status(500).json({ error: 'Failed to delete event' });
    }
});

server.post('/api/admin/store/items', verifyToken, async (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }

    try {
        const { name, description, price, category, imageUrl, stock } = req.body;

        const result = await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO store_items (name, description, price, category, imageUrl, stock, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [name, description, price, category, imageUrl, stock || 0, req.user.id],
                function(err) {
                    if (err) reject(err);
                    resolve(this.lastID);
                }
            );
        });

        res.status(201).json({
            success: true,
            itemId: result,
            message: 'Store item created successfully'
        });
    } catch (error) {
        console.error('Error creating store item:', error);
        res.status(500).json({ error: 'Failed to create store item' });
    }
});

server.delete('/api/admin/store/items/:id', verifyToken, async (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }

    try {
        await new Promise((resolve, reject) => {
            db.run('DELETE FROM store_items WHERE id = ?', [req.params.id], (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        res.json({ success: true, message: 'Store item deleted successfully' });
    } catch (error) {
        console.error('Error deleting store item:', error);
        res.status(500).json({ error: 'Failed to delete store item' });
    }
});

server.get('/api/admin/dashboard', verifyToken, async (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }

    try {
        const stats = await Promise.all([
            // Get total users
            new Promise((resolve, reject) => {
                db.get('SELECT COUNT(*) as count FROM students', [], (err, row) => {
                    if (err) reject(err);
                    resolve(row.count);
                });
            }),
            // Get total events
            new Promise((resolve, reject) => {
                db.get('SELECT COUNT(*) as count FROM events', [], (err, row) => {
                    if (err) reject(err);
                    resolve(row.count);
                });
            }),
            // Get total store items
            new Promise((resolve, reject) => {
                db.get('SELECT COUNT(*) as count FROM store_items', [], (err, row) => {
                    if (err) reject(err);
                    resolve(row.count);
                });
            }),
            // Get total feedback
            new Promise((resolve, reject) => {
                db.get('SELECT COUNT(*) as count FROM item_feedback', [], (err, row) => {
                    if (err) reject(err);
                    resolve(row.count);
                });
            })
        ]);

        res.json({
            success: true,
            stats: {
                totalUsers: stats[0],
                totalEvents: stats[1],
                totalStoreItems: stats[2],
                totalFeedback: stats[3]
            }
        });
    } catch (error) {
        console.error('Error fetching admin dashboard stats:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

// Checkout endpoint
server.post('/api/store/checkout', verifyToken, async (req, res) => {
    try {
        if (!req.user || !req.user.id) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const { items } = req.body;
        if (!Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'Invalid items array' });
        }

        // Start a transaction
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION', (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        try {
            // Check stock and update quantities
            for (const item of items) {
                const { itemId, quantity } = item;
                
                // Get current stock
                const currentStock = await new Promise((resolve, reject) => {
                    db.get('SELECT stock FROM store_items WHERE id = ?', [itemId], (err, row) => {
                        if (err) reject(err);
                        if (!row) reject(new Error(`Item ${itemId} not found`));
                        resolve(row.stock);
                    });
                });

                if (currentStock < quantity) {
                    throw new Error(`Not enough stock for item ${itemId}`);
                }

                // Update stock
                await new Promise((resolve, reject) => {
                    db.run(
                        'UPDATE store_items SET stock = stock - ? WHERE id = ?',
                        [quantity, itemId],
                        (err) => {
                            if (err) reject(err);
                            resolve();
                        }
                    );
                });
            }

            // Record the transaction
            const transactionId = await new Promise((resolve, reject) => {
                db.run(
                    'INSERT INTO transactions (user_id, date) VALUES (?, ?)',
                    [req.user.id, new Date().toISOString()],
                    function(err) {
                        if (err) reject(err);
                        resolve(this.lastID);
                    }
                );
            });

            // Record transaction items
            for (const item of items) {
                await new Promise((resolve, reject) => {
                    db.run(
                        'INSERT INTO transaction_items (transaction_id, item_id, quantity) VALUES (?, ?, ?)',
                        [transactionId, item.itemId, item.quantity],
                        (err) => {
                            if (err) reject(err);
                            resolve();
                        }
                    );
                });
            }

            // Commit the transaction
            await new Promise((resolve, reject) => {
                db.run('COMMIT', (err) => {
                    if (err) reject(err);
                    resolve();
                });
            });

            res.json({ 
                success: true, 
                message: 'Checkout successful',
                transactionId 
            });

        } catch (error) {
            // Rollback on error
            await new Promise((resolve) => {
                db.run('ROLLBACK', () => resolve());
            });
            throw error;
        }
    } catch (error) {
        console.error('Checkout error:', error);
        res.status(400).json({ error: error.message || 'Checkout failed' });
    }
});

// Create necessary tables if they don't exist
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES students(id) ON DELETE CASCADE
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS transaction_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
            FOREIGN KEY (item_id) REFERENCES store_items(id) ON DELETE CASCADE
        )
    `);
});

// Error Handler
server.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Something went wrong!',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Start Server
server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
}).on('error', (err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
});
}).on('error', (err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
});
