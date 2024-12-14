const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const db_access = require('./db.js');
const db = db_access.db;
const secret_key = 'DdsdsdKKFDDFDdvfddvxvc4dsdvdsvdb'
const server = express();
const port = 2322;
server.use(cors({
    origin:"http://127.0.0.1:3000",
    credentials:true
}))

const JWT_SECRET = 'your_jwt_secret_key'; // This should be an environment variable
server.use(express.json());
server.use(cookieParser()); // Middleware to parse cookies
const generateToken = (id, isAdmin) => {
    return jwt.sign({ id, isAdmin }, secret_key, { expiresIn: '1h' })
}
const verifyToken = (req, res, next) => {
    const token = req.cookies.authToken
    if (!token)
        return res.status(401).send('unauthorized')
    jwt.verify(token, secret_key, (err, details) => {
        if (err)
            return res.status(403).send('invalid or expired token')
        req.userDetails = details

        next()
    })
}


// Helper: Convert boolean to integer for SQLite
const boolToInt = (bool) => (bool ? 1 : 0);

// Middleware to check if user is admin
function isAdmin(req, res, next) {
    const adminId = req.body.adminId;
    db.get('SELECT isAdmin FROM students WHERE id = ?', [adminId], (err, row) => {
        if (err) {
            console.log('Database error during admin check:', err.message);
            return res.status(500).send('Server error');
        }
        if (row && row.isAdmin) {
            next();
        } else {
            return res.status(403).send('Permission denied');
        }
    });
}

// User Login
server.post('/user/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const query = `SELECT * FROM students WHERE email = '${email}'`;

    db.get(query, async (err, row) => {
        if (err) {
            console.log('Database error during login:', err.message);
            return res.status(500).send('Server error');
        }
        if (!row) {
            console.log('Login failed: Invalid email');
            return res.status(401).send('Invalid credentials');
        }
        const match = await bcrypt.compare(password, row.password);
        if (match) {
            return res.status(200).send(`Login successful: ${row.name}`);
        } else {
            console.log('Login failed: Incorrect password');
            return res.status(401).send('Invalid credentials');
        }
    });
});

// User Registration
server.post('/user/register', async (req, res) => {
    const { name, email, password } = req.body;
    const isAdmin = boolToInt(req.body.isAdmin || false);

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = `INSERT INTO students (name, email, password, isAdmin) VALUES (?, ?, ?, ?)`;
        db.run(query, [name, email, hashedPassword, isAdmin], (err) => {
            if (err) {
                console.log('Database error during registration:', err.message);
                return res.status(401).send(err.message);
            } else {
                return res.status(200).send('Registration successful');
            }
        });
    } catch (error) {
        console.log('Error during password hashing or registration:', error.message);
        return res.status(500).send('Server error');
    }
});

// Add Comment (Students and Admins)
server.post('/comments', (req, res) => {
    const { content, studentId, date } = req.body;
    const query = `INSERT INTO comments (content, studentId, date) VALUES (?, ?, ?)`;

    db.run(query, [content, studentId, date], (err) => {
        if (err) {
            console.log('Database error while adding comment:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Comment added successfully');
        }
    });
});

// Add Item to Cart
server.post('/cart', (req, res) => {
    const { studentId, itemId, quantity } = req.body;
    const query = `INSERT INTO cart (studentId, itemId, quantity) VALUES (?, ?, ?)`;

    db.run(query, [studentId, itemId, quantity], (err) => {
        if (err) {
            console.log('Database error while adding to cart:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Item added to cart');
        }
    });
});

// View Cart
server.get('/cart/:studentId', (req, res) => {
    const studentId = req.params.studentId;
    const query = `SELECT cart.id, store_items.name, store_items.price, cart.quantity 
                   FROM cart 
                   JOIN store_items ON cart.itemId = store_items.id 
                   WHERE cart.studentId = ?`;

    db.all(query, [studentId], (err, rows) => {
        if (err) {
            console.log('Database error while fetching cart:', err.message);
            return res.status(500).send(err.message);
        } else {
            return res.status(200).json(rows);
        }
    });
});

// Checkout (Buy Items in Cart)
server.post('/checkout', (req, res) => {
    const { studentId } = req.body;
    const query = `SELECT cart.itemId, cart.quantity, store_items.price 
                   FROM cart 
                   JOIN store_items ON cart.itemId = store_items.id 
                   WHERE cart.studentId = ?`;

    db.all(query, [studentId], (err, rows) => {
        if (err) {
            console.log('Database error during checkout fetch:', err.message);
            return res.status(500).send(err.message);
        }
        if (rows.length === 0) {
            console.log('Checkout failed: Cart is empty');
            return res.status(400).send('Cart is empty');
        }

        let totalPrice = 0;
        rows.forEach((item) => {
            totalPrice += item.quantity * item.price;
        });

        const transactionQuery = `INSERT INTO transactions (studentId, totalPrice, date) VALUES (?, ?, ?)`;

        db.run(transactionQuery, [studentId, totalPrice, new Date().toISOString()], (err) => {
            if (err) {
                console.log('Database error while recording transaction:', err.message);
                return res.status(500).send(err.message);
            }

            const deleteCartQuery = `DELETE FROM cart WHERE studentId = ?`;
            db.run(deleteCartQuery, [studentId], (err) => {
                if (err) {
                    console.log('Database error while clearing cart:', err.message);
                    return res.status(500).send(err.message);
                } else {
                    return res.status(200).send('Checkout successful');
                }
            });
        });
    });
});

// Add Feedback
server.post('/feedback', (req, res) => {
    const { studentId, itemId, comment, date } = req.body;
    const query = `INSERT INTO feedback (studentId, itemId, comment, date) VALUES (?, ?, ?, ?)`;

    db.run(query, [studentId, itemId, comment, date], (err) => {
        if (err) {
            console.log('Database error while adding feedback:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Feedback added successfully');
        }
    });
});

// Search for Items
server.get('/search', (req, res) => {
    const { query } = req.query;
    const searchQuery = `SELECT * FROM store_items WHERE name LIKE ? OR description LIKE ?`;

    db.all(searchQuery, [`%${query}%`, `%${query}%`], (err, rows) => {
        if (err) {
            console.log('Database error during item search:', err.message);
            return res.status(500).send(err.message);
        } else {
            return res.status(200).json(rows);
        }
    });
});

// Admin Routes for Store Items

// Add Store Item (Admin Only)
server.post('/store_items', isAdmin, (req, res) => {
    const { name, description, price, category, available } = req.body;
    const query = `INSERT INTO store_items (name, description, price, category, available) VALUES (?, ?, ?, ?, ?)`;
    db.run(query, [name, description, price, category, available], (err) => {
        if (err) {
            console.log('Database error while adding store item:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Store item added successfully');
        }
    });
});

// Edit Store Item (Admin Only)
server.put('/store_items/:id', isAdmin, (req, res) => {
    const { name, description, price, category, available } = req.body;
    const itemId = req.params.id;
    const query = `UPDATE store_items SET name = ?, description = ?, price = ?, category = ?, available = ? WHERE id = ?`;
    db.run(query, [name, description, price, category, available, itemId], (err) => {
        if (err) {
            console.log('Database error while updating store item:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Store item updated successfully');
        }
    });
});

// Delete Store Item (Admin Only)
server.delete('/store_items/:id', isAdmin, (req, res) => {
    const itemId = req.params.id;
    const query = `DELETE FROM store_items WHERE id = ?`;
    db.run(query, [itemId], (err) => {
        if (err) {
            console.log('Database error while deleting store item:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Store item deleted successfully');
        }
    });
});

// Events Routes
// View Events (Accessible to All)
server.get('/events', (req, res) => {
    const query = `SELECT * FROM events`;

    db.all(query, (err, rows) => {
        if (err) {
            console.log('Database error while fetching events:', err.message);
            return res.status(500).send(err.message);
        } else {
            return res.status(200).json(rows);
        }
    });
});

// Add Event (Admin Only)
server.post('/events', isAdmin, (req, res) => {
    const { name, date, description } = req.body;
    const query = `INSERT INTO events (name, date, description) VALUES (?, ?, ?)`;

    db.run(query, [name, date, description], (err) => {
        if (err) {
            console.log('Database error while adding event:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Event added successfully');
        }
    });
});

// Edit Event (Admin Only)
server.put('/events/:id', isAdmin, (req, res) => {
    const { name, date, description } = req.body;
    const eventId = req.params.id;
    const query = `UPDATE events SET name = ?, date = ?, description = ? WHERE id = ?`;

    db.run(query, [name, date, description, eventId], (err) => {
        if (err) {
            console.log('Database error while editing event:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Event updated successfully');
        }
    });
});

// Delete Event (Admin Only)
server.delete('/events/:id', isAdmin, (req, res) => {
    const eventId = req.params.id;
    const query = `DELETE FROM events WHERE id = ?`;

    db.run(query, [eventId], (err) => {
        if (err) {
            console.log('Database error while deleting event:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Event deleted successfully');
        }
    });
});

// Admin Respond to Comment
server.post('/comments/respond', isAdmin, (req, res) => {
    const { commentId, response } = req.body;
    const query = `UPDATE comments SET response = ? WHERE id = ?`;

    db.run(query, [response, commentId], (err) => {
        if (err) {
            console.log('Database error while responding to comment:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Response added successfully');
        }
    });
});

// Admin Delete Comment
server.delete('/comments/:id', isAdmin, (req, res) => {
    const commentId = req.params.id;
    const query = `DELETE FROM comments WHERE id = ?`;

    db.run(query, [commentId], (err) => {
        if (err) {
            console.log('Database error while deleting comment:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Comment deleted successfully');
        }
    });
});

// Admin Respond to Feedback
server.post('/feedback/respond', isAdmin, (req, res) => {
    const { feedbackId, response } = req.body;
    const query = `UPDATE feedback SET response = ? WHERE id = ?`;

    db.run(query, [response, feedbackId], (err) => {
        if (err) {
            console.log('Database error while responding to feedback:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Response added successfully');
        }
    });
});

// Admin Delete Feedback
server.delete('/feedback/:id', isAdmin, (req, res) => {
    const feedbackId = req.params.id;
    const query = `DELETE FROM feedback WHERE id = ?`;

    db.run(query, [feedbackId], (err) => {
        if (err) {
            console.log('Database error while deleting feedback:', err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Feedback deleted successfully');
        }
    });
});

// Listen on Port
server.listen(port, () => {
    console.log(`Server started on port ${port}`);
    db.serialize(() => {
        db.exec(db_access.createStudentsTable, (err) => {
            if (err) console.log('Error creating Students table:', err.message);
        });
        db.exec(db_access.createCommentsTable, (err) => {
            if (err) console.log('Error creating Comments table:', err.message);
        });
        db.exec(db_access.createStoreItemsTable, (err) => {
            if (err) console.log('Error creating Store Items table:', err.message);
        });
        db.exec(db_access.createTransactionsTable, (err) => {
            if (err) console.log('Error creating Transactions table:', err.message);
        });
        db.exec(db_access.createCartTable, (err) => {
            if (err) console.log('Error creating Cart table:', err.message);
        });
        db.exec(db_access.createFeedbackTable, (err) => {
            if (err) console.log('Error creating Feedback table:', err.message);
        });
        db.exec(db_access.createEventsTable, (err) => {
            if (err) console.log('Error creating Events table:', err.message);
        });
    });
});

const createEvent = (name, date, description) => {
    // Example logic for creating an event
    const query = `INSERT INTO events (name, date, description) VALUES (?, ?, ?)`;
    db.run(query, [name, date, description], (err) => {
        if (err) {
            console.log('Database error while creating event:', err.message);
        } else {
            console.log('Event created successfully');
        }
    });
};


// Export the createEvent function
module.exports = {
    db,
    createStudentsTable: db_access.createStudentsTable,
    createCommentsTable: db_access.createCommentsTable,
    createStoreItemsTable: db_access.createStoreItemsTable,
    createTransactionsTable: db_access.createTransactionsTable,
    createCartTable: db_access.createCartTable,
    createFeedbackTable: db_access.createFeedbackTable,
    createEventsTable: db_access.createEventsTable,
    createEvent,
};
