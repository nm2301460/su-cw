const express = require('express');
const bcrypt = require('bcrypt');
const db_access = require('./db.js');
const db = db_access.db;
const server = express();
const port = 888;
server.use(express.json());

// Helper: Convert boolean to integer for SQLite
const boolToInt = (bool) => (bool ? 1 : 0);

// User Login
server.post('/user/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const query = `SELECT * FROM students WHERE email = '${email}'`;

    db.get(query, async (err, row) => {
        if (err || !row) {
            return res.status(401).send('Invalid credentials');
        } else {
            const match = await bcrypt.compare(password, row.password);
            if (match) {
                return res.status(200).send(`Login successful: ${row.name}`);
            } else {
                return res.status(401).send('Invalid credentials');
            }
        }
    });
});

// User Registration
server.post('/user/register', async (req, res) => {
    const { name, email, password } = req.body;
    const isAdmin = boolToInt(req.body.isAdmin || false);

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = `INSERT INTO students (name, email, password, isAdmin) VALUES ('${name}', '${email}', '${hashedPassword}', ${isAdmin})`;

        db.run(query, (err) => {
            if (err) {
                console.log(err.message);
                return res.status(401).send(err.message);
            } else {
                return res.status(200).send('Registration successful');
            }
        });
    } catch (error) {
        console.log(error.message);
        return res.status(500).send('Server error');
    }
});

// Add Comment (Students and Admins)
server.post('/comments', (req, res) => {
    const { content, studentId, date } = req.body;
    const query = `INSERT INTO comments (content, studentId, date) VALUES ('${content}', ${studentId}, '${date}')`;

    db.run(query, (err) => {
        if (err) {
            console.log(err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Comment added successfully');
        }
    });
});

// Add Item to Cart
server.post('/cart', (req, res) => {
    const { studentId, itemId, quantity } = req.body;
    const query = `INSERT INTO cart (studentId, itemId, quantity) VALUES (${studentId}, ${itemId}, ${quantity})`;

    db.run(query, (err) => {
        if (err) {
            console.log(err.message);
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
                   WHERE cart.studentId = ${studentId}`;

    db.all(query, (err, rows) => {
        if (err) {
            console.log(err.message);
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
                   WHERE cart.studentId = ${studentId}`;

    db.all(query, (err, rows) => {
        if (err || rows.length === 0) {
            console.log(err?.message || 'Cart is empty');
            return res.status(500).send(err?.message || 'Cart is empty');
        }

        let totalPrice = 0;
        rows.forEach((item) => {
            totalPrice += item.quantity * item.price;
        });

        const transactionQuery = `INSERT INTO transactions (studentId, totalPrice, date) VALUES (${studentId}, ${totalPrice}, '${new Date().toISOString()}')`;

        db.run(transactionQuery, (err) => {
            if (err) {
                console.log(err.message);
                return res.status(500).send(err.message);
            }

            const deleteCartQuery = `DELETE FROM cart WHERE studentId = ${studentId}`;
            db.run(deleteCartQuery, (err) => {
                if (err) {
                    console.log(err.message);
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
    const query = `INSERT INTO feedback (studentId, itemId, comment, date) VALUES (${studentId}, ${itemId}, '${comment}', '${date}')`;

    db.run(query, (err) => {
        if (err) {
            console.log(err.message);
            return res.status(401).send(err.message);
        } else {
            return res.status(200).send('Feedback added successfully');
        }
    });
});

// Listen on Port
server.listen(port, () => {
    console.log(`Server started on port ${port}`);
    db.serialize(() => {
        db.exec(db_access.createStudentsTable);
        db.exec(db_access.createCommentsTable);
        db.exec(db_access.createStoreItemsTable);
        db.exec(db_access.createTransactionsTable);
        db.exec(db_access.createCartTable);
        db.exec(db_access.createFeedbackTable);
        db.exec(db_access.createEventsTable);
    });
});
