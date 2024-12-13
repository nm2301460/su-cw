const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('tkh_student_union.db'); // Database name

// Students Table
const createStudentsTable = `
CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  isAdmin INT 
)`;

// Comments Table
const createCommentsTable = `
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content TEXT NOT NULL,
  studentId INTEGER NOT NULL,
  date TEXT NOT NULL,
  FOREIGN KEY (studentId) REFERENCES students (id)
)`;

// Store Items Table
const createStoreItemsTable = `
CREATE TABLE IF NOT EXISTS store_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  price REAL NOT NULL,
  category TEXT NOT NULL,
  available INT NOT NULL
)`;

// Transactions Table
const createTransactionsTable = `
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  studentId INTEGER NOT NULL,
  itemId INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  totalPrice REAL NOT NULL,
  FOREIGN KEY (studentId) REFERENCES students (id),
  FOREIGN KEY (itemId) REFERENCES store_items (id)
)`;

// Cart Table
const createCartTable = `
CREATE TABLE IF NOT EXISTS cart (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  studentId INTEGER NOT NULL,
  itemId INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  FOREIGN KEY (studentId) REFERENCES students (id),
  FOREIGN KEY (itemId) REFERENCES store_items (id)
)`;

// Feedback Table
const createFeedbackTable = `
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  studentId INTEGER NOT NULL,
  itemId INTEGER NOT NULL,
  comment TEXT NOT NULL,
  date TEXT NOT NULL,
  FOREIGN KEY (studentId) REFERENCES students (id),
  FOREIGN KEY (itemId) REFERENCES store_items (id)
)`;

// Events Table (Optional)
const createEventsTable = `
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  location TEXT,
  createdBy INTEGER NOT NULL,
  FOREIGN KEY (createdBy) REFERENCES students (id)
)`;

// Export database connection and table creation scripts
module.exports = {
  db,
  createStudentsTable,
  createCommentsTable,
  createStoreItemsTable,
  createTransactionsTable,
  createCartTable,
  createFeedbackTable,
  createEventsTable,
};
