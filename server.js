const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const app = express();
const port = process.env.PORT || 5000;
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cors = require('cors');

// Use CORS middleware to allow all origins for development
app.use(cors({
    origin: '*',   // Allow all origins
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allow methods for CORS
    allowedHeaders: ['Content-Type'] // Allow specific headers if needed
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// MySQL Connection
const pool = mysql.createPool({
    connectionLimit: 10,
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'todo_app',   // Database name
});

// POST: Create a new user (signup)
app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
        return res.status(400).send('Username, email, and password are required.');
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).send('Error hashing password');
        }

        // Insert user into database
        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Error getting DB connection:', err); // Log the connection error
                return res.status(500).send('Error connecting to database');
            }

            const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
            connection.query(query, [username, email, hashedPassword], (err, result) => {
                connection.release();

                if (err) {
                    console.error('Error inserting user into database:', err); // Log the specific query error
                    return res.status(500).send('Error inserting user into database');
                }

                console.log('User inserted successfully:', result); // Log successful insertion
                return res.status(201).send('User created successfully');
            });
        });
    });
});

// POST: Login a user
app.post('/login', (req, res) => {
    const { username, password } = req.body; // Expecting 'username' (can be username or email)

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username/Email and password are required.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error connecting to database' });
        }

        // Query the database checking either the username or the email
        const query = 'SELECT * FROM users WHERE username = ? OR email = ?';
        connection.query(query, [username, username], (err, rows) => {
            connection.release();

            if (err) {
                return res.status(500).json({ success: false, message: 'Error checking credentials' });
            }

            if (rows.length === 0) {
                return res.status(400).json({ success: false, message: 'User not found' });
            }

            const user = rows[0];

            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ success: false, message: 'Error comparing passwords' });
                }

                if (result) {
                    // Successful login - Include userId in the response
                    return res.status(200).json({ success: true, message: 'Login successful', userId: user.id });
                } else {
                    return res.status(400).json({ success: false, message: 'Invalid password' });
                }
            });
        });
    });
});

// Forgot Password Route
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).send('Email is required');
    }

    pool.getConnection((err, connection) => {
        if (err) return res.status(500).send('Error connecting to database');

        const query = 'SELECT * FROM users WHERE email = ?';
        connection.query(query, [email], (err, rows) => {
            connection.release();

            if (err) return res.status(500).send('Error checking email');
            if (rows.length === 0) return res.status(400).send('Email not found');

            const user = rows[0];
            const resetToken = crypto.randomBytes(32).toString('hex'); // Generate a random reset token

            // Store the reset token in the database
            const updateQuery = 'UPDATE users SET reset_token = ? WHERE email = ?';
            connection.query(updateQuery, [resetToken, email], (err) => {
                if (err) return res.status(500).send('Error storing reset token');

                // Log the reset token for testing purposes (email sending skipped in demo)
                console.log(`Reset token for ${email}: ${resetToken}`);

                res.send('Password reset link has been generated');
            });
        });
    });
});

// Password Reset Route
app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    if (!newPassword) {
        return res.status(400).send('New password is required');
    }

    pool.getConnection((err, connection) => {
        if (err) return res.status(500).send('Error connecting to database');

        const query = 'SELECT * FROM users WHERE reset_token = ?';
        connection.query(query, [token], (err, rows) => {
            connection.release();

            if (err) return res.status(500).send('Error finding token');
            if (rows.length === 0) return res.status(400).send('Invalid or expired reset token');

            const user = rows[0];

            // Hash the new password
            bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
                if (err) return res.status(500).send('Error hashing password');

                // Update the password in the database
                const updateQuery = 'UPDATE users SET password = ?, reset_token = NULL WHERE id = ?';
                connection.query(updateQuery, [hashedPassword, user.id], (err) => {
                    if (err) return res.status(500).send('Error updating password');
                    res.send('Password successfully updated');
                });
            });
        });
    });
});

// POST: Add a new To-Do item
app.post('/todos', (req, res) => {
    const { title, userId, description, schedule } = req.body; // Expecting 'title', 'userId', 'description', and 'schedule' in the request body

    if (!title || !userId) {
        return res.status(400).send('Title and userId are required.');
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).send('Error connecting to database');
        }

        // Use 'schedule' as the actual column name from your data
        const query = 'INSERT INTO todos (user_id, title, description, schedule) VALUES (?, ?, ?, ?)';
        connection.query(query, [userId, title, description || null, schedule || null], (err, result) => {
            connection.release();

            if (err) {
                console.error('Error inserting To-Do item:', err);
                return res.status(500).send('Error adding To-Do item');
            }

            return res.status(201).json({ message: 'To-Do item added successfully', todoId: result.insertId });
        });
    });
});

// GET: Fetch all To-Do items for a specific user with optional sorting
app.get('/api/todos/:userId', (req, res) => {
    const { userId } = req.params;
    const { sortBy, sortOrder } = req.query;

    if (!userId) {
        return res.status(400).send('userId is required.');
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).send('Error connecting to database');
        }

        let query = 'SELECT id, title, description, status, schedule, created_at, priority FROM todos WHERE user_id = ?';
        const queryParams = [userId];
        let orderByClause = ' ORDER BY created_at DESC'; // Default sorting

        // Sanitize and apply sorting
        if (sortBy) {
            const allowedSortColumns = ['priority', 'dueDate', 'created_at', 'title', 'status']; // Add other allowed columns
            if (allowedSortColumns.includes(sortBy)) {
                const order = sortOrder && sortOrder.toLowerCase() === 'asc' ? 'ASC' : 'DESC';
                orderByClause = ` ORDER BY ${sortBy} ${order}`;
            } else {
                return res.status(400).send('Invalid sortBy parameter.');
            }
        }

        query += orderByClause;

        connection.query(query, queryParams, (err, rows) => {
            connection.release();

            if (err) {
                console.error('Error fetching To-Do items:', err);
                return res.status(500).json({ message: 'Error fetching To-Do items', error: err });
            }

            return res.status(200).json(rows);
        });
    });
});

// PUT: Update an existing To-Do item
app.put('/todos/:id', (req, res) => {
    const todoId = req.params.id;
    const { title, description, schedule, userId } = req.body; // Expecting userId for authorization

    if (!title) {
        return res.status(400).json({ message: 'Title is required for update' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            return res.status(500).json({ message: 'Error connecting to database' });
        }

        const query = 'UPDATE todos SET title = ?, description = ?, schedule = ? WHERE id = ? AND user_id = ?';
        connection.query(query, [title, description, schedule, todoId, userId], (err, result) => {
            connection.release();

            if (err) {
                console.error('Error updating todo:', err);
                return res.status(500).json({ message: 'Error updating todo' });
            }

            if (result.affectedRows > 0) {
                res.status(200).json({ message: 'Todo updated successfully' });
            } else {
                res.status(404).json({ message: 'Todo not found or you do not have permission to update it.' });
            }
        });
    });
});

// DELETE: Delete a To-Do item
app.delete('/todos/:id', (req, res) => {
    const todoId = req.params.id;
    const userId = req.query.userId; // Get userId from query parameter

    if (!userId) {
        return res.status(400).json({ message: 'User ID is required for deletion.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            return res.status(500).json({ message: 'Error connecting to database' });
        }

        const query = 'DELETE FROM todos WHERE id = ? AND user_id = ?';
        connection.query(query, [todoId, userId], (err, result) => {
            connection.release();

            if (err) {
                console.error('Error deleting todo:', err);
                return res.status(500).json({ message: 'Error deleting todo', error: err.message });
            }

            if (result.affectedRows > 0) {
                res.status(200).json({ message: 'Todo deleted successfully' });
            } else {
                res.status(404).json({ message: 'Todo not found or you do not have permission to delete it.' });
            }
        });
    });
});


// POST: Create a new note
app.post('/api/notes', (req, res) => {
    const { userId, title, content } = req.body;

    if (!userId || !title) {
        return res.status(400).json({ success: false, message: 'User ID and title are required.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).json({ success: false, message: 'Error connecting to database' });
        }

        const query = 'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)';
        connection.query(query, [userId, title, content || null], (err, result) => {
            connection.release();

            if (err) {
                console.error('Error inserting note:', err);
                return res.status(500).json({ success: false, message: 'Error creating note' });
            }

            return res.status(201).json({ success: true, message: 'Note created successfully', noteId: result.insertId });
        });
    });
});

// GET: Fetch all notes for a specific user
app.get('/api/notes/:userId', (req, res) => {
    const { userId } = req.params;

    if (!userId) {
        return res.status(400).json({ success: false, message: 'User ID is required.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).json({ success: false, message: 'Error connecting to database' });
        }

        const query = 'SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY created_at DESC';
        connection.query(query, [userId], (err, rows) => {
            connection.release();

            if (err) {
                console.error('Error fetching notes:', err);
                return res.status(500).json({ success: false, message: 'Error fetching notes' });
            }

            return res.status(200).json({ success: true, notes: rows });
        });
    });
});

// PUT: Update an existing note
app.put('/api/notes/:id', (req, res) => {
    const { id } = req.params;
    const { userId, title, content } = req.body;

    if (!id || !userId || !title) {
        return res.status(400).json({ success: false, message: 'Note ID, User ID, and title are required for update.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).json({ success: false, message: 'Error connecting to database' });
        }

        const query = 'UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?';
        connection.query(query, [title, content || null, id, userId], (err, result) => {
            connection.release();

            if (err) {
                console.error('Error updating note:', err);
                return res.status(500).json({ success: false, message: 'Error updating note' });
            }

            if (result.affectedRows > 0) {
                return res.status(200).json({ success: true, message: 'Note updated successfully' });
            } else {
                return res.status(404).json({ success: false, message: 'Note not found or you do not have permission to update it.' });
            }
        });
    });
});


// DELETE: Delete a note
app.delete('/api/notes/:id', (req, res) => {
    const { id } = req.params;
    const { userId } = req.body; // Expecting userId in the request body for authorization

    if (!id || !userId) {
        return res.status(400).json({ success: false, message: 'Note ID and User ID are required for deletion.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).json({ success: false, message: 'Error connecting to database' });
        }

        const query = 'DELETE FROM notes WHERE id = ? AND user_id = ?';
        connection.query(query, [id, userId], (err, result) => {
            connection.release();

            if (err) {
                console.error('Error deleting note:', err);
                return res.status(500).json({ success: false, message: 'Error deleting note' });
            }

            if (result.affectedRows > 0) {
                return res.status(200).json({ success: true, message: 'Note deleted successfully' });
            } else {
                return res.status(404).json({ success: false, message: 'Note not found or you do not have permission to delete it.' });
            }
        });
    });
});







app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});