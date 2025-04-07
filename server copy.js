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
    origin: '*',  // Allow all origins
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
    database: 'todo_app',  // Database name
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
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error connecting to database' });
        }

        const query = 'SELECT * FROM users WHERE email = ?';
        connection.query(query, [email], (err, rows) => {
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
                    // Successful login
                    return res.status(200).json({ success: true, message: 'Login successful' });
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

// GET: Get all notes for a specific user
app.get('/api/notes/:userId', (req, res) => {
    const userId = req.params.userId;
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).json({ message: 'Error connecting to database' });
        }
        const query = 'SELECT * FROM notes WHERE user_id = ?';
        connection.query(query, [userId], (err, results) => {
            connection.release();
            if (err) {
                console.error('Error fetching notes:', err);
                return res.status(500).json({ message: 'Error fetching notes' });
            }
            res.status(200).json(results);
        });
    });
});

// POST: Create a new note for a user
app.post('/api/notes', (req, res) => {
    const { user_id, title, content } = req.body;
    if (!user_id || !title) {
        return res.status(400).json({ message: 'User ID and note title are required' });
    }
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).json({ message: 'Error connecting to database' });
        }
        const query = 'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)';
        connection.query(query, [user_id, title, content], (err, result) => {
            connection.release();
            if (err) {
                console.error('Error creating note:', err);
                return res.status(500).json({ message: 'Error creating note' });
            }
            res.status(201).json({ message: 'Note created successfully', noteId: result.insertId });
        });
    });
});

// PUT: Update an existing note
app.put('/api/notes/:noteId', (req, res) => {
    const noteId = req.params.noteId;
    const { user_id, title, content } = req.body;
    if (!user_id || !title) {
        return res.status(400).json({ message: 'User ID and note title are required' });
    }
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).json({ message: 'Error connecting to database' });
        }
        const query = 'UPDATE notes SET user_id = ?, title = ?, content = ? WHERE id = ?';
        connection.query(query, [user_id, title, content, noteId], (err, result) => {
            connection.release();
            if (err) {
                console.error('Error updating note:', err);
                return res.status(500).json({ message: 'Error updating note' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Note not found' });
            }
            res.status(200).json({ message: 'Note updated successfully' });
        });
    });
});

// DELETE: Delete a note
app.delete('/api/notes/:noteId', (req, res) => {
    const noteId = req.params.noteId;
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting DB connection:', err);
            return res.status(500).json({ message: 'Error connecting to database' });
        }
        const query = 'DELETE FROM notes WHERE id = ?';
        connection.query(query, [noteId], (err, result) => {
            connection.release();
            if (err) {
                console.error('Error deleting note:', err);
                return res.status(500).json({ message: 'Error deleting note' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Note not found' });
            }
            res.status(200).json({ message: 'Note deleted successfully' });
        });
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
