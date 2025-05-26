const express = require('express');
const mysql = require('mysql2');
const util = require('util');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const { body, validationResult } = require('express-validator');

dotenv.config();
const app = express();
app.use(express.json());

// MySQL Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to MySQL database.');
});

const queryAsync = util.promisify(db.query).bind(db);

// JWT Middleware
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied' });
    jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// -------------------- API Endpoints --------------------

// Create Communication
app.post('/api/communication',
    authenticateToken,
    [
        body('sender').isString().withMessage('Sender must be a string'),
        body('receiver').isString().withMessage('Receiver must be a string'),
        body('message').isString().withMessage('Message must be a string')
    ],
    async (req, res) => {
        // Check validation
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { sender, receiver, channel, noise, code, message, feedback, sense, longitude, latitude, date_time, file_path } = req.body;
        
        let space_time_id = null;
        let file_id = null;

        try {
            // Insert into space_time if location and date_time are provided
            if (longitude && latitude && date_time) {
                const spaceTimeSql = `INSERT INTO space_time (longitude, latitude, date_time) VALUES (?, ?, ?)`;
                const spaceTimeResult = await queryAsync(spaceTimeSql, [longitude, latitude, date_time]);
                space_time_id = spaceTimeResult.insertId;
            }

            // Insert into file if file_path is provided
            if (file_path) {
                const fileSql = `INSERT INTO file (file_path) VALUES (?)`;
                const fileResult = await queryAsync(fileSql, [file_path]);
                file_id = fileResult.insertId;
            }

            // Insert into communication
            const communicationSql = `
                INSERT INTO communication (sender, receiver, channel, noise, code, message, feedback, sense, space_time_id, file_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            const communicationResult = await queryAsync(communicationSql, 
                [sender, receiver, channel, noise, code, message, feedback, sense, space_time_id, file_id]
            );

            res.json({ id: communicationResult.insertId, message: 'Communication record created successfully' });
        } catch (err) {
            res.status(500).send({ error: 'Error inserting data', details: err.message });
        }
    }
);

// Get All Communications (Including date_time and file_path)
app.get('/api/communication', authenticateToken, async (req, res) => {
    const sql = `
        SELECT 
            c.id, c.sender, c.receiver, c.channel, c.noise, c.code, 
            c.message, c.feedback, c.sense, 
            s.date_time, 
            f.file_path
        FROM communication c
        LEFT JOIN space_time s ON c.space_time_id = s.id
        LEFT JOIN file f ON c.file_id = f.id`;

    try {
        const results = await queryAsync(sql);
        res.json(results);
    } catch (err) {
        res.status(500).send({ error: 'Error retrieving communication records', details: err.message });
    }
});

// Get Communication by ID (Including date_time and file_path)
app.get('/api/communication/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const sql = `
        SELECT 
            c.id, c.sender, c.receiver, c.channel, c.noise, c.code, 
            c.message, c.feedback, c.sense, 
            s.date_time, 
            f.file_path
        FROM communication c
        LEFT JOIN space_time s ON c.space_time_id = s.id
        LEFT JOIN file f ON c.file_id = f.id
        WHERE c.id = ?`;

    try {
        const results = await queryAsync(sql, [id]);
        if (results.length === 0) return res.status(404).send({ message: 'Communication record not found' });
        res.json(results[0]);
    } catch (err) {
        res.status(500).send({ error: 'Error retrieving communication record', details: err.message });
    }
});

// Update Communication by ID
app.put('/api/communication/:id', authenticateToken, [
    body('sender').optional().isString().withMessage('Sender must be a string'),
    body('receiver').optional().isString().withMessage('Receiver must be a string'),
    body('message').optional().isString().withMessage('Message must be a string')
], async (req, res) => {
    // Check validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { sender, receiver, channel, noise, code, message, feedback, sense } = req.body;
    const sql = `UPDATE communication SET sender = ?, receiver = ?, channel = ?, noise = ?, code = ?, message = ?, feedback = ?, sense = ? WHERE id = ?`;
    
    try {
        const result = await queryAsync(sql, [sender, receiver, channel, noise, code, message, feedback, sense, id]);
        if (result.affectedRows === 0) return res.status(404).send({ message: 'Communication record not found' });
        res.json({ message: 'Communication record updated successfully' });
    } catch (err) {
        res.status(500).send({ error: 'Error updating communication record', details: err.message });
    }
});

// Delete Communication by ID
app.delete('/api/communication/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const sql = `DELETE FROM communication WHERE id = ?`;
    try {
        const result = await queryAsync(sql, [id]);
        if (result.affectedRows === 0) return res.status(404).send({ message: 'Communication record not found' });
        res.json({ message: 'Communication record deleted successfully' });
    } catch (err) {
        res.status(500).send({ error: 'Error deleting communication record', details: err.message });
    }
});

// Authentication Routes
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    // Check if the password is hashed in the .env file
    // Check for Admin credentials
    if (username === process.env.ADMIN_USER) {
        const hashedPassword = process.env.ADMIN_PASS;
        if (!bcrypt.compareSync(password, hashedPassword)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    }

    // Check for Developer credentials
    if (username === process.env.DEVELOPER_USER) {
        const hashedDeveloperPassword = process.env.DEVELOPER_PASS;
        if (!bcrypt.compareSync(password, hashedDeveloperPassword)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    }

    return res.status(401).json({ error: 'Invalid credentials' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

