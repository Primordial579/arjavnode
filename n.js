const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const multer = require('multer');
const mysql = require('mysql');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL Configuration
const db = mysql.createConnection({
    host: 'db54.cd4o4gaekmw5.ap-south-1.rds.amazonaws.com',
    user: 'admin',
    password: 'Kammavari123',
    database: 'Arjav',
});

db.connect(err => {
    if (err) {
        console.error('Database connection error:', err);
        return;
    }
    console.log('Connected to MySQL');

    const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users1 (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`;

    const createFilesTable = `
    CREATE TABLE IF NOT EXISTS files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fileName VARCHAR(255) NOT NULL,
        fileUrl VARCHAR(512) NOT NULL,
        scanType VARCHAR(100) NOT NULL,
        userId INT NOT NULL,
        uploadDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`;

    db.query(createUsersTable, err => {
        if (err) {
            console.error('Error creating users1 table:', err);
        } else {
            console.log('Users table is ready.');
        }
    });

    db.query(createFilesTable, err => {
        if (err) {
            console.error('Error creating files table:', err);
        } else {
            console.log('Files table is ready.');
        }
    });
});

// AWS S3 Configuration
const s3 = new AWS.S3({
    accessKeyId: 'AKIATNVEVWTHSQV5W667',
    secretAccessKey: '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',
    region: 'ap-south-1',
});

// Multer Configuration for File Upload
const storage = multer.memoryStorage();
const upload = multer({ storage });

// JWT Secret
const JWT_SECRET = '57958';

// Helper: Authenticate JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Register
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users1 (email, password) VALUES (?, ?)';

    db.query(query, [email, hashedPassword], err => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ message: 'User registered successfully' });
    });
});

// Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users1 WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, redirect: 'https://db34.s3.ap-south-1.amazonaws.com/tp.html' });
    });
});

// Fetch User Files
app.get('/files', authenticateToken, (req, res) => {
    const query = 'SELECT id, fileName, fileUrl, uploadDate, scanType FROM files WHERE userId = ?';
    db.query(query, [req.userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(results);
    });
});

// Rename a File
app.post('/rename', authenticateToken, (req, res) => {
    const { fileId, newFileName } = req.body;

    if (!fileId || !newFileName) {
        return res.status(400).json({ error: 'File ID and new file name are required' });
    }

    const query = 'UPDATE files SET fileName = ? WHERE id = ? AND userId = ?';
    db.query(query, [newFileName, fileId, req.userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.affectedRows === 0) {
            return res.status(404).json({ error: 'File not found or not authorized' });
        }
        res.json({ message: 'File renamed successfully' });
    });
});

// Delete a File
app.delete('/delete/:fileId', authenticateToken, (req, res) => {
    const { fileId } = req.params;

    // Fetch file details from the database to get the S3 URL
    const getFileQuery = 'SELECT fileUrl FROM files WHERE id = ? AND userId = ?';
    db.query(getFileQuery, [fileId, req.userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error while fetching file details' });

        if (results.length === 0) {
            return res.status(404).json({ error: 'File not found or not authorized' });
        }

        const fileUrl = results[0].fileUrl;
        const s3Key = fileUrl.split('/').slice(3).join('/'); // Extract S3 key from URL

        // Delete the file from S3
        const deleteParams = {
            Bucket: 'arjav579',
            Key: s3Key,
        };

        s3.deleteObject(deleteParams, (err) => {
            if (err) {
                console.error('Error deleting file from S3:', err);
                return res.status(500).json({ error: 'Error deleting file from S3' });
            }

            // Delete the file from the database
            const deleteFileQuery = 'DELETE FROM files WHERE id = ? AND userId = ?';
            db.query(deleteFileQuery, [fileId, req.userId], (err, results) => {
                if (err) return res.status(500).json({ error: 'Database error while deleting file' });
                if (results.affectedRows === 0) {
                    return res.status(404).json({ error: 'File not found or not authorized' });
                }
                res.json({ message: 'File deleted successfully from database and S3' });
            });
        });
    });
});

// File Upload
app.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
    const file = req.file;
    const { scanType } = req.body;

    if (!file || !scanType) {
        return res.status(400).json({ error: 'File and scan type are required' });
    }

    const folderName = `user_${req.userId}/`;
    const params = {
        Bucket: 'arjav579',
        Key: `${folderName}${Date.now()}-${file.originalname}`,
        Body: file.buffer,
        ACL: 'public-read',
        ContentType: file.mimetype,
    };

    s3.upload(params, (err, data) => {
        if (err) return res.status(500).json({ error: 'S3 upload failed' });

        const query = 'INSERT INTO files (fileName, fileUrl, scanType, userId) VALUES (?, ?, ?, ?)';
        db.query(query, [file.originalname, data.Location, scanType, req.userId], err => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({
                message: 'File uploaded successfully',
                fileName: file.originalname,
                uploadDate: new Date(),
                scanType,
            });
        });
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
