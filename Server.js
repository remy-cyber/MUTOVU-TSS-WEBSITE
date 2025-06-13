require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'mutovutss_system',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to verify JWT
const authenticate = (user_types = []) => {
    return async (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ message: 'Authentication required' });

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const [users] = await pool.query('SELECT * FROM users WHERE user_id = ?', [decoded.userId]);
            if (!users.length) return res.status(401).json({ message: 'User not found' });

            const user = users[0];
            if (user_types.length && !user_types.includes(user.user_type)) {
                return res.status(403).json({ message: 'Insufficient permissions' });
            }

            req.user = user;
            next();
        } catch (error) {
            res.status(401).json({ message: 'Invalid token' });
        }
    };
};

// Set up storage for uploaded documents
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/documents/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname.replace(/\s+/g, '_'));
    }
});
const upload = multer({ storage });

// Add multer storage for updates images
const updatesImageStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/updates/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname.replace(/\s+/g, '_'));
    }
});
const updatesImageUpload = multer({ storage: updatesImageStorage });

// Make sure uploads/updates exists
const updatesDir = path.join(__dirname, 'uploads', 'updates');
if (!fs.existsSync(updatesDir)) {
    fs.mkdirSync(updatesDir, { recursive: true });
}

// Serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/uploads/updates', express.static(path.join(__dirname, 'uploads', 'updates')));

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'MUTOVUTSS System API' });
});

// User registration
app.post('/api/register', async (req, res) => {
    const { 
        username, 
        password, 
        confirmPassword,
        email, 
        firstName,
        lastName,
        user_type,
        phone_number, 
        address, 
        subject_specialization 
    } = req.body;

    try {
        // Normalize user_type
        const normalizedUserType = (user_type || '').trim().toLowerCase();
        const validUserTypes = ['student', 'parent', 'teacher', 'admin'];
        if (!validUserTypes.includes(normalizedUserType)) {
            return res.status(400).json({ 
                message: 'Invalid user type', 
                validTypes: validUserTypes,
                received: user_type
            });
        }

        // Validate required fields
        if (!username || !password || !email || !firstName || !lastName || !user_type) {
            return res.status(400).json({ message: 'All required fields must be provided' });
        }

        // Validate password match
        if (password !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match' });
        }

        // Check if username or email exists
        const [existing] = await pool.query(
            'SELECT * FROM users WHERE username = ? OR email = ?', 
            [username, email]
        );
        if (existing.length) {
            return res.status(400).json({ message: 'Username or email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Start transaction
        const conn = await pool.getConnection();
        await conn.beginTransaction();

        try {
            // Create user
            const [result] = await conn.query(
                'INSERT INTO users (username, password, email, first_name, last_name, user_type) VALUES (?, ?, ?, ?, ?, ?)',
                [username, hashedPassword, email, firstName, lastName, normalizedUserType]
            );
            const userId = result.insertId;

            // Create role-specific record
            if (normalizedUserType === 'parent') {
                await conn.query(
                    'INSERT INTO parents (parent_id, phone_number, address) VALUES (?, ?, ?)',
                    [userId, phone_number, address]
                );
            } else if (normalizedUserType === 'teacher') {
                await conn.query(
                    'INSERT INTO teachers (teacher_id, subject_specialization, hire_date) VALUES (?, ?, ?)',
                    [userId, subject_specialization, new Date()]
                );
            }

            await conn.commit();
            res.status(201).json({ message: 'User registered successfully' });
        } catch (error) {
            await conn.rollback();
            throw error;
        } finally {
            conn.release();
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            message: 'Registration failed',
            error: error.message 
        });
    }
});

// User login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (!users.length) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Update last login
        await pool.query('UPDATE users SET last_login = NOW() WHERE user_id = ?', [user.user_id]);

        // Create JWT token
        const token = jwt.sign({ userId: user.user_id }, JWT_SECRET, { expiresIn: '1d' });

        // Get user details based on user_type
        let userDetails = { 
            id: user.user_id, 
            username: user.username, 
            email: user.email, 
            user_type: user.user_type, 
            firstName: user.first_name, 
            lastName: user.last_name 
        };
        
        if (user.user_type === 'parent') {
            const [parents] = await pool.query('SELECT * FROM parents WHERE parent_id = ?', [user.user_id]);
            if (parents.length) userDetails = { ...userDetails, ...parents[0] };
        } else if (user.user_type === 'teacher') {
            const [teachers] = await pool.query('SELECT * FROM teachers WHERE teacher_id = ?', [user.user_id]);
            if (teachers.length) userDetails = { ...userDetails, ...teachers[0] };
        } else if (user.user_type === 'student') {
            const [students] = await pool.query('SELECT * FROM students WHERE student_id = ?', [user.user_id]);
            if (students.length) userDetails = { ...userDetails, ...students[0] };
        }

        res.json({ token, user: userDetails });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Login failed' });
    }
});

// Example: Get user notifications
app.get('/api/notifications', authenticate(), async (req, res) => {
    try {
        const [notifications] = await pool.query(
            'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
            [req.user.user_id]
        );
        res.json(notifications);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch notifications' });
    }
});

// Example: Mark notification as read
app.patch('/api/notifications/:id/read', authenticate(), async (req, res) => {
    try {
        await pool.query(
            'UPDATE notifications SET is_read = TRUE WHERE notification_id = ? AND user_id = ?',
            [req.params.id, req.user.user_id]
        );
        res.json({ message: 'Notification marked as read' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to update notification' });
    }
});

// Registration request (parent registers student for approval)
app.post('/api/registration-request', async (req, res) => {
    const { student_name, parent_name, parent_email, student_dob, grade_level, class_id } = req.body;
    if (!student_name || !parent_name || !parent_email || !class_id) {
        return res.status(400).json({ message: 'All required fields must be provided' });
    }
    try {
        await pool.query(
            `INSERT INTO registration_requests 
            (student_name, parent_name, parent_email, student_dob, grade_level, class_id) 
            VALUES (?, ?, ?, ?, ?, ?)`,
            [student_name, parent_name, parent_email, student_dob, grade_level, class_id]
        );
        res.status(201).json({ message: 'Registration request submitted' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to submit registration request' });
    }
});

// Get all registration requests (for admin)
app.get('/api/registration-requests', async (req, res) => {
    try {
        const [requests] = await pool.query(
            'SELECT * FROM registration_requests ORDER BY requested_at DESC'
        );
        res.json(requests);
    } catch (error) {
        console.error('Fetch registration requests error:', error);
        res.status(500).json({ message: 'Failed to fetch registration requests' });
    }
});

// Approve registration request
app.patch('/api/registration-requests/:id/approve', async (req, res) => {
    const requestId = req.params.id;
    try {
        // Update request status
        await pool.query(
            "UPDATE registration_requests SET status = 'approved', processed_at = NOW() WHERE request_id = ?",
            [requestId]
        );

        // Fetch the request to get parent_email
        const [[request]] = await pool.query(
            "SELECT * FROM registration_requests WHERE request_id = ?",
            [requestId]
        );

        // Try to find parent user
        const [[parent]] = await pool.query(
            "SELECT user_id FROM users WHERE email = ? AND user_type = 'parent'",
            [request.parent_email]
        );

        // Insert student regardless of parent existence
        await pool.query(
            `INSERT INTO students (student_name, parent_id, parent_name, parent_email, student_dob, grade_level, class_id)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                request.student_name,
                parent ? parent.user_id : null,
                request.parent_name,
                request.parent_email,
                request.student_dob,
                request.grade_level,
                request.class_id
            ]
        );

        // Send notification if parent exists
        if (parent) {
            await pool.query(
                "INSERT INTO notifications (user_id, title, message, notification_type) VALUES (?, ?, ?, ?)",
                [
                    parent.user_id,
                    'Registration Approved',
                    `Your registration request for ${request.student_name} has been approved.`,
                    'request'
                ]
            );
        }

        res.json({ message: 'Request approved and student added.' });
    } catch (error) {
        console.error('Approve request error:', error);
        res.status(500).json({ message: 'Failed to approve request' });
    }
});

// Reject registration request
app.patch('/api/registration-requests/:id/reject', async (req, res) => {
    const requestId = req.params.id;
    try {
        // Update request status
        await pool.query(
            "UPDATE registration_requests SET status = 'rejected', processed_at = NOW() WHERE request_id = ?",
            [requestId]
        );

        // Fetch the request to get parent_email
        const [[request]] = await pool.query(
            "SELECT * FROM registration_requests WHERE request_id = ?",
            [requestId]
        );

        // Send notification to parent (if parent exists in users table)
        const [[parent]] = await pool.query(
            "SELECT user_id FROM users WHERE email = ? AND user_type = 'parent'",
            [request.parent_email]
        );
        if (parent) {
            await pool.query(
                "INSERT INTO notifications (user_id, title, message, notification_type) VALUES (?, ?, ?, ?)",
                [
                    parent.user_id,
                    'Registration Rejected',
                    `Your registration request for ${request.student_name} has been rejected.`,
                    'request'
                ]
            );
        }

        res.json({ message: 'Request rejected and parent notified.' });
    } catch (error) {
        console.error('Reject request error:', error);
        res.status(500).json({ message: 'Failed to reject request' });
    }
});

// School Updates CRUD
// Get all updates
app.get('/api/updates', async (req, res) => {
    try {
        const [updates] = await pool.query('SELECT * FROM school_updates ORDER BY created_at DESC');
        res.json(updates);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch updates' });
    }
});

// Post new update with image
app.post('/api/updates', updatesImageUpload.single('image'), async (req, res) => {
    const { title, content } = req.body;
    let image_url = null;
    if (req.file) {
        image_url = `/uploads/updates/${req.file.filename}`;
    }
    try {
        await pool.query(
            'INSERT INTO school_updates (title, content, image_url) VALUES (?, ?, ?)',
            [title, content, image_url]
        );
        res.status(201).json({ message: 'Update posted' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to post update' });
    }
});

// Edit update with image
app.put('/api/updates/:id', updatesImageUpload.single('image'), async (req, res) => {
    const { title, content } = req.body;
    const { id } = req.params;
    let image_url = null;
    if (req.file) {
        image_url = `/uploads/updates/${req.file.filename}`;
    }
    try {
        if (image_url) {
            await pool.query(
                'UPDATE school_updates SET title=?, content=?, image_url=? WHERE id=?',
                [title, content, image_url, id]
            );
        } else {
            await pool.query(
                'UPDATE school_updates SET title=?, content=? WHERE id=?',
                [title, content, id]
            );
        }
        res.json({ message: 'Update edited' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to edit update' });
    }
});

// Delete update
app.delete('/api/updates/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM school_updates WHERE id=?', [id]);
        res.json({ message: 'Update deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete update' });
    }
});

// Dashboard statistics
app.get('/api/dashboard-stats', async (req, res) => {
  try {
    const [[{ students }]] = await pool.query("SELECT COUNT(*) AS students FROM students");
    const [[{ parents }]] = await pool.query("SELECT COUNT(*) AS parents FROM users WHERE user_type = 'parent'");
    const [[{ teachers }]] = await pool.query("SELECT COUNT(*) AS teachers FROM users WHERE user_type = 'teacher'");
    const [[{ requests }]] = await pool.query("SELECT COUNT(*) AS requests FROM registration_requests");
    const [[{ users }]] = await pool.query("SELECT COUNT(*) AS users FROM users");
    const [[{ updates }]] = await pool.query("SELECT COUNT(*) AS updates FROM school_updates");
    res.json({ students, parents, teachers, requests, users, updates });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch dashboard stats' });
  }
});

// Get all students
app.get('/api/students', async (req, res) => {
    try {
        const [students] = await pool.query(
            `SELECT s.*, c.name AS class_name, c.level AS class_level
             FROM students s
             LEFT JOIN classes c ON s.class_id = c.class_id
             ORDER BY s.created_at DESC`
        );
        res.json(students);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch students' });
    }
});

// Add new student
app.post('/api/students', async (req, res) => {
    const { student_name, parent_id, parent_name, parent_email, student_dob, grade_level } = req.body;
    try {
        await pool.query(
            `INSERT INTO students (student_name, parent_id, parent_name, parent_email, student_dob, grade_level)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [student_name, parent_id, parent_name, parent_email, student_dob, grade_level]
        );
        res.status(201).json({ message: 'Student added' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to add student' });
    }
});

// Get all parents
app.get('/api/parents', async (req, res) => {
    try {
        const [parents] = await pool.query(
            `SELECT u.user_id AS parent_id, u.first_name, u.last_name, u.email, p.phone_number, p.address
             FROM users u
             JOIN parents p ON u.user_id = p.parent_id
             WHERE u.user_type = 'parent'
             ORDER BY u.created_at DESC`
        );
        res.json(parents);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch parents' });
    }
});

// Add new parent
app.post('/api/parents', async (req, res) => {
    const { first_name, last_name, email, phone_number, address } = req.body;
    try {
        // Create user
        const [userResult] = await pool.query(
            `INSERT INTO users (first_name, last_name, email, user_type) VALUES (?, ?, ?, 'parent')`,
            [first_name, last_name, email]
        );
        const parent_id = userResult.insertId;
        // Create parent details
        await pool.query(
            `INSERT INTO parents (parent_id, phone_number, address) VALUES (?, ?, ?)`,
            [parent_id, phone_number, address]
        );
        res.status(201).json({ message: 'Parent added' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to add parent' });
    }
});

// Update parent
app.put('/api/parents/:id', async (req, res) => {
    const { id } = req.params;
    const { first_name, last_name, email, phone_number, address } = req.body;
    try {
        await pool.query(
            `UPDATE users SET first_name=?, last_name=?, email=? WHERE user_id=? AND user_type='parent'`,
            [first_name, last_name, email, id]
        );
        await pool.query(
            `UPDATE parents SET phone_number=?, address=? WHERE parent_id=?`,
            [phone_number, address, id]
        );
        res.json({ message: 'Parent updated' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to update parent' });
    }
});

// Delete parent
app.delete('/api/parents/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM parents WHERE parent_id=?', [id]);
        await pool.query('DELETE FROM users WHERE user_id=? AND user_type="parent"', [id]);
        res.json({ message: 'Parent deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete parent' });
    }
});

// Get chat contacts
app.get('/api/users', authenticate(), async (req, res) => {
    const { type, exclude } = req.query;
    try {
        let users = [];
        if (type === 'student') {
            users = await pool.query(
                'SELECT user_id, first_name, last_name, email, user_type FROM users WHERE user_type = "student" AND user_id != ?',
                [exclude || req.user.user_id]
            );
        } else if (type === 'teacher') {
            users = await pool.query(
                'SELECT user_id, first_name, last_name, email, user_type FROM users WHERE user_type = "teacher"'
            );
        } else if (type === 'staff') {
            users = await pool.query(
                'SELECT user_id, first_name, last_name, email, user_type FROM users WHERE user_type IN ("parent", "teacher", "admin") AND user_id != ?',
                [req.user.user_id]
            );
        }
        res.json(users[0]);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch users' });
    }
});

// Get messages between current user and selected user
app.get('/api/messages', authenticate(), async (req, res) => {
    const { userId } = req.query;
    try {
        const [messages] = await pool.query(
            `SELECT * FROM messages
             WHERE (from_user_id = ? AND to_user_id = ?)
                OR (from_user_id = ? AND to_user_id = ?)
             ORDER BY created_at ASC`,
            [req.user.user_id, userId, userId, req.user.user_id]
        );
        res.json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch messages' });
    }
});

// Send a message
app.post('/api/messages', authenticate(), async (req, res) => {
    const { to_user_id, message } = req.body;
    try {
        await pool.query(
            'INSERT INTO messages (from_user_id, to_user_id, message, created_at) VALUES (?, ?, ?, NOW())',
            [req.user.user_id, to_user_id, message]
        );
        res.status(201).json({ message: 'Message sent' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to send message' });
    }
});

// Simulated active users endpoint
// In production, use WebSocket or Redis for real-time tracking
app.get('/api/active-users', authenticate(), async (req, res) => {
    try {
        // For demo: return users who logged in within the last 5 minutes
        const [users] = await pool.query(
            `SELECT user_id FROM users WHERE last_login >= (NOW() - INTERVAL 5 MINUTE)`
        );
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch active users' });
    }
});

// Get all classes
app.get('/api/classes', authenticate(), async (req, res) => {
    try {
        const [classes] = await pool.query('SELECT * FROM classes ORDER BY name, level');
        res.json(classes);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch classes' });
    }
});

// Get students in a class
app.get('/api/classes/:class_id/students', authenticate(), async (req, res) => {
    const { class_id } = req.params;
    try {
        const [students] = await pool.query(
            'SELECT * FROM students WHERE class_id = ? ORDER BY student_name',
            [class_id]
        );
        res.json(students);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch students for class' });
    }
});

// Submit attendance for a class
app.post('/api/classes/:class_id/attendance', authenticate(['teacher']), async (req, res) => {
    const { class_id } = req.params;
    const { date, attendance } = req.body; // attendance: [{student_id, status}]
    if (!Array.isArray(attendance) || !date) {
        return res.status(400).json({ message: 'Attendance data and date are required' });
    }
    try {
        const values = attendance.map(a => [a.student_id, class_id, date, a.status]);
        await pool.query(
            'INSERT INTO attendance (student_id, class_id, date, status) VALUES ?',
            [values]
        );
        res.status(201).json({ message: 'Attendance recorded' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to record attendance' });
    }
});

// Get attendance for a class on a date
app.get('/api/classes/:class_id/attendance', authenticate(), async (req, res) => {
    const { class_id } = req.params;
    const { date } = req.query;
    try {
        const [records] = await pool.query(
            'SELECT * FROM attendance WHERE class_id = ? AND date = ?',
            [class_id, date]
        );
        res.json(records);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch attendance' });
    }
});

// Get documents for a class
app.get('/api/classes/:class_id/documents', authenticate(), async (req, res) => {
    const { class_id } = req.params;
    try {
        const [docs] = await pool.query(
            `SELECT d.*, u.first_name AS uploaded_by_name
             FROM documents d
             LEFT JOIN users u ON d.uploaded_by = u.user_id
             WHERE d.class_id = ?
             ORDER BY d.uploaded_at DESC`,
            [class_id]
        );
        res.json(docs);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch documents' });
    }
});

// Upload a document for a class (teacher only)
app.post('/api/classes/:class_id/documents', authenticate(['teacher']), upload.single('file'), async (req, res) => {
    const { class_id } = req.params;
    const { title } = req.body;
    if (!req.file) return res.status(400).json({ message: 'File is required' });
    try {
        await pool.query(
            `INSERT INTO documents (title, file_path, class_id, uploaded_by, uploaded_at)
             VALUES (?, ?, ?, ?, NOW())`,
            [title, req.file.filename, class_id, req.user.user_id]
        );
        res.status(201).json({ message: 'Document uploaded' });
    } catch (error) {
        console.error(error); // <--- Add this line
        res.status(500).json({ message: 'Failed to upload document' });
    }
});

// Download a document by document_id
app.get('/api/documents/:document_id/download', authenticate(), async (req, res) => {
    const { document_id } = req.params;
    try {
        const [[doc]] = await pool.query(
            'SELECT file_path, title FROM documents WHERE document_id = ?',
            [document_id]
        );
        if (!doc) {
            return res.status(404).json({ message: 'Document not found' });
        }
        const filePath = path.join(__dirname, 'uploads', 'documents', doc.file_path);
        res.download(filePath, doc.title || doc.file_path);
    } catch (error) {
        res.status(500).json({ message: 'Failed to download document' });
    }
});

// OPTIONAL: Delete a document (teacher or admin)
app.delete('/api/documents/:document_id', authenticate(['teacher', 'admin']), async (req, res) => {
    const { document_id } = req.params;
    try {
        // Optionally, fetch and delete the file from disk here
        await pool.query('DELETE FROM documents WHERE document_id = ?', [document_id]);
        res.json({ message: 'Document deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete document' });
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Get all attendance for a date (for dashboard)
app.get('/api/attendance', async (req, res) => {
    const { date } = req.query;
    if (!date) return res.status(400).json({ message: 'Date is required' });
    try {
        const [records] = await pool.query(
            `SELECT 
                a.*, 
                s.student_name, 
                c.name AS class_name, 
                c.level 
             FROM attendance a
             LEFT JOIN students s ON a.student_id = s.student_id
             LEFT JOIN classes c ON a.class_id = c.class_id
             WHERE a.date = ?
             ORDER BY c.name, s.student_name`,
            [date]
        );
        res.json(records);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch attendance' });
    }
});

// View a document in browser (PDF/images/office files)
app.get('/api/documents/:document_id/view', async (req, res) => {
    const { document_id } = req.params;
    try {
        const [[doc]] = await pool.query(
            'SELECT file_path, title FROM documents WHERE document_id = ?',
            [document_id]
        );
        if (!doc) {
            return res.status(404).json({ message: 'Document not found' });
        }
        const filePath = path.join(__dirname, 'uploads', 'documents', doc.file_path);
        // Set correct content type for preview
        const ext = path.extname(doc.file_path).toLowerCase();
        let contentType = 'application/octet-stream';
        if (ext === '.pdf') contentType = 'application/pdf';
        else if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
        else if (ext === '.png') contentType = 'image/png';
        else if (ext === '.doc') contentType = 'application/msword';
        else if (ext === '.docx') contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        else if (ext === '.ppt') contentType = 'application/vnd.ms-powerpoint';
        else if (ext === '.pptx') contentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        else if (ext === '.xls') contentType = 'application/vnd.ms-excel';
        else if (ext === '.xlsx') contentType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

        res.setHeader('Content-Type', contentType);
        res.sendFile(filePath);
    } catch (error) {
        res.status(500).json({ message: 'Failed to view document' });
    }
});

// Helper middleware to allow document preview without authentication for GET /api/documents/:document_id/view
app.get('/api/documents/:document_id/view', async (req, res) => {
    const { document_id } = req.params;
    try {
        const [[doc]] = await pool.query(
            'SELECT file_path, title FROM documents WHERE document_id = ?',
            [document_id]
        );
        if (!doc) {
            return res.status(404).json({ message: 'Document not found' });
        }
        const filePath = path.join(__dirname, 'uploads', 'documents', doc.file_path);
        // Set correct content type for preview
        const ext = path.extname(doc.file_path).toLowerCase();
        let contentType = 'application/octet-stream';
        if (ext === '.pdf') contentType = 'application/pdf';
        else if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
        else if (ext === '.png') contentType = 'image/png';
        else if (ext === '.doc') contentType = 'application/msword';
        else if (ext === '.docx') contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        else if (ext === '.ppt') contentType = 'application/vnd.ms-powerpoint';
        else if (ext === '.pptx') contentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        else if (ext === '.xls') contentType = 'application/vnd.ms-excel';
        else if (ext === '.xlsx') contentType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

        res.setHeader('Content-Type', contentType);
        res.sendFile(filePath);
    } catch (error) {
        res.status(500).json({ message: 'Failed to view document' });
    }
});

// Search API
app.get('/api/search', async (req, res) => {
  const { q = '', type = 'all' } = req.query;
  if (!q || q.length < 2) return res.json({ results: [] });

  let results = [];
  try {
    // Students (with class info)
    if (type === 'all' || type === 'student') {
      const [students] = await pool.query(
        `SELECT s.student_id, s.student_name as name, c.name as class_name, c.level, s.parent_name
         FROM students s
         LEFT JOIN classes c ON s.class_id = c.class_id
         WHERE s.student_name LIKE ?`,
        [`%${q}%`]
      );
      results.push(...students.map(s => ({ ...s, type: 'student' })));
    }
    // Teachers
    if (type === 'all' || type === 'teacher') {
      const [teachers] = await pool.query(
        `SELECT t.teacher_id, CONCAT(u.first_name, ' ', u.last_name) as name, u.email, t.subject_specialization as subject
         FROM users u
         JOIN teachers t ON u.user_id = t.teacher_id
         WHERE (u.first_name LIKE ? OR u.last_name LIKE ?)`,
        [`%${q}%`, `%${q}%`]
      );
      results.push(...teachers.map(t => ({ ...t, type: 'teacher' })));
    }
    // Parents
    if (type === 'all' || type === 'parent') {
      const [parents] = await pool.query(
        `SELECT p.parent_id, CONCAT(u.first_name, ' ', u.last_name) as name, u.email, p.phone_number as phone
         FROM users u
         JOIN parents p ON u.user_id = p.parent_id
         WHERE (u.first_name LIKE ? OR u.last_name LIKE ? OR p.parent_id LIKE ?)`,
        [`%${q}%`, `%${q}%`, `%${q}%`]
      );
      results.push(...parents.map(p => ({ ...p, type: 'parent' })));
    }
    // Documents
    if (type === 'all' || type === 'document') {
      const [documents] = await pool.query(
        "SELECT document_id, title, uploaded_by FROM documents WHERE title LIKE ?",
        [`%${q}%`]
      );
      results.push(...documents.map(d => ({ ...d, type: 'document' })));
    }
    res.json({ results });
  } catch (err) {
    console.error(err);
    res.json({ results: [] });
  }
});
