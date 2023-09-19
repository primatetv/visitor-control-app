// ==========================
// MODULE IMPORTS
// ==========================
const fs = require('fs');
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const https = require('https');

// Middleware imports
const { checkAuthentication } = require('./middleware/authMiddleware');
const { checkRole } = require('./middleware/roleMiddleware');

// ==========================
// DATABASE SETUP
// ==========================
const db = new sqlite3.Database('./database.db');

// ==========================
// EXPRESS CONFIGURATIONS
// ==========================
const app = express();

// Set EJS as the view engine for rendering pages
app.set('view engine', 'ejs');

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to parse incoming POST data
app.use(express.urlencoded({ extended: true }));


// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Session configuration for authentication
app.use(session({
    secret: 'your_secret_key', // Change this to a random secret key
    resave: false,
    saveUninitialized: false
}));

// Flash messages middleware for displaying messages
app.use(flash());

// Initialize passport for authentication
app.use(passport.initialize());
app.use(passport.session());

// ==========================
// MULTER CONFIGURATION (for file uploads)
// ==========================
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// ==========================
// PASSPORT AUTHENTICATION CONFIGURATION
// ==========================
passport.use(new LocalStrategy(
    function(username, password, done) {
        db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
            if (err) return done(err);
            if (!user) return done(null, false, { message: 'Incorrect username.' });
            
            bcrypt.compare(password, user.password, (err, result) => {
                if (result) {
                    return done(null, user);
                } else {
                    return done(null, false, { message: 'Incorrect password.' });
                }
            });
        });
    }
));

// Serialize user for session
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(function(id, done) {
    db.get("SELECT * FROM users WHERE id = ?", [id], (err, user) => {
        done(err, user);
    });
});

// ==========================
// ROUTES
// ==========================

// Root route
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        switch (req.user.role) {
            case 'root':
                res.redirect('/root-dashboard');
                break;
            case 'building_admin':
                res.redirect('/admin-dashboard');
                break;
            case 'guard':
                res.redirect('/visitors-log');
                break;
            default:
                res.redirect('/login');
        }
    } else {
        res.redirect('/login');
    }
});

// Login route: Renders the login page
app.get('/login', (req, res) => {
    res.render('login', { message: req.flash('error') });
});

// Login POST route: Handles user authentication
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

// Logout route: Logs the user out and redirects to login page
app.get('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
});

// Root Dashboard route: Displays all users for the root user
app.get('/root-dashboard', checkRole('root'), (req, res) => {
    db.all("SELECT * FROM users", [], (err, users) => {
        if (err) throw err;
        res.render('rootDashboard', { users: users });
    });
});

// Admin Dashboard route: Displays all visitors for the building admin
app.get('/admin-dashboard', checkRole('building_admin'), (req, res) => {
    const adminBuildingId = req.user.building_id; // Assuming each admin is associated with a building
    db.all("SELECT * FROM visitors WHERE building_id = ?", [adminBuildingId], (err, visitors) => {
        if (err) throw err;
        res.render('adminDashboard', { visitors: visitors });
    });
});

// Visitors Log route: Displays the log of all visitors
app.get('/visitors-log', checkAuthentication, (req, res) => {
    db.all("SELECT * FROM visitors", [], (err, rows) => {
        if (err) throw err;
        res.render('visitorsLog', { visitors: rows });
    });
});

// Register Visitor route: Renders the form to register a visitor
app.get('/register-visitor', checkRole('guard'), (req, res) => {
    res.render('registerVisitor');
});

// Register Visitor POST route: Handles the submission of visitor registration form
app.post('/register-visitor', upload.single('picture'), (req, res) => {
    const { rut_dni, name, surname, host_name, host_apartment_number, license_plate, visit_type } = req.body;
    const picture_path = req.file.path;

    db.run("INSERT INTO visitors (rut_dni, name, surname, host_name, host_apartment_number, picture_path, license_plate, visit_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [rut_dni, name, surname, host_name, host_apartment_number, picture_path, license_plate, visit_type], (err) => {
        if (err) {
            console.error(err);
            return res.json({ success: false, message: 'Database error.' });
        }
        res.json({ success: true });
    });
});

// ==========================
// HTTPS SERVER CONFIGURATION
// ==========================
// Load SSL certificate files
const privateKey = fs.readFileSync('server.key', 'utf8');
const certificate = fs.readFileSync('server.cert', 'utf8');
const credentials = { key: privateKey, cert: certificate };

const httpsServer = https.createServer(credentials, app);

// ==========================
// START THE SERVER
// ==========================
httpsServer.listen(3000, () => {
    console.log('HTTPS Server running on https://localhost:3000');
});
