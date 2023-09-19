const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('./database.db');

const saltRounds = 10;

// User data
const users = [
    { username: 'rootUser', password: 'rootPass', role: 'root', building_id: null },
    { username: 'adminUser', password: 'adminPass', role: 'building_admin', building_id: 1 },
    { username: 'guardUser', password: 'guardPass', role: 'guard', building_id: 1 }
];

const insertUser = (user) => {
    return new Promise((resolve, reject) => {
        bcrypt.hash(user.password, saltRounds, (err, hashedPassword) => {
            if (err) reject(err);

            db.run(`INSERT INTO users (username, password, role, building_id) VALUES (?, ?, ?, ?)`, [user.username, hashedPassword, user.role, user.building_id], (err) => {
                if (err) reject(err);
                console.log(`User ${user.username} created successfully!`);
                resolve();
            });
        });
    });
};

// Use Promise.all to wait for all insert operations to complete
Promise.all(users.map(user => insertUser(user)))
    .then(() => {
        db.close();
    })
    .catch(err => {
        console.error(err);
    });
