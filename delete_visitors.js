const sqlite3 = require('sqlite3').verbose();

// Open the database
let db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the database.');
});

// Delete all visitors from the table
db.run("DELETE FROM visitors", (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('All visitors have been deleted.');
});

// Close the database connection
db.close((err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Closed the database connection.');
});
