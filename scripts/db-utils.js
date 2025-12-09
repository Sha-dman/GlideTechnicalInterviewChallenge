const Database = require("better-sqlite3");
const path = require("path");

const dbPath = path.join(__dirname, "..", "bank.db");
const db = new Database(dbPath);

const command = process.argv[2];

if (command === "list-users") {
  console.log("\n=== Current Users ===");
  const users = db.prepare("SELECT id, email, first_name, last_name FROM users").all();
  if (users.length === 0) {
    console.log("No users found");
  } else {
    users.forEach((user) => {
      console.log(`ID: ${user.id}, Email: ${user.email}, Name: ${user.first_name} ${user.last_name}`);
    });
  }
} else if (command === "list-sessions") {
  console.log("\n=== Current Sessions ===");
  const sessions = db
    .prepare(
      `
    SELECT s.id, s.token, s.expires_at, u.email 
    FROM sessions s 
    JOIN users u ON s.user_id = u.id
  `
    )
    .all();
  if (sessions.length === 0) {
    console.log("No sessions found");
  } else {
    sessions.forEach((session) => {
      const isExpired = new Date(session.expires_at) < new Date();
      console.log(`User: ${session.email}, Expires: ${session.expires_at} ${isExpired ? "(EXPIRED)" : "(ACTIVE)"}`);
      console.log(`Token: ${session.token.substring(0, 20)}...`);
      console.log("---");
    });
  }
} else if (command === "clear") {
  console.log("\n=== Clearing Database ===");
  db.exec("DELETE FROM sessions");
  db.exec("DELETE FROM transactions");
  db.exec("DELETE FROM accounts");
  db.exec("DELETE FROM users");
  console.log("Database cleared!");
} else if (command === "delete-user") {
  const email = process.argv[3];
  if (!email) {
    console.log("Please provide an email: npm run db:delete-user <email>");
  } else {
    const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (user) {
      db.exec(`DELETE FROM sessions WHERE user_id = ${user.id}`);
      db.exec(`DELETE FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE user_id = ${user.id})`);
      db.exec(`DELETE FROM accounts WHERE user_id = ${user.id}`);
      db.exec(`DELETE FROM users WHERE id = ${user.id}`);
      console.log(`User ${email} and all related data deleted!`);
    } else {
      console.log(`User ${email} not found`);
    }
  }
} else {
  console.log(`
Database Utilities
==================

Commands:
  npm run db:list-users     - List all users
  npm run db:list-sessions  - List all sessions
  npm run db:clear          - Clear all data
  npm run db:delete-user    - Delete a specific user by email

Examples:
  npm run db:list-users
  npm run db:list-sessions
  npm run db:clear
  npm run db:delete-user test@example.com
  `);
}

db.close();
