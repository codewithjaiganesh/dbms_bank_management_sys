require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET in .env to a random string at least 32 characters long.");
  process.exit(1);
}

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "banksphere",
  waitForConnections: true,
  connectionLimit: 10,
  decimalNumbers: true
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/auth/login", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30 }));

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Please log in." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expired. Please log in again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "ADMIN") return res.status(403).json({ error: "Admin access required." });
  next();
}

function validAmount(value) {
  const amount = Number(value);
  return Number.isFinite(amount) && amount > 0 && amount <= 100000000
    ? Math.round(amount * 100) / 100
    : null;
}

function newReference() {
  return "BS" + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString("hex").toUpperCase();
}

async function getCustomerAccountIds(userId) {
  const [rows] = await pool.execute(
    `SELECT a.account_id FROM accounts a
     JOIN customers c ON c.customer_id=a.customer_id
     WHERE c.user_id=? AND a.status='ACTIVE'`,
    [userId]
  );
  return rows.map(r => r.account_id);
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(503).json({ ok: false, database: "unavailable" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !password) return res.status(400).json({ error: "Email and password are required." });

    const [rows] = await pool.execute(
      "SELECT user_id,full_name,email,password_hash,role,active FROM users WHERE email=? LIMIT 1",
      [email]
    );
    const user = rows[0];
    if (!user || !user.active || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const token = jwt.sign(
      { sub: String(user.user_id), name: user.full_name, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "4h", issuer: "banksphere-demo", audience: "banksphere-client" }
    );
    res.json({
      token,
      user: { id: user.user_id, name: user.full_name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not log in." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  res.json({ user: { id: req.user.sub, name: req.user.name, email: req.user.email, role: req.user.role } });
});

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    if (req.user.role === "ADMIN") {
      const [[customers]] = await pool.query("SELECT COUNT(*) AS total FROM customers");
      const [[accounts]] = await pool.query("SELECT COUNT(*) AS total FROM accounts");
      const [[money]] = await pool.query("SELECT COALESCE(SUM(balance),0) AS total FROM accounts WHERE status='ACTIVE'");
      const [[transactions]] = await pool.query("SELECT COUNT(*) AS total FROM transactions");
      return res.json({
        role: "ADMIN",
        totalCustomers: customers.total,
        totalAccounts: accounts.total,
        totalBalance: money.total,
        totalTransactions: transactions.total
      });
    }
    const ids = await getCustomerAccountIds(req.user.sub);
    if (!ids.length) return res.json({ role: "CUSTOMER", accounts: [], totalBalance: 0, totalTransactions: 0 });
    const [accounts] = await pool.execute(
      `SELECT a.account_id,a.account_number,a.account_type,a.balance,a.status,a.created_at
       FROM accounts a JOIN customers c ON c.customer_id=a.customer_id
       WHERE c.user_id=? ORDER BY a.account_id`,
      [req.user.sub]
    );
    const [countRows] = await pool.execute(
      `SELECT COUNT(*) AS total FROM transactions t JOIN accounts a ON a.account_id=t.account_id
       JOIN customers c ON c.customer_id=a.customer_id WHERE c.user_id=?`,
      [req.user.sub]
    );
    res.json({
      role: "CUSTOMER",
      accounts,
      totalBalance: accounts.reduce((sum, a) => sum + Number(a.balance), 0),
      totalTransactions: countRows[0].total
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load dashboard." });
  }
});

app.get("/api/customers", auth, adminOnly, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT c.customer_id,c.customer_number,c.phone,c.address,c.kyc_status,c.created_at,
              u.full_name,u.email,
              COUNT(a.account_id) AS account_count,
              COALESCE(SUM(CASE WHEN a.status='ACTIVE' THEN a.balance ELSE 0 END),0) AS total_balance
       FROM customers c JOIN users u ON u.user_id=c.user_id
       LEFT JOIN accounts a ON a.customer_id=c.customer_id
       GROUP BY c.customer_id ORDER BY c.customer_id DESC`
    );
    res.json({ customers: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load customers." });
  }
});

app.post("/api/customers", auth, adminOnly, async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const phone = String(req.body.phone || "").trim();
  const address = String(req.body.address || "").trim();
  const initialDeposit = validAmount(req.body.initialDeposit ?? 0) ?? (Number(req.body.initialDeposit) === 0 ? 0 : null);

  if (!name || !email || password.length < 8 || initialDeposit === null) {
    return res.status(400).json({ error: "Enter name, valid email, password (8+ characters), and a valid initial deposit." });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const hash = await bcrypt.hash(password, 12);
    const [userResult] = await connection.execute(
      "INSERT INTO users (full_name,email,password_hash,role) VALUES (?,?,?,'CUSTOMER')",
      [name, email, hash]
    );
    const customerNo = "C" + Date.now().toString().slice(-10);
    const [customerResult] = await connection.execute(
      "INSERT INTO customers (user_id,customer_number,phone,address,kyc_status) VALUES (?,?,?,?, 'PENDING')",
      [userResult.insertId, customerNo, phone || null, address || null]
    );
    const accountNo = "2" + Date.now().toString().slice(-9) + String(crypto.randomInt(0, 10));
    const [accountResult] = await connection.execute(
      "INSERT INTO accounts (customer_id,account_number,account_type,balance,status) VALUES (?,?,'SAVINGS',?,'ACTIVE')",
      [customerResult.insertId, accountNo, initialDeposit]
    );
    if (initialDeposit > 0) {
      await connection.execute(
        `INSERT INTO transactions (reference_code,account_id,transaction_type,amount,balance_after,description)
         VALUES (?,?,'DEPOSIT',?,?,?)`,
        [newReference(), accountResult.insertId, initialDeposit, initialDeposit, "Initial deposit"]
      );
    }
    await connection.commit();
    res.status(201).json({ message: "Customer created.", customerNumber: customerNo, accountNumber: accountNo });
  } catch (err) {
    await connection.rollback();
    if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "That email is already registered." });
    console.error(err);
    res.status(500).json({ error: "Could not create customer." });
  } finally {
    connection.release();
  }
});

app.get("/api/accounts", auth, async (req, res) => {
  try {
    let rows;
    if (req.user.role === "ADMIN") {
      [rows] = await pool.query(
        `SELECT a.account_id,a.account_number,a.account_type,a.balance,a.status,a.created_at,
                u.full_name,u.email,c.customer_number
         FROM accounts a JOIN customers c ON c.customer_id=a.customer_id
         JOIN users u ON u.user_id=c.user_id ORDER BY a.account_id DESC`
      );
    } else {
      [rows] = await pool.execute(
        `SELECT a.account_id,a.account_number,a.account_type,a.balance,a.status,a.created_at,
                u.full_name,u.email,c.customer_number
         FROM accounts a JOIN customers c ON c.customer_id=a.customer_id
         JOIN users u ON u.user_id=c.user_id WHERE c.user_id=? ORDER BY a.account_id DESC`,
        [req.user.sub]
      );
    }
    res.json({ accounts: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load accounts." });
  }
});

app.get("/api/transactions", auth, async (req, res) => {
  try {
    let rows;
    if (req.user.role === "ADMIN") {
      [rows] = await pool.query(
        `SELECT t.transaction_id,t.reference_code,t.transaction_type,t.amount,t.balance_after,
                t.description,t.created_at,a.account_number,u.full_name,
                ra.account_number AS related_account_number
         FROM transactions t JOIN accounts a ON a.account_id=t.account_id
         JOIN customers c ON c.customer_id=a.customer_id JOIN users u ON u.user_id=c.user_id
         LEFT JOIN accounts ra ON ra.account_id=t.related_account_id
         ORDER BY t.transaction_id DESC LIMIT 100`
      );
    } else {
      [rows] = await pool.execute(
        `SELECT t.transaction_id,t.reference_code,t.transaction_type,t.amount,t.balance_after,
                t.description,t.created_at,a.account_number,
                ra.account_number AS related_account_number
         FROM transactions t JOIN accounts a ON a.account_id=t.account_id
         JOIN customers c ON c.customer_id=a.customer_id
         LEFT JOIN accounts ra ON ra.account_id=t.related_account_id
         WHERE c.user_id=? ORDER BY t.transaction_id DESC LIMIT 100`,
        [req.user.sub]
      );
    }
    res.json({ transactions: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load transactions." });
  }
});

async function performAccountOperation(req, res, kind) {
  const amount = validAmount(req.body.amount);
  const accountNumber = String(req.body.accountNumber || "").trim();
  if (!amount || !accountNumber) return res.status(400).json({ error: "Enter a valid account number and amount." });

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.execute(
      `SELECT a.account_id,a.account_number,a.balance,a.status,c.user_id
       FROM accounts a JOIN customers c ON c.customer_id=a.customer_id
       WHERE a.account_number=? FOR UPDATE`,
      [accountNumber]
    );
    const account = rows[0];
    if (!account || account.status !== "ACTIVE") {
      await connection.rollback();
      return res.status(404).json({ error: "Active account not found." });
    }
    if (req.user.role !== "ADMIN" && Number(account.user_id) !== Number(req.user.sub)) {
      await connection.rollback();
      return res.status(403).json({ error: "You can only operate on your own account." });
    }
    const current = Number(account.balance);
    if (kind === "WITHDRAWAL" && current < amount) {
      await connection.rollback();
      return res.status(400).json({ error: "Insufficient balance." });
    }
    const updated = Math.round((current + (kind === "DEPOSIT" ? amount : -amount)) * 100) / 100;
    await connection.execute("UPDATE accounts SET balance=? WHERE account_id=?", [updated, account.account_id]);
    await connection.execute(
      `INSERT INTO transactions (reference_code,account_id,transaction_type,amount,balance_after,description)
       VALUES (?,?,?,?,?,?)`,
      [newReference(), account.account_id, kind, amount, updated, req.body.description || kind.toLowerCase()]
    );
    await connection.commit();
    res.json({ message: `${kind === "DEPOSIT" ? "Deposit" : "Withdrawal"} successful.`, balance: updated });
  } catch (err) {
    await connection.rollback();
    console.error(err);
    res.status(500).json({ error: "Operation failed." });
  } finally {
    connection.release();
  }
}

app.post("/api/deposit", auth, adminOnly, (req, res) => performAccountOperation(req, res, "DEPOSIT"));
app.post("/api/withdraw", auth, adminOnly, (req, res) => performAccountOperation(req, res, "WITHDRAWAL"));

app.post("/api/transfer", auth, async (req, res) => {
  const fromNumber = String(req.body.fromAccountNumber || "").trim();
  const toNumber = String(req.body.toAccountNumber || "").trim();
  const amount = validAmount(req.body.amount);
  if (!fromNumber || !toNumber || fromNumber === toNumber || !amount) {
    return res.status(400).json({ error: "Enter different source and destination accounts and a valid amount." });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [accounts] = await connection.execute(
      `SELECT a.account_id,a.account_number,a.balance,a.status,c.user_id
       FROM accounts a JOIN customers c ON c.customer_id=a.customer_id
       WHERE a.account_number IN (?,?) ORDER BY a.account_id FOR UPDATE`,
      [fromNumber, toNumber]
    );
    const from = accounts.find(a => a.account_number === fromNumber);
    const to = accounts.find(a => a.account_number === toNumber);
    if (!from || !to || from.status !== "ACTIVE" || to.status !== "ACTIVE") {
      await connection.rollback();
      return res.status(404).json({ error: "Both accounts must exist and be active." });
    }
    if (req.user.role !== "ADMIN" && Number(from.user_id) !== Number(req.user.sub)) {
      await connection.rollback();
      return res.status(403).json({ error: "You can only send money from your own account." });
    }
    const fromBalance = Number(from.balance);
    const toBalance = Number(to.balance);
    if (fromBalance < amount) {
      await connection.rollback();
      return res.status(400).json({ error: "Insufficient balance." });
    }

    const newFrom = Math.round((fromBalance - amount) * 100) / 100;
    const newTo = Math.round((toBalance + amount) * 100) / 100;
    await connection.execute("UPDATE accounts SET balance=? WHERE account_id=?", [newFrom, from.account_id]);
    await connection.execute("UPDATE accounts SET balance=? WHERE account_id=?", [newTo, to.account_id]);
    const reference = newReference();
    await connection.execute(
      `INSERT INTO transactions (reference_code,account_id,transaction_type,amount,balance_after,related_account_id,description)
       VALUES (?,?, 'TRANSFER_OUT', ?,?,?,?)`,
      [reference, from.account_id, amount, newFrom, to.account_id, `Transfer to ${toNumber}`]
    );
    await connection.execute(
      `INSERT INTO transactions (reference_code,account_id,transaction_type,amount,balance_after,related_account_id,description)
       VALUES (?,?, 'TRANSFER_IN', ?,?,?,?)`,
      [reference + "IN", to.account_id, amount, newTo, from.account_id, `Transfer from ${fromNumber}`]
    );
    await connection.commit();
    res.json({ message: "Demo transfer successful.", reference, fromBalance: newFrom, toBalance: newTo });
  } catch (err) {
    await connection.rollback();
    console.error(err);
    res.status(500).json({ error: "Transfer failed." });
  } finally {
    connection.release();
  }
});

app.get("/api/qr/account/:accountNumber", auth, async (req, res) => {
  try {
    const accountNumber = String(req.params.accountNumber);
    const [rows] = await pool.execute(
      `SELECT a.account_number,a.account_type,u.full_name,c.user_id
       FROM accounts a JOIN customers c ON c.customer_id=a.customer_id
       JOIN users u ON u.user_id=c.user_id
       WHERE a.account_number=? AND a.status='ACTIVE'`,
      [accountNumber]
    );
    const account = rows[0];
    if (!account) return res.status(404).json({ error: "Active account not found." });
    if (req.user.role !== "ADMIN" && Number(account.user_id) !== Number(req.user.sub)) {
      return res.status(403).json({ error: "You can only generate a QR for your own account." });
    }
    res.json({
      qr: JSON.stringify({ version: 1, app: "BANKSPHERE_DEMO", accountNumber: account.account_number }),
      account: { accountNumber: account.account_number, accountType: account.account_type, name: account.full_name }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not generate account QR." });
  }
});

app.post("/api/qr/pay", auth, async (req, res) => {
  const fromNumber = String(req.body.fromAccountNumber || "").trim();
  const amount = validAmount(req.body.amount);
  let payload;
  try {
    payload = typeof req.body.qrPayload === "string" ? JSON.parse(req.body.qrPayload) : req.body.qrPayload;
  } catch {
    return res.status(400).json({ error: "QR data is invalid." });
  }
  const toNumber = String(payload?.accountNumber || "").trim();
  if (payload?.app !== "BANKSPHERE_DEMO" || payload?.version !== 1 || !toNumber || !amount || !fromNumber || fromNumber === toNumber) {
    return res.status(400).json({ error: "Invalid demo QR, account, or amount." });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [accounts] = await connection.execute(
      `SELECT a.account_id,a.account_number,a.balance,a.status,c.user_id
       FROM accounts a JOIN customers c ON c.customer_id=a.customer_id
       WHERE a.account_number IN (?,?) ORDER BY a.account_id FOR UPDATE`,
      [fromNumber, toNumber]
    );
    const from = accounts.find(a => a.account_number === fromNumber);
    const to = accounts.find(a => a.account_number === toNumber);
    if (!from || !to || from.status !== "ACTIVE" || to.status !== "ACTIVE") {
      await connection.rollback();
      return res.status(404).json({ error: "Both accounts must exist and be active." });
    }
    if (req.user.role !== "ADMIN" && Number(from.user_id) !== Number(req.user.sub)) {
      await connection.rollback();
      return res.status(403).json({ error: "You can only pay from your own account." });
    }
    const fromBalance = Number(from.balance);
    const toBalance = Number(to.balance);
    if (fromBalance < amount) {
      await connection.rollback();
      return res.status(400).json({ error: "Insufficient balance." });
    }
    const newFrom = Math.round((fromBalance - amount) * 100) / 100;
    const newTo = Math.round((toBalance + amount) * 100) / 100;
    await connection.execute("UPDATE accounts SET balance=? WHERE account_id=?", [newFrom, from.account_id]);
    await connection.execute("UPDATE accounts SET balance=? WHERE account_id=?", [newTo, to.account_id]);
    const reference = newReference();
    await connection.execute(
      `INSERT INTO transactions (reference_code,account_id,transaction_type,amount,balance_after,related_account_id,description)
       VALUES (?,?, 'TRANSFER_OUT', ?,?,?,?)`,
      [reference, from.account_id, amount, newFrom, to.account_id, `QR payment to ${toNumber}`]
    );
    await connection.execute(
      `INSERT INTO transactions (reference_code,account_id,transaction_type,amount,balance_after,related_account_id,description)
       VALUES (?,?, 'TRANSFER_IN', ?,?,?,?)`,
      [reference + "IN", to.account_id, amount, newTo, from.account_id, `QR payment from ${fromNumber}`]
    );
    await connection.commit();
    res.json({ message: "QR demo payment successful.", reference, fromBalance: newFrom, toBalance: newTo, recipientAccount: toNumber });
  } catch (err) {
    await connection.rollback();
    console.error(err);
    res.status(500).json({ error: "QR payment failed." });
  } finally {
    connection.release();
  }
});

// Face-to-Pay academic demo. Users must explicitly opt in; only a face descriptor is stored.
app.get("/api/face/status", auth, async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT consented_at, updated_at FROM face_profiles WHERE user_id=?", [req.user.sub]);
    res.json({ enrolled: rows.length > 0, consentedAt: rows[0]?.consented_at || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load face enrollment status. Run the updated database.sql first." });
  }
});

app.post("/api/face/enroll", auth, async (req, res) => {
  if (req.user.role !== "CUSTOMER") return res.status(403).json({ error: "Only customer demo accounts can enroll." });
  if (req.body.consent !== true) return res.status(400).json({ error: "Explicit consent is required." });
  const descriptor = req.body.descriptor;
  if (!Array.isArray(descriptor) || descriptor.length !== 128 || descriptor.some(n => !Number.isFinite(n) || n < -2 || n > 2)) {
    return res.status(400).json({ error: "Invalid face descriptor. Capture one clear face and try again." });
  }
  try {
    await pool.execute(
      `INSERT INTO face_profiles (user_id, descriptor) VALUES (?, ?)
       ON DUPLICATE KEY UPDATE descriptor=VALUES(descriptor), consented_at=CURRENT_TIMESTAMP`,
      [req.user.sub, JSON.stringify(descriptor)]
    );
    res.json({ message: "Face enrollment saved. No face photo was uploaded or stored." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not save enrollment. Run the updated database.sql first." });
  }
});

app.delete("/api/face/enroll", auth, async (req, res) => {
  try {
    await pool.execute("DELETE FROM face_profiles WHERE user_id=?", [req.user.sub]);
    res.json({ message: "Face enrollment deleted." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not delete face enrollment." });
  }
});

app.post("/api/face/match", auth, async (req, res) => {
  const probe = req.body.descriptor;
  if (!Array.isArray(probe) || probe.length !== 128 || probe.some(n => !Number.isFinite(n) || n < -2 || n > 2)) {
    return res.status(400).json({ error: "Invalid face descriptor." });
  }
  try {
    const [rows] = await pool.query(
      `SELECT fp.user_id, fp.descriptor, u.full_name, a.account_id, a.account_number, a.account_type
       FROM face_profiles fp
       JOIN users u ON u.user_id=fp.user_id AND u.active=TRUE
       JOIN customers c ON c.user_id=u.user_id
       JOIN accounts a ON a.customer_id=c.customer_id AND a.status='ACTIVE'
       WHERE fp.user_id <> ? ORDER BY fp.user_id`, [req.user.sub]
    );
    let best = null;
    for (const row of rows) {
      let saved;
      try { saved = typeof row.descriptor === "string" ? JSON.parse(row.descriptor) : row.descriptor; } catch { continue; }
      if (!Array.isArray(saved) || saved.length !== 128) continue;
      let sum = 0;
      for (let i=0;i<128;i++) sum += (Number(probe[i])-Number(saved[i])) ** 2;
      const distance = Math.sqrt(sum);
      if (!best || distance < best.distance) best = { row, distance };
    }
    // Face descriptors can be wrong or spoofed. This threshold is for a classroom demo only.
    if (!best || best.distance > 0.48) return res.status(404).json({ error: "No enrolled demo recipient matched. Ask the person to enroll or use QR Pay." });
    const matchToken = jwt.sign(
      { purpose: "face-pay-recipient", payerId: Number(req.user.sub), recipientUserId: Number(best.row.user_id), recipientAccountId: Number(best.row.account_id) },
      JWT_SECRET, { expiresIn: "2m", issuer: "banksphere-demo", audience: "banksphere-face-pay" }
    );
    res.json({
      matchToken,
      recipient: {
        name: best.row.full_name,
        accountNumber: "•••• " + String(best.row.account_number).slice(-4),
        accountType: best.row.account_type
      },
      expiresInSeconds: 120,
      message: "Possible match found. Verify the person and account details before continuing."
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Face matching failed. Run the updated database.sql first." });
  }
});

app.post("/api/face/pay", auth, async (req, res) => {
  const amount = validAmount(req.body.amount);
  const password = String(req.body.password || "");
  const fromNumber = String(req.body.fromAccountNumber || "").trim();
  let match;
  try {
    match = jwt.verify(String(req.body.matchToken || ""), JWT_SECRET, {
      issuer: "banksphere-demo", audience: "banksphere-face-pay"
    });
  } catch {
    return res.status(401).json({ error: "Recipient match expired. Scan again." });
  }
  if (match.purpose !== "face-pay-recipient" || Number(match.payerId) !== Number(req.user.sub)) {
    return res.status(403).json({ error: "Invalid recipient verification." });
  }
  if (!amount || !password || !fromNumber) return res.status(400).json({ error: "Choose a source account, amount and confirm your login password." });

  const connection = await pool.getConnection();
  try {
    const [userRows] = await connection.execute("SELECT password_hash FROM users WHERE user_id=? AND active=TRUE", [req.user.sub]);
    if (!userRows[0] || !(await bcrypt.compare(password, userRows[0].password_hash))) {
      return res.status(401).json({ error: "Password confirmation failed." });
    }
    await connection.beginTransaction();
    const [accounts] = await connection.execute(
      `SELECT a.account_id,a.account_number,a.balance,a.status,c.user_id
       FROM accounts a JOIN customers c ON c.customer_id=a.customer_id
       WHERE a.account_number=? OR a.account_id=? ORDER BY a.account_id FOR UPDATE`,
      [fromNumber, Number(match.recipientAccountId)]
    );
    const from = accounts.find(a => a.account_number === fromNumber);
    const to = accounts.find(a => Number(a.account_id) === Number(match.recipientAccountId));
    if (!from || !to || from.status !== "ACTIVE" || to.status !== "ACTIVE" || Number(to.user_id) !== Number(match.recipientUserId)) {
      await connection.rollback();
      return res.status(404).json({ error: "Source or recipient account is no longer available." });
    }
    if (Number(from.user_id) !== Number(req.user.sub) || Number(from.account_id) === Number(to.account_id)) {
      await connection.rollback();
      return res.status(403).json({ error: "Choose your own account and a different recipient." });
    }
    const fromBalance = Number(from.balance), toBalance = Number(to.balance);
    if (fromBalance < amount) {
      await connection.rollback();
      return res.status(400).json({ error: "Insufficient balance." });
    }
    const newFrom = Math.round((fromBalance-amount)*100)/100;
    const newTo = Math.round((toBalance+amount)*100)/100;
    await connection.execute("UPDATE accounts SET balance=? WHERE account_id=?", [newFrom, from.account_id]);
    await connection.execute("UPDATE accounts SET balance=? WHERE account_id=?", [newTo, to.account_id]);
    const reference = newReference();
    await connection.execute(
      `INSERT INTO transactions (reference_code,account_id,transaction_type,amount,balance_after,related_account_id,description)
       VALUES (?,?, 'TRANSFER_OUT', ?,?,?,?)`,
      [reference, from.account_id, amount, newFrom, to.account_id, "Face-to-Pay demo transfer"]
    );
    await connection.execute(
      `INSERT INTO transactions (reference_code,account_id,transaction_type,amount,balance_after,related_account_id,description)
       VALUES (?,?, 'TRANSFER_IN', ?,?,?,?)`,
      [reference+"IN", to.account_id, amount, newTo, from.account_id, "Face-to-Pay demo received"]
    );
    await connection.commit();
    res.json({ message: "Face-to-Pay demo transfer successful.", reference, balance: newFrom });
  } catch (err) {
    await connection.rollback();
    console.error(err);
    res.status(500).json({ error: "Face-to-Pay transfer failed." });
  } finally {
    connection.release();
  }
});

app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`BankSphere running at http://localhost:${PORT}`));
