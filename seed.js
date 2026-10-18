require("dotenv").config();
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");

async function main() {
  const db = await mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "banksphere"
  });

  const demoUsers = [
    { name: "Bank Administrator", email: "admin@banksphere.demo", password: "Admin@12345", role: "ADMIN" },
    { name: "Rahul Kumar", email: "rahul@banksphere.demo", password: "User@12345", role: "CUSTOMER", customerNo: "CUST1001", phone: "9000000001", accountNo: "1000000001", balance: 25000 },
    { name: "Priya Sharma", email: "priya@banksphere.demo", password: "User@12345", role: "CUSTOMER", customerNo: "CUST1002", phone: "9000000002", accountNo: "1000000002", balance: 18000 }
  ];

  for (const item of demoUsers) {
    const hash = await bcrypt.hash(item.password, 12);
    await db.execute(
      `INSERT INTO users (full_name,email,password_hash,role)
       VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE full_name=VALUES(full_name), role=VALUES(role)`,
      [item.name, item.email, hash, item.role]
    );

    const [[user]] = await db.execute("SELECT user_id FROM users WHERE email=?", [item.email]);
    if (item.role === "CUSTOMER") {
      await db.execute(
        `INSERT INTO customers (user_id,customer_number,phone,address,kyc_status)
         VALUES (?,?,?,?, 'VERIFIED')
         ON DUPLICATE KEY UPDATE phone=VALUES(phone)`,
        [user.user_id, item.customerNo, item.phone, "Demo Address"]
      );
      const [[customer]] = await db.execute("SELECT customer_id FROM customers WHERE user_id=?", [user.user_id]);
      await db.execute(
        `INSERT INTO accounts (customer_id,account_number,account_type,balance,status)
         VALUES (?,?, 'SAVINGS',?,'ACTIVE')
         ON DUPLICATE KEY UPDATE account_type='SAVINGS'`,
        [customer.customer_id, item.accountNo, item.balance]
      );
    }
  }

  console.log("Demo accounts ready:");
  console.log("Admin: admin@banksphere.demo / Admin@12345");
  console.log("Customer 1: rahul@banksphere.demo / User@12345");
  console.log("Customer 2: priya@banksphere.demo / User@12345");
  console.log("Change demo passwords before sharing the project.");
  await db.end();
}

main().catch(err => { console.error(err); process.exit(1); });
