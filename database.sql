CREATE DATABASE IF NOT EXISTS banksphere
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE banksphere;

CREATE TABLE IF NOT EXISTS users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('ADMIN','CUSTOMER') NOT NULL DEFAULT 'CUSTOMER',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customers (
  customer_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  customer_number VARCHAR(24) NOT NULL UNIQUE,
  phone VARCHAR(20),
  address VARCHAR(255),
  kyc_status ENUM('PENDING','VERIFIED') NOT NULL DEFAULT 'PENDING',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_customers_user FOREIGN KEY (user_id)
    REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS accounts (
  account_id INT AUTO_INCREMENT PRIMARY KEY,
  customer_id INT NOT NULL,
  account_number VARCHAR(24) NOT NULL UNIQUE,
  account_type ENUM('SAVINGS','CURRENT') NOT NULL DEFAULT 'SAVINGS',
  balance DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  status ENUM('ACTIVE','FROZEN','CLOSED') NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_accounts_customer FOREIGN KEY (customer_id)
    REFERENCES customers(customer_id),
  CONSTRAINT chk_account_balance CHECK (balance >= 0)
);

CREATE TABLE IF NOT EXISTS transactions (
  transaction_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  reference_code VARCHAR(40) NOT NULL UNIQUE,
  account_id INT NOT NULL,
  transaction_type ENUM('DEPOSIT','WITHDRAWAL','TRANSFER_IN','TRANSFER_OUT') NOT NULL,
  amount DECIMAL(15,2) NOT NULL,
  balance_after DECIMAL(15,2) NOT NULL,
  related_account_id INT NULL,
  description VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_transactions_account FOREIGN KEY (account_id)
    REFERENCES accounts(account_id),
  CONSTRAINT fk_transactions_related_account FOREIGN KEY (related_account_id)
    REFERENCES accounts(account_id),
  CONSTRAINT chk_transaction_amount CHECK (amount > 0),
  INDEX idx_transactions_account_date (account_id, created_at)
);

CREATE OR REPLACE VIEW account_summary AS
SELECT a.account_id, a.account_number, a.account_type, a.balance, a.status,
       c.customer_number, u.full_name, u.email
FROM accounts a
JOIN customers c ON c.customer_id = a.customer_id
JOIN users u ON u.user_id = c.user_id;


-- Opt-in Face-to-Pay: stores only a numerical face descriptor, never a face photo.
CREATE TABLE IF NOT EXISTS face_profiles (
  face_profile_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  descriptor JSON NOT NULL,
  consented_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_face_profiles_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
