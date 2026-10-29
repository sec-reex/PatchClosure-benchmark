-- Pre-create one database per phpMyFAQ version + a shared low-privilege DB user.
CREATE DATABASE IF NOT EXISTS pmf_v0 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS pmf_v1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS pmf_v2 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'pmf'@'%' IDENTIFIED BY 'pmfpass';
GRANT ALL PRIVILEGES ON pmf_v0.* TO 'pmf'@'%';
GRANT ALL PRIVILEGES ON pmf_v1.* TO 'pmf'@'%';
GRANT ALL PRIVILEGES ON pmf_v2.* TO 'pmf'@'%';
FLUSH PRIVILEGES;
