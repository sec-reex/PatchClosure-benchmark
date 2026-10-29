CREATE DATABASE IF NOT EXISTS suitecrm_v1 CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
GRANT ALL ON suitecrm_v1.* TO 'suitecrm'@'%';
CREATE DATABASE IF NOT EXISTS suitecrm_v2 CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
GRANT ALL ON suitecrm_v2.* TO 'suitecrm'@'%';
FLUSH PRIVILEGES;
