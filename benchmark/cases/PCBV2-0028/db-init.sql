-- MariaDB init: create one database per TestLink version so each app can seed its OWN
-- version-matched schema/db_version (a 1.9.19 app rejects a 1.9.20-seeded DB with an
-- "upgrade required" page, so the three versions must NOT share a database).
CREATE DATABASE IF NOT EXISTS testlink_v0 CHARACTER SET utf8;
CREATE DATABASE IF NOT EXISTS testlink_v1 CHARACTER SET utf8;
CREATE DATABASE IF NOT EXISTS testlink_v2 CHARACTER SET utf8;
GRANT ALL PRIVILEGES ON testlink_v0.* TO 'testlink'@'%';
GRANT ALL PRIVILEGES ON testlink_v1.* TO 'testlink'@'%';
GRANT ALL PRIVILEGES ON testlink_v2.* TO 'testlink'@'%';
FLUSH PRIVILEGES;
