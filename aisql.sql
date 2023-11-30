CREATE DATABASE aisql;
USE aisql;
CREATE USER 'root'@'localhost' IDENTIFIED BY '0000';
GRANT ALL PRIVILEGES ON aisql.* TO 'root'@'localhost';
FLUSH PRIVILEGES;
