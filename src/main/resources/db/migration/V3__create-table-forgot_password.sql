
CREATE TABLE forgot_password (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    user_password VARCHAR(255),
    expiration_time TIMESTAMP
);
