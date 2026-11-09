-- MySQL migration: add email verification fields to the users table.
-- Back up the database before applying this migration.
ALTER TABLE users
    ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN email_verification_code_hash VARCHAR(64) NULL,
    ADD COLUMN email_verification_expires_at DATETIME NULL,
    ADD COLUMN email_verification_last_sent_at DATETIME NULL;
