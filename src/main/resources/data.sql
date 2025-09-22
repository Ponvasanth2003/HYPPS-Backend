INSERT INTO roles (role_id, role_name, is_active) VALUES
(1, 'STUDENT', true),
(2, 'TEACHER', true),
(3, 'ADMIN', true)
ON CONFLICT (role_id) DO NOTHING;

-- Create teacher_verifications table
CREATE TABLE teacher_verifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    submission_type ENUM('CERTIFICATE', 'VIDEO') NOT NULL,
    file_url VARCHAR(500) NOT NULL,
    profile_verification_status ENUM('PENDING', 'VERIFIED', 'REJECTED') DEFAULT 'PENDING',
    rejection_reason TEXT,
    verified_at DATETIME,
    verified_by BIGINT,
    timer_started_at DATETIME NOT NULL,
    timer_expires_at DATETIME NOT NULL,
    second_chance_allowed BOOLEAN DEFAULT FALSE,
    retry_count INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (verified_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_verification (user_id),
    INDEX idx_verification_status (profile_verification_status),
    INDEX idx_timer_expires (timer_expires_at)
);

-- Create kyc_submissions table
CREATE TABLE kyc_submissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    govt_id_url VARCHAR(500) NOT NULL,
    bank_proof_url VARCHAR(500) NOT NULL,
    selfie_with_id_url VARCHAR(500),
    kyc_status ENUM('PENDING', 'VERIFIED', 'REJECTED') DEFAULT 'PENDING',
    rejection_reason TEXT,
    verified_at DATETIME,
    verified_by BIGINT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (verified_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_kyc (user_id),
    INDEX idx_kyc_status (kyc_status)
);

-- Add new columns to onboarding_data table
ALTER TABLE onboarding_data
ADD COLUMN timer_started_at DATETIME,
ADD COLUMN timer_expires_at DATETIME,
ADD COLUMN can_create_paid_classes BOOLEAN DEFAULT FALSE;

-- Add indexes for performance
ALTER TABLE onboarding_data
ADD INDEX idx_timer_expires (timer_expires_at),
ADD INDEX idx_can_create_paid (can_create_paid_classes);

-- Add new fields to users table
ALTER TABLE users ADD COLUMN phone_number VARCHAR(20);
ALTER TABLE users ADD COLUMN date_of_birth DATE;
ALTER TABLE users ADD COLUMN profile_picture VARCHAR(500);

-- Create security_events table
CREATE TABLE security_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    user_email VARCHAR(150),
    client_ip VARCHAR(45),
    details VARCHAR(1000),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20),
    user_agent VARCHAR(500),
    session_id VARCHAR(100)
);