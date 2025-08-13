INSERT INTO roles (role_id, role_name, is_active) VALUES
(1, 'STUDENT', true),
(2, 'TEACHER', true),
(3, 'ADMIN', true)
ON CONFLICT (role_id) DO NOTHING;

CREATE TABLE teacher_verification (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    has_certificate BOOLEAN NOT NULL,
    certificate_url VARCHAR(500),
    teaching_video_url VARCHAR(500),
    current_submission_type VARCHAR(20) CHECK (current_submission_type IN ('CERTIFICATE', 'VIDEO')),
    profile_verification_status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (profile_verification_status IN ('PENDING', 'VERIFIED', 'REJECTED')),
    kyc_status VARCHAR(20) DEFAULT 'NOT_STARTED'
        CHECK (kyc_status IN ('NOT_STARTED', 'PENDING', 'VERIFIED', 'REJECTED')),
    is_verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP,
    timer_started_at TIMESTAMP NOT NULL,
    timer_completed_at TIMESTAMP,
    second_chance_allowed BOOLEAN DEFAULT TRUE,
    rejection_reason TEXT,
    admin_notes TEXT,
    can_create_paid_classes BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE kyc_documents (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    govt_id_url VARCHAR(500) NOT NULL,
    bank_proof_url VARCHAR(500) NOT NULL,
    selfie_with_id_url VARCHAR(500),
    kyc_status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (kyc_status IN ('PENDING', 'VERIFIED', 'REJECTED')),
    admin_notes TEXT,
    rejection_reason TEXT,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE verification_timeline (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    action_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    admin_id BIGINT REFERENCES users(id),
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);