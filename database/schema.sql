CREATE TABLE IF NOT EXISTS analysis_logs (
    id VARCHAR(36) PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    binary_label VARCHAR(20) NOT NULL,
    malware_prob FLOAT NOT NULL,
    threat_family VARCHAR(50),
    threat_level VARCHAR(20) NOT NULL,
    yara_matches TEXT NOT NULL DEFAULT '[]',
    feature_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sha256 ON analysis_logs(sha256);
CREATE INDEX IF NOT EXISTS idx_created_at ON analysis_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_binary_label ON analysis_logs(binary_label);
