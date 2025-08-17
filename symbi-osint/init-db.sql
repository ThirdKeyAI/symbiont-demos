-- Database initialization for Symbi-OSINT
-- Create extensions and initial schema

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS osint;
CREATE SCHEMA IF NOT EXISTS analytics;
CREATE SCHEMA IF NOT EXISTS audit;

-- Create tables for agent data storage
CREATE TABLE IF NOT EXISTS osint.investigations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB,
    targets JSONB
);

CREATE TABLE IF NOT EXISTS osint.intelligence_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) REFERENCES osint.investigations(investigation_id),
    agent_type VARCHAR(100) NOT NULL,
    target_type VARCHAR(100) NOT NULL,
    target_value TEXT NOT NULL,
    report_data JSONB NOT NULL,
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    embedding vector(1536) -- For OpenAI embeddings
);

CREATE TABLE IF NOT EXISTS osint.correlations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) REFERENCES osint.investigations(investigation_id),
    entity_type VARCHAR(100) NOT NULL,
    entity_value TEXT NOT NULL,
    related_entities JSONB,
    correlation_score REAL CHECK (correlation_score >= 0 AND correlation_score <= 1),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_investigations_id ON osint.investigations(investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON osint.investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_created ON osint.investigations(created_at);

CREATE INDEX IF NOT EXISTS idx_reports_investigation ON osint.intelligence_reports(investigation_id);
CREATE INDEX IF NOT EXISTS idx_reports_agent_type ON osint.intelligence_reports(agent_type);
CREATE INDEX IF NOT EXISTS idx_reports_target ON osint.intelligence_reports(target_type, target_value);
CREATE INDEX IF NOT EXISTS idx_reports_created ON osint.intelligence_reports(created_at);

-- Vector similarity search index
CREATE INDEX IF NOT EXISTS idx_reports_embedding ON osint.intelligence_reports 
USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

CREATE INDEX IF NOT EXISTS idx_correlations_investigation ON osint.correlations(investigation_id);
CREATE INDEX IF NOT EXISTS idx_correlations_entity ON osint.correlations(entity_type, entity_value);

-- Analytics tables
CREATE TABLE IF NOT EXISTS analytics.agent_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(255) NOT NULL,
    agent_type VARCHAR(100) NOT NULL,
    execution_time_ms INTEGER NOT NULL,
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_metrics_agent_type ON analytics.agent_metrics(agent_type);
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON analytics.agent_metrics(timestamp);

-- Audit tables
CREATE TABLE IF NOT EXISTS audit.operations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    operation_type VARCHAR(100) NOT NULL,
    operation_details JSONB NOT NULL,
    user_id VARCHAR(255),
    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_type ON audit.operations(operation_type);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit.operations(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit.operations(user_id);

-- Grant permissions
GRANT USAGE ON SCHEMA osint TO symbi;
GRANT USAGE ON SCHEMA analytics TO symbi;
GRANT USAGE ON SCHEMA audit TO symbi;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA osint TO symbi;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO symbi;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO symbi;

GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA osint TO symbi;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO symbi;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO symbi;

-- Insert initial data
INSERT INTO osint.investigations (investigation_id, status, priority, metadata) VALUES 
('demo-investigation', 'demo', 'low', '{"description": "Demo investigation for testing"}')
ON CONFLICT (investigation_id) DO NOTHING;