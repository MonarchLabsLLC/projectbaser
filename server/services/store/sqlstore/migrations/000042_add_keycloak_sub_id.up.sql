-- Add keycloak_sub_id column to users table for Keycloak SSO integration
-- This stores the Keycloak subject ID for persistent user identification
-- even if the user's email changes in Keycloak

ALTER TABLE {{.prefix}}users ADD COLUMN keycloak_sub_id VARCHAR(255);

-- Create index for faster lookups by keycloak_sub_id
CREATE INDEX {{.prefix}}idx_users_keycloak_sub_id ON {{.prefix}}users(keycloak_sub_id);

