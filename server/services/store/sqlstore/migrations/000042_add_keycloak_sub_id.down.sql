-- Remove keycloak_sub_id column and index from users table

DROP INDEX IF EXISTS {{.prefix}}idx_users_keycloak_sub_id;

{{if .mysql}}
ALTER TABLE {{.prefix}}users DROP COLUMN keycloak_sub_id;
{{else}}
ALTER TABLE {{.prefix}}users DROP COLUMN IF EXISTS keycloak_sub_id;
{{end}}

