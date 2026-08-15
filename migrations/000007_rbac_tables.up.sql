CREATE TABLE IF NOT EXISTS client_permissions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name        text NOT NULL,
    value       text NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE(client_id, name, value)
);

CREATE INDEX IF NOT EXISTS idx_client_permissions_client_id ON client_permissions(client_id);

CREATE TABLE IF NOT EXISTS client_permission_groups (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name        text NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE(client_id, name)
);

CREATE INDEX IF NOT EXISTS idx_client_permission_groups_client_id ON client_permission_groups(client_id);

CREATE TABLE IF NOT EXISTS client_permission_group_items (
    group_id      uuid NOT NULL REFERENCES client_permission_groups(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES client_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, permission_id)
);

CREATE TABLE IF NOT EXISTS client_user_permission_groups (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    email       citext NOT NULL,
    user_id     uuid REFERENCES users(id) ON DELETE CASCADE,
    group_id    uuid NOT NULL REFERENCES client_permission_groups(id) ON DELETE CASCADE,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(client_id, email, group_id)
);

CREATE INDEX IF NOT EXISTS idx_client_user_perm_groups_email ON client_user_permission_groups(email) WHERE user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_client_user_perm_groups_user_id ON client_user_permission_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_client_user_perm_groups_client_id ON client_user_permission_groups(client_id);
