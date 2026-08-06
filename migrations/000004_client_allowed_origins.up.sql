CREATE TABLE IF NOT EXISTS client_allowed_origins (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    origin    text NOT NULL,
    UNIQUE(client_id, origin)
);
