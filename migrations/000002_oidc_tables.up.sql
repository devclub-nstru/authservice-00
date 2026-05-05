CREATE TABLE IF NOT EXISTS clients (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id          text NOT NULL UNIQUE,
    client_secret_hash text NOT NULL,
    name               text NOT NULL,
    avatar_url         text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_clients_owner_id ON clients(owner_id);

CREATE TABLE IF NOT EXISTS client_redirect_uris (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    uri       text NOT NULL,
    UNIQUE(client_id, uri)
);

CREATE TABLE IF NOT EXISTS client_memberships (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id  uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text NOT NULL DEFAULT 'member',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(client_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_user_id ON client_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_client_id ON client_memberships(client_id);

CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash             text NOT NULL UNIQUE,
    client_id             uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id               uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id            uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri          text NOT NULL,
    scope                 text NOT NULL DEFAULT 'openid profile email',
    state                 text,
    nonce                 text,
    code_challenge        text,
    code_challenge_method text,
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oidc_tokens (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id         uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    access_token_hash  text NOT NULL UNIQUE,
    refresh_token_hash text UNIQUE,
    scope              text NOT NULL DEFAULT 'openid profile email',
    access_expires_at  timestamptz NOT NULL,
    refresh_expires_at timestamptz,
    revoked_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_oidc_tokens_session_id ON oidc_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_oidc_tokens_user_client ON oidc_tokens(user_id, client_id);
