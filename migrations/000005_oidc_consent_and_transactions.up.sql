CREATE TABLE IF NOT EXISTS oidc_consents (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_oidc_consents_user_client ON oidc_consents(user_id, client_id);

CREATE TABLE IF NOT EXISTS oidc_authorization_transactions (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id             uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id               uuid REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri          text NOT NULL,
    scope                 text NOT NULL DEFAULT 'openid profile email',
    state                 text,
    nonce                 text,
    code_challenge        text,
    code_challenge_method text,
    response_type         text NOT NULL DEFAULT 'code',
    status                text NOT NULL DEFAULT 'pending',
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_oidc_tx_user_id ON oidc_authorization_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_tx_client_id ON oidc_authorization_transactions(client_id);
