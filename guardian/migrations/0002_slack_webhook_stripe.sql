-- 0002 — Slack webhook + Stripe scaffolding.
--
-- Slack: per-account webhook URL + minimum severity to notify on.
-- Stripe: scaffolding tables only (no checkout flow yet — that's launch-week+).

-- ─── Slack ────────────────────────────────────────────────────────────────────
CREATE TABLE slack_integrations (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id        uuid UNIQUE NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  webhook_url       text NOT NULL,
  -- Only fire the webhook for severities >= this threshold.
  min_severity      text NOT NULL DEFAULT 'high'
                    CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
  enabled           boolean NOT NULL DEFAULT true,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  -- Track last fire for debugging / rate-limit detection.
  last_fired_at     timestamptz,
  last_error        text,
  last_error_at     timestamptz
);

CREATE INDEX idx_slack_integrations_account ON slack_integrations (account_id);

-- ─── Stripe scaffolding (tables only — no checkout flow at v0.1) ──────────────
--
-- These columns mirror Stripe's data model. The flow lands in v0.2 when we
-- open self-serve billing. For v0.1 launch: free preview tier for everyone,
-- 90 days. After that, Stripe is wired.

CREATE TABLE stripe_customers (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id          uuid UNIQUE NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  stripe_customer_id  text UNIQUE,  -- 'cus_...' from Stripe; NULL until paid signup
  preview_started_at  timestamptz NOT NULL DEFAULT now(),
  preview_ends_at     timestamptz NOT NULL DEFAULT now() + interval '90 days',
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_stripe_customers_account ON stripe_customers (account_id);
CREATE INDEX idx_stripe_customers_stripe_id ON stripe_customers (stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;

CREATE TABLE stripe_subscriptions (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id               uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  stripe_subscription_id   text UNIQUE NOT NULL,  -- 'sub_...' from Stripe
  stripe_customer_id       text NOT NULL,
  -- Plan: pro ($99), team ($299), org ($999). See STRATEGY.md §13.4.
  plan_id                  text NOT NULL CHECK (plan_id IN ('pro', 'team', 'org')),
  status                   text NOT NULL  -- 'active', 'past_due', 'canceled', etc.
                           CHECK (status IN ('active', 'past_due', 'canceled', 'unpaid', 'trialing', 'incomplete')),
  current_period_start     timestamptz NOT NULL,
  current_period_end       timestamptz NOT NULL,
  cancel_at_period_end     boolean NOT NULL DEFAULT false,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_stripe_subscriptions_account ON stripe_subscriptions (account_id);
CREATE INDEX idx_stripe_subscriptions_active ON stripe_subscriptions (account_id) WHERE status = 'active';

-- Cancel-at-period-end tracking handled by Stripe webhooks (v0.2).
-- For now: rows live forever; we read the latest active subscription per account.
