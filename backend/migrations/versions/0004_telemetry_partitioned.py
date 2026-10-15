"""partitioned telemetry events (ARG-025)

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-12
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Append-only high-rate data lives in a time-partitioned table, apart from configuration and incidents.
    # Daily partitions are created by the application (TelemetryStore.ensure_partitions); the DEFAULT partition
    # guarantees that an insert never fails because a day was not prepared yet.
    op.execute(
        """
        CREATE TABLE telemetry_events (
            id          BIGSERIAL,
            ts          TIMESTAMPTZ      NOT NULL,
            received_at TIMESTAMPTZ      NOT NULL,
            asset_id    INTEGER          NOT NULL,
            kind        VARCHAR(16)      NOT NULL,
            event_type  VARCHAR(16)      NOT NULL,
            track_id    VARCHAR(64),
            x           DOUBLE PRECISION,
            y           DOUBLE PRECISION,
            altitude    DOUBLE PRECISION,
            speed       DOUBLE PRECISION,
            heading     DOUBLE PRECISION,
            confidence  REAL,
            zone_code   VARCHAR(16),
            severity    VARCHAR(12)      NOT NULL DEFAULT 'info',
            payload     JSONB            NOT NULL DEFAULT '{}'::jsonb,
            PRIMARY KEY (id, ts)
        ) PARTITION BY RANGE (ts)
        """
    )
    op.execute("CREATE TABLE telemetry_events_default PARTITION OF telemetry_events DEFAULT")
    op.execute("CREATE INDEX ix_telemetry_ts ON telemetry_events (ts)")
    op.execute("CREATE INDEX ix_telemetry_asset_ts ON telemetry_events (asset_id, ts)")
    op.execute("CREATE INDEX ix_telemetry_track_ts ON telemetry_events (track_id, ts) WHERE track_id IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS telemetry_events CASCADE")
