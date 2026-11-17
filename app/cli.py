"""
Flask CLI Management Commands
=============================
Provides administrative CLI commands for background tasks, maintenance,
automated indicator lifecycle management, and production credential rotation.
"""

import click
import secrets
import string
from flask import Flask
from werkzeug.security import generate_password_hash

from app.services.ioc_expiry_service import (
    evaluate_and_expire_iocs,
    get_expiry_statistics,
    DEFAULT_TTL_POLICIES,
)


def register_cli_commands(app: Flask):
    """Register custom CLI commands with the Flask application instance."""

    @app.cli.command("expire-iocs")
    @click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Preview indicators eligible for expiry without modifying the database.",
    )
    @click.option(
        "--days",
        type=int,
        default=None,
        help="Global TTL days override for all indicator types.",
    )
    @click.option(
        "--type",
        "indicator_type",
        default=None,
        help="Restrict expiration to a specific indicator type (e.g. ip, domain, url, hash).",
    )
    def expire_iocs_command(dry_run: bool, days: int | None, indicator_type: str | None):
        """Evaluate and expire aged Indicators of Compromise (Task 13)."""
        click.echo("=" * 60)
        click.echo("  Threat Intelligence Platform — Automated IOC Expiry Job")
        click.echo(f"  Mode: {'DRY RUN (Simulation)' if dry_run else 'LIVE EXECUTION'}")
        if indicator_type:
            click.echo(f"  Filter Type: {indicator_type}")
        if days is not None:
            click.echo(f"  TTL Override: {days} days")
        click.echo("=" * 60)

        custom_policies = None
        if days is not None:
            custom_policies = {k: days for k in DEFAULT_TTL_POLICIES}

        result = evaluate_and_expire_iocs(
            ttl_policies=custom_policies,
            dry_run=dry_run,
            filter_type=indicator_type,
        )

        click.echo(f"Evaluated Active Indicators: {result['evaluated_count']}")
        click.echo(f"{'Eligible to Expire' if dry_run else 'Expired Successfully'}: {result['expired_count']}")

        if result["breakdown_by_type"]:
            click.echo("\nBreakdown by Type:")
            for t_name, count in result["breakdown_by_type"].items():
                click.echo(f"  - {t_name.upper()}: {count}")

        if result["expired_indicators"]:
            click.echo("\nSample Expired Indicators:")
            for ind in result["expired_indicators"][:10]:
                click.echo(
                    f"  [{ind['type'].upper()}] {ind['value']} "
                    f"(Age: {ind['age_days']}d / TTL: {ind['ttl_days']}d, Sev: {ind['severity']})"
                )
            if len(result["expired_indicators"]) > 10:
                click.echo(f"  ... and {len(result['expired_indicators']) - 10} more.")

        click.echo("\n[OK] IOC Expiry Job completed.\n")

    @app.cli.command("ioc-expiry-stats")
    def ioc_expiry_stats_command():
        """Display IOC lifecycle and expiration statistics."""
        stats = get_expiry_statistics()
        click.echo("=" * 60)
        click.echo("  IOC Lifecycle & Expiry Statistics")
        click.echo("=" * 60)
        click.echo(f"Total Indicators   : {stats['total_indicators']}")
        click.echo(f"Active Indicators  : {stats['active_indicators']}")
        click.echo(f"Expired Indicators : {stats['expired_indicators']}")
        click.echo(f"Inactive           : {stats['inactive_indicators']}")
        click.echo(f"False Positives    : {stats['false_positive_indicators']}")
        click.echo(f"Expiring Soon (7d) : {stats['expiring_soon_7d']}")

        click.echo("\nType Breakdown:")
        for t_name, data in stats.get("type_summary", {}).items():
            click.echo(
                f"  - {t_name.upper()}: Active={data['active']}, Expired={data['expired']} "
                f"(TTL: {data.get('ttl_days')}d)"
            )
        click.echo("=" * 60)

    @app.cli.command("audit-production-credentials")
    def audit_production_credentials_command():
        """Audit database for test accounts, static API keys, and default credentials."""
        from app.models.user import User

        click.echo("=" * 60)
        click.echo("  Production Credential & Account Audit")
        click.echo("=" * 60)

        users = User.query.all()
        dev_accounts = []
        static_keys = []

        for u in users:
            if u.api_key and any(x in u.api_key.lower() for x in ("test", "dummy", "12345")):
                static_keys.append(f"{u.username} ({u.email}) -> key: {u.api_key[:12]}...")

            if u.username in ("admin_user", "analyst_user", "plain_user", "test_user"):
                dev_accounts.append(f"{u.username} ({u.email}, role: {u.role}, active: {u.is_active})")

        click.echo(f"Total Users in Database: {len(users)}")
        click.echo(f"Static / Test API Keys Detected: {len(static_keys)}")
        for k in static_keys:
            click.echo(f"  [WARN] {k}")

        click.echo(f"\nDevelopment Seed Accounts Detected: {len(dev_accounts)}")
        for a in dev_accounts:
            click.echo(f"  [DEV ACCOUNT] {a}")

        click.echo("=" * 60)

    @app.cli.command("rotate-production-credentials")
    @click.option("--username", default="deepak", help="Target admin username to rotate.")
    @click.option("--new-password", default=None, help="Explicit password override.")
    def rotate_production_credentials_command(username: str, new_password: str | None):
        """Rotate test API keys, deactivate dev accounts, and rotate admin credentials."""
        from app import db
        from app.models.user import User
        from app.services.api_key_service import generate_user_api_key

        click.echo("=" * 60)
        click.echo("  Rotating Production Credentials for TIP")
        click.echo("=" * 60)

        # 1. Purge/Revoke static test API keys across all accounts
        users_with_keys = User.query.filter(User.api_key.isnot(None)).all()
        revoked_keys_count = 0
        for u in users_with_keys:
            if u.username != username and any(x in (u.api_key or "").lower() for x in ("test", "dummy", "12345")):
                u.api_key = None
                revoked_keys_count += 1
        db.session.commit()
        click.echo(f"[OK] Revoked {revoked_keys_count} static/test API keys.")

        # 2. Deactivate development seed accounts (except primary admin)
        dev_users = User.query.filter(
            User.username.in_(["admin_user", "analyst_user", "plain_user", "test_user"])
        ).all()
        deactivated_count = 0
        for du in dev_users:
            if du.username != username and du.is_active:
                du.is_active = False
                deactivated_count += 1
        db.session.commit()
        click.echo(f"[OK] Deactivated {deactivated_count} default development seed accounts.")

        # 3. Rotate Admin Password
        admin = User.query.filter_by(username=username).first()
        if not admin:
            click.echo(f"[ERROR] Admin account '{username}' not found!")
            return

        if not new_password:
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            new_password = "".join(secrets.choice(chars) for _ in range(20))

        admin.password_hash = generate_password_hash(new_password)
        admin.failed_login_count = 0
        admin.locked_until = None
        admin.session_token = secrets.token_hex(32)
        admin.is_active = True
        db.session.commit()

        # 4. Generate Production API Key for Admin
        ok, msg, new_api_key = generate_user_api_key(admin.id, label="Production Admin API Key")

        click.echo(f"[SUCCESS] Admin account '{username}' credentials successfully rotated!")
        click.echo(f"  - New Password : {new_password}")
        click.echo(f"  - New API Key  : {new_api_key}")
        click.echo("  - Session Token: Rotated (All prior sessions invalidated)")
        click.echo("=" * 60)
