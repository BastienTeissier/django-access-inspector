"""
Snapshot Service for Django Access Inspector.

This service handles snapshot operations for CI mode, including loading,
saving, and comparing snapshots for security baseline management.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from .models import AnalysisResult, CIResult, Snapshot, UncheckedView
from .view_inspector import ViewInspectorService

logger = logging.getLogger(__name__)


class SnapshotService:
    """Service responsible for snapshot operations in CI mode."""

    SNAPSHOT_VERSION = "1.0"

    def load_snapshot(self, snapshot_path: str) -> Snapshot:
        """
        Load snapshot from file.

        Args:
            snapshot_path: Path to the snapshot file

        Returns:
            Snapshot object

        Raises:
            FileNotFoundError: If snapshot file doesn't exist
            ValueError: If snapshot file is invalid or malformed
        """
        if snapshot_path is None:
            raise ValueError("Snapshot path cannot be None")

        path = Path(snapshot_path)

        if not path.exists():
            raise FileNotFoundError(f"Snapshot file not found: {snapshot_path}")

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            # Validate required fields
            required_fields = [
                "version",
                "timestamp",
                "unauthenticated_endpoints",
                "unchecked_endpoints",
            ]
            for field in required_fields:
                if field not in data:
                    raise ValueError(f"Missing required field in snapshot: {field}")

            return Snapshot.from_dict(data)

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in snapshot file: {e}")
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Malformed snapshot file: {e}")

    def save_snapshot(
        self, analysis_result: AnalysisResult, snapshot_path: str
    ) -> None:
        """
        Save current analysis as snapshot file.

        Args:
            analysis_result: Analysis result to save as snapshot
            snapshot_path: Path where to save the snapshot file
        """
        # Extract unauthenticated endpoints
        view_inspector = ViewInspectorService()
        split_views = view_inspector.split_views_by_authentication(
            analysis_result.views
        )
        unauthenticated_endpoints = list(split_views.unauthenticated.keys())

        # Create snapshot
        snapshot = Snapshot(
            version=self.SNAPSHOT_VERSION,
            timestamp=datetime.now(),
            unauthenticated_endpoints=unauthenticated_endpoints,
            unchecked_endpoints=analysis_result.unchecked_views,
        )

        # Save to file
        path = Path(snapshot_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with path.open("w", encoding="utf-8") as f:
                json.dump(snapshot.to_dict(), f, indent=2, ensure_ascii=False)

            logger.info(f"Snapshot saved to {snapshot_path}")

        except (OSError, IOError) as e:
            raise ValueError(f"Failed to save snapshot: {e}")

    def compare_with_snapshot(
        self, analysis_result: AnalysisResult, snapshot: Snapshot
    ) -> CIResult:
        """
        Compare current analysis with snapshot to identify new security issues.

        Args:
            analysis_result: Current analysis result
            snapshot: Baseline snapshot to compare against

        Returns:
            CIResult with comparison details
        """
        # Extract current unauthenticated endpoints
        view_inspector = ViewInspectorService()
        split_views = view_inspector.split_views_by_authentication(
            analysis_result.views
        )
        current_unauthenticated = set(split_views.unauthenticated.keys())

        # Compare unauthenticated endpoints
        snapshot_unauthenticated = set(snapshot.unauthenticated_endpoints)
        new_unauthenticated = list(current_unauthenticated - snapshot_unauthenticated)
        removed_unauthenticated = list(
            snapshot_unauthenticated - current_unauthenticated
        )

        # Compare unchecked endpoints
        current_unchecked_set = {
            (uv.view, uv.cause) for uv in analysis_result.unchecked_views
        }
        snapshot_unchecked_set = {
            (uv.view, uv.cause) for uv in snapshot.unchecked_endpoints
        }

        new_unchecked_tuples = current_unchecked_set - snapshot_unchecked_set
        new_unchecked = [
            UncheckedView(view=view, cause=cause)
            for view, cause in new_unchecked_tuples
        ]

        # Determine success
        has_new_issues = len(new_unauthenticated) > 0 or len(new_unchecked) > 0
        success = not has_new_issues

        # Generate message
        message_parts = []
        if new_unauthenticated:
            endpoint_count = len(new_unauthenticated)
            message_parts.append(f"{endpoint_count} new unauthenticated endpoint(s)")

        if new_unchecked:
            unchecked_count = len(new_unchecked)
            message_parts.append(f"{unchecked_count} new unchecked endpoint(s)")

        if message_parts:
            message = f"CI check failed: {', '.join(message_parts)} found"
        else:
            message = "CI check passed: no new security issues detected"

        return CIResult(
            success=success,
            new_unauthenticated_endpoints=new_unauthenticated,
            new_unchecked_endpoints=new_unchecked,
            removed_endpoints=removed_unauthenticated,
            message=message,
        )
