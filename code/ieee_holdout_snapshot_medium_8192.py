"""Repeat the medium-effort frozen holdout with an 8,192-token ceiling."""

from pathlib import Path

import ieee_holdout_snapshot as holdout


if __name__ == '__main__':
    holdout.OUT = holdout.study.WORK.parent / 'outputs' / 'IEEEAccess小修' / '固定快照medium8192'
    holdout.POLICY = {
        **holdout.POLICY,
        'reasoning': {'effort': 'medium'},
        'role_max_output_tokens': 8192,
        'plan_max_output_tokens': 8192,
        'comparison_launcher_sha256': holdout.study.digest(Path(__file__)),
        'prospective_reference': 'Report every case. Keep 18/24 completion as an engineering reference.',
    }
    try:
        holdout.main()
    except holdout.HaltRun as error:
        raise SystemExit(str(error)) from None
