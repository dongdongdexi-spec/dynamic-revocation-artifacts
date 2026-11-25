"""Repeat the frozen fixed-snapshot holdout with medium reasoning effort."""

from pathlib import Path

import ieee_holdout_snapshot as study


if __name__ == '__main__':
    study.OUT = study.study.WORK.parent / 'outputs' / 'IEEEAccess第二轮大修' / '固定快照medium'
    study.POLICY = {
        **study.POLICY,
        'reasoning': {'effort': 'medium'},
        'comparison_launcher_sha256': study.study.digest(Path(__file__)),
        'prospective_reference': '18 of 24 completed cases per topology; report all outcomes at both efforts.',
    }
    try:
        study.main()
    except study.HaltRun as error:
        raise SystemExit(str(error)) from None
