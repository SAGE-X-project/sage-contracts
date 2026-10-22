"""Completion status for fixed test receipts; no execution or authority judgment."""
def finalize(record, coverage_met, failed):
    stages = record.get('stages', [])
    ready = (record.get('execution_complete') is True and coverage_met is True and failed is False
             and bool(stages) and all(s.get('complete') is True and s.get('cleanup_confirmed') is True for s in stages))
    return {'complete': ready, 'production_coverage_qualified': False, 'operating_ready': False}
