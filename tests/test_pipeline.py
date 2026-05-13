from cybertrend.services.pipeline import PipelineService


class FakeIngestionService:
    def __init__(self):
        self.jobs = []

    def process_job(self, job):
        self.jobs.append(job)
        return 2


def test_manual_run_processes_all_rss_jobs_synchronously_without_queue():
    ingestion = FakeIngestionService()
    pipeline = PipelineService(queue=None, ingestion_service=ingestion)

    result = pipeline.trigger_manual_run()

    assert result["queued_jobs"] == 6
    assert result["processed_jobs"] == 6
    assert result["stored_items"] == 12
    assert len(result["failed_jobs"]) == 0
    source_types = {job["source_type"] for job in ingestion.jobs}
    assert source_types == {"rss"}
