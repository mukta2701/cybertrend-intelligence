from cybertrend.services.pipeline import PipelineService


class FakeIngestionService:
    def __init__(self):
        self.jobs = []

    def process_job(self, job):
        self.jobs.append(job)
        if job["source_type"] == "reddit":
            raise RuntimeError("Reddit client is not configured")
        return 2


def test_manual_run_processes_jobs_synchronously_without_queue():
    ingestion = FakeIngestionService()
    pipeline = PipelineService(queue=None, ingestion_service=ingestion)

    result = pipeline.trigger_manual_run()

    assert result["queued_jobs"] == 6
    assert result["processed_jobs"] == 1
    assert result["stored_items"] == 2
    assert len(result["failed_jobs"]) == 5
