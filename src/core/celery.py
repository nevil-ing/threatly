'''from celery import Celery
from src.core.config import settings
from src.models.log import Log
from src.models.alert import Alert
from src.models.incident import Incident

celery_app = Celery(
    "teapec_backend",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["src.services.anomaly_detector"]
)

celery_app.conf.update(
    broker_connection_retry_on_startup=True, 
    broker_heartbeat=30, 
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
)

# Beat schedule configuration
celery_app.conf.beat_schedule = {
    # A descriptive name for the scheduled task
    'analyze-logs-every-30-seconds': {
        # The string path to the task function
        'task': 'src.services.anomaly_detector.analyze_logs_batch_task',
        # The schedule: run every 30.0 seconds
        'schedule': 30.0,
        # Arguments to pass to the task. Your task requires a 'threshold'.
        # Note: 'args' must be a tuple, so we use (0.5,) with a trailing comma.
        'args': (0.5,)
    },
}

if __name__ == '__main__':
    celery_app.start()
    '''