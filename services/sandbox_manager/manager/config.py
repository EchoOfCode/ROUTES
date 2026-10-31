import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    token: str
    docker_url: str
    gateway_url: str
    gateway_token: str
    gateway_container: str
    upload_volume: str
    uploads_dir: str
    max_concurrent_runs: int
    max_crawl_pages: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            token=os.environ.get("SANDBOX_MANAGER_TOKEN", ""),
            docker_url=os.environ.get("DOCKER_API_URL", "http://docker-proxy:2375"),
            gateway_url=os.environ.get("GATEWAY_CONTROL_URL", "http://network-gateway:8080"),
            gateway_token=os.environ.get("GATEWAY_CONTROL_TOKEN", ""),
            gateway_container=os.environ.get("GATEWAY_CONTAINER", "routes-p1-gateway"),
            upload_volume=os.environ.get("UPLOAD_VOLUME", "routes_uploads"),
            uploads_dir=os.environ.get("UPLOADS_DIR", "/data/uploads"),
            max_concurrent_runs=int(os.environ.get("MAX_CONCURRENT_RUNS", "4")),
            max_crawl_pages=min(int(os.environ.get("MAX_CRAWL_PAGES", "25")), 25),
        )
