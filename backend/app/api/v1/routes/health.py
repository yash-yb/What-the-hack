from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health_check() -> dict[str, str]:
    """Return a dependency-free readiness signal during the scaffold stage."""
    return {"status": "ok", "service": "what-the-hack-api"}

