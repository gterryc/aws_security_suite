import json
from datetime import datetime, date
from pathlib import Path
from typing import Any


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder que maneja objetos datetime y date."""
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


def save_json(data: Any, path: str) -> None:
    """Guarda cualquier objeto serializable a un archivo JSON."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, cls=DateTimeEncoder, ensure_ascii=False)


def load_json(path: str) -> Any:
    """Carga un archivo JSON y retorna su contenido."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: str) -> dict:
    """Carga un archivo YAML y retorna su contenido como dict."""
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def slugify(text: str) -> str:
    """Convierte un texto a formato slug para nombres de archivo."""
    return text.lower().replace(" ", "_").replace("/", "-")


def utcnow_iso() -> str:
    """Retorna el timestamp actual en formato ISO 8601 UTC."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")