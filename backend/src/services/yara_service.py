import logging
from pathlib import Path
from typing import Any

from src.core.config import settings

logger = logging.getLogger(__name__)


class YaraService:
    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules = None
        self.warning: str | None = None
        path = rules_dir or settings.yara_rules_dir
        try:
            import yara

            files = sorted([*path.glob("*.yar"), *path.glob("*.yara")])
            if not files:
                self.warning = f"No YARA rule files found in {path}."
                logger.warning(self.warning)
                return
            sources = {f"rule_{index}": str(rule_file) for index, rule_file in enumerate(files)}
            self.rules = yara.compile(filepaths=sources)
            logger.info("Compiled YARA rules from %s", len(files))
        except ImportError:
            self.warning = "yara-python is not installed; signature scanning is disabled."
            logger.warning(self.warning)
        except Exception:
            self.warning = "YARA rules could not be loaded; signature scanning is disabled."
            logger.exception(self.warning)

    def scan(self, data: bytes) -> list[str]:
        if self.rules is None:
            return []
        try:
            matches = sorted({str(match.rule) for match in self.rules.match(data=data)})
            logger.info("YARA scan completed: %d match(es)", len(matches))
            return matches
        except Exception:
            logger.warning("YARA scanning failed; continuing without matches", exc_info=True)
            return []
