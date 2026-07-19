"""Custom scalar types for the WCM reference SDK."""
from __future__ import annotations

import re
from typing import Any

from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema


class HashValue(str):
    """Cryptographic hash with an algorithm prefix.

    Valid formats:
      sha256:<64 lowercase hex chars>
      shake256:<64 lowercase hex chars>  (256-bit output, FIPS 202)

    Used for ``weights_hash``, serving-image and KBS-image measurements, and
    any other measurement field in the manifest (SPEC.md section 3.1).
    """

    _PATTERN = re.compile(r"^(sha256|shake256):[0-9a-f]{64}$")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, _core_schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return {"type": "string", "pattern": cls._PATTERN.pattern}

    @classmethod
    def _validate(cls, v: Any) -> "HashValue":
        if not isinstance(v, str):
            raise ValueError(f"HashValue must be a string, got {type(v).__name__}")
        if not cls._PATTERN.match(v):
            prefix = v.split(":")[0] if ":" in v else v[:10]
            raise ValueError(
                f"Invalid hash value (prefix='{prefix}'). "
                "Expected sha256:<64-hex> or shake256:<64-hex>"
            )
        return cls(v)

    @property
    def algorithm(self) -> str:
        return self.split(":")[0]

    @property
    def hex_digest(self) -> str:
        return self.split(":")[1]
