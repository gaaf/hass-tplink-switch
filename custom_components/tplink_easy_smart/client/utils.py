import logging
from functools import wraps

from .const import FEATURE_POE, URL_POE_PORT_SETTINGS
from .coreapi import (
    ApiCallError,
    TpLinkJsonApi,
    VariableType,
    APICALL_ERRCAT_DISCONNECTED,
)

_LOGGER = logging.getLogger(__name__)


# ---------------------------
#   TpLinkFeaturesDetector
# ---------------------------
class TpLinkFeaturesDetector:
    def __init__(self, core_api: TpLinkJsonApi):
        """Initialize."""
        self._core_api = core_api
        self._available_features = set()
        self._is_initialized = False

    @staticmethod
    def disconnected_as_false(func):
        @wraps(func)
        async def wrapper(*args, **kwargs) -> bool:
            try:
                return await func(*args, **kwargs)
            except ApiCallError as ace:
                if ace.category == APICALL_ERRCAT_DISCONNECTED:
                    return False
                raise

        return wrapper

    @staticmethod
    def log_feature(feature_name: str):
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                try:
                    _LOGGER.debug("Check feature '%s' availability", feature_name)
                    result = await func(*args, **kwargs)
                    if result:
                        _LOGGER.debug("Feature '%s' is available", feature_name)
                    else:
                        _LOGGER.debug("Feature '%s' is not available", feature_name)
                    return result
                except Exception:
                    _LOGGER.debug(
                        "Feature availability check failed on %s", feature_name
                    )
                    raise

            return wrapper

        return decorator

    @log_feature(FEATURE_POE)
    @disconnected_as_false
    async def _is_poe_available(self) -> bool:
        data = await self._core_api.get_variables(URL_POE_PORT_SETTINGS)
        return len(data) > 0

    async def update(self) -> None:
        """Update the available features list."""
        if await self._is_poe_available():
            self._available_features.add(FEATURE_POE)

    def is_available(self, feature: str) -> bool:
        """Return true if feature is available."""
        return feature in self._available_features
