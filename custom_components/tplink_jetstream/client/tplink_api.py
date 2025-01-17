"""TP-Link api."""

import logging
from typing import Tuple

from .classes import (
    PoeClass,
    PoePowerLimit,
    PoePowerStatus,
    PoePriority,
    PoeState,
    PortPoeState,
    PortSpeed,
    PortState,
    TpLinkSystemInfo,
)
from .const import (
    FEATURE_POE,
    URL_DEVICE_INFO,
    URL_INTERFACES,
    URL_PORT_STATES,
    URL_PORT_SETTINGS,
    URL_POE_GLOBAL,
    URL_POE_PORT_SETTINGS,

)
from .coreapi import TpLinkJsonApi, VariableType
from .utils import TpLinkFeaturesDetector

_LOGGER = logging.getLogger(__name__)

_POE_PRIORITIES_SET_MAP: dict[PoePriority, int] = {
    PoePriority.HIGH: 2,
    PoePriority.MIDDLE: 1,
    PoePriority.LOW: 0,
}

_POE_POWER_LIMITS_SET_MAP: dict[PoePowerLimit, int] = {
    PoePowerLimit.AUTO: 0,
    PoePowerLimit.CLASS_1: 1,
    PoePowerLimit.CLASS_2: 2,
    PoePowerLimit.CLASS_3: 3,
    PoePowerLimit.CLASS_4: 4
}


# ---------------------------
#   ActionError
# ---------------------------
class ActionError(Exception):
    def __init__(self, message: str):
        """Initialize."""
        super().__init__(message)
        self._message = message

    def __str__(self, *args, **kwargs) -> str:
        """Return str(self)."""
        return f"{self._message}"

    def __repr__(self) -> str:
        """Return repr(self)."""
        return self.__str__()


# ---------------------------
#   TpLinkApi
# ---------------------------
class TpLinkApi:
    def __init__(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        user: str,
        password: str,
        verify_ssl: bool,
    ) -> None:
        """Initialize."""
        self._core_api = TpLinkJsonApi(host, port, use_ssl, user, password, verify_ssl)
        self._is_features_updated = False
        self._features = TpLinkFeaturesDetector(self._core_api)
        self._port_count = None
        self._poe_port_count = None
        _LOGGER.debug("New instance of TpLinkApi created")

    async def _ensure_features_updated(self):
        if not self._is_features_updated:
            _LOGGER.debug("Updating available features")
            await self._features.update()
            self._is_features_updated = True
            _LOGGER.debug("Available features updated")

    async def is_feature_available(self, feature: str) -> bool:
        """Return true if specified feature is known and available."""
        await self._ensure_features_updated()
        return self._features.is_available(feature)

    async def authenticate(self) -> None:
        """Perform authentication."""
        await self._core_api.authenticate()

    async def disconnect(self) -> None:
        """Disconnect from api."""
        await self._core_api.disconnect()

    @property
    def device_url(self) -> str:
        """URL address of the device."""
        return self._core_api.device_url

    async def get_port_count(self) -> int:
        if self._port_count == None:
            ports = await self._core_api.get_variables(URL_PORT_SETTINGS)
            if not ports:
                raise ActionError("Can not get ports count")
            self._port_count = len(ports)

        return self._port_count

    async def get_poe_port_count(self) -> int:
        if self._poe_port_count == None:
            ports = await self._core_api.get_variables(URL_POE_PORT_SETTINGS)
            if not ports:
                raise ActionError("Can not get ports count")
            self._poe_port_count = len(ports)

        return self._poe_port_count

    async def get_device_info(self) -> TpLinkSystemInfo:
        """Return the device information."""
        sys = await self._core_api.get_variables(URL_DEVICE_INFO)
        ip = await self._core_api.get_variables(URL_INTERFACES)
        ip = ip[0]

        return TpLinkSystemInfo(
            name=sys["dev_name"],
            firmware=sys["fw_version"],
            hardware=sys["hw_version"],
            mac=sys["mac_address"],

            ip=ip["ip"],
            netmask=ip["mask"],
        )

    async def get_port_states(self) -> list[PortState]:
        """Return the port states."""
        data = await self._core_api.get_variables(URL_PORT_STATES)
        self._port_count = len(data)
        config = await self._core_api.get_variables(URL_PORT_SETTINGS)

        result: list[PortState] = []

        for idx, p in enumerate(data, start=1):
            state = PortState(
                number=idx,
                speed_config=PortSpeed(6 if p["speedCfg"] == 3 else p["speedCfg"] * 2 + (0 if p["duplexCfg"] == 0 else p["duplexCfg"] - 1)),
                speed_actual=PortSpeed(1 if p["linkStatus"] == 0 else 6 if p["speedLink"] == 3 else p["speedLink"] * 2 + p["duplexLink"] - 1),
                enabled=p["state"] == 1,
                flow_control_config=config[idx-1]["flowControl"] == 1,
                flow_control_actual=p["flowControl"] == 1,
            )
            result.append(state)

        return result

    async def get_port_poe_states(self) -> list[PortPoeState]:
        """Return the port states."""
        if not await self.is_feature_available(FEATURE_POE):
            return []

        data = await self._core_api.get_variables(URL_POE_PORT_SETTINGS)
        self._poe_port_count = len(data)

        result: list[PortPoeState] = []

        for p in data:
            state = PortPoeState(
                number=int(p["port"]),
                enabled=p["poeStatus"] == 1,
                priority=PoePriority(p["poePriority"]),
                current=p["current"],
                voltage=p["voltage"],
                power=p["power"],
                power_limit=PoePowerLimit.try_parse(p["powerLimit"]) or p["powerLimit"] / 10,
                power_status=PoePowerStatus(p["poeStatus"]),
                pd_class=PoeClass.try_parse(p["pdClass"]),
            )
            result.append(state)

        return result

    async def get_poe_state(self) -> PoeState | None:
        """Return the port states."""
        if not await self.is_feature_available(FEATURE_POE):
            return None

        _LOGGER.debug("Begin fetching POE states")

        poe_config = await self._core_api.get_variables(URL_POE_GLOBAL)
        if not poe_config:
            _LOGGER.warning("No POE status found, returning")
            return None

        unit = poe_config[0]
        return PoeState(
            power_limit=unit["limit"],
            power_remain=unit["remain"],
            power_limit_min=unit["min"],
            power_limit_max=unit["max"],
            power_consumption=unit["comsumption"],
        )

    async def set_port_state(
        self,
        number: int,
        enabled: bool,
        speed_config: PortSpeed,
        flow_control_config: bool,
    ) -> None:
        """Change port state."""

        if number < 1:
            raise ActionError("Port number should be greater than or equals to 1")
        if number > await self.get_port_count():
            raise ActionError(
                f"Port number should be less than or equals to {ports_count}"
            )

        port = {
            "key": f"1/0/{number}",
            "status": 1 if enabled else 0,
            "speed": speed_config.value,
            "flowControl": 1 if flow_control_config else 0
        }

        data = {
            "operation": "update",
            "tab": "unit1",
            "new": [ port, ],
        }
        result = await self._core_api.post(URL_PORT_SETTINGS, data)
        _LOGGER.debug("PORT_SET_RESULT: %s", result)

    async def set_poe_limit(self, limit: float) -> None:
        """Change poe limit."""
        if not await self.is_feature_available(FEATURE_POE):
            raise ActionError("POE feature is not supported by device")

        current_state = await self.get_poe_state()
        if not current_state:
            raise ActionError("Can not get actual PoE state")

        if limit < current_state.power_limit_min:
            raise ActionError(
                f"PoE limit should be greater than or equal to {current_state.power_limit_min}"
            )
        if limit > current_state.power_limit_max:
            raise ActionError(
                f"PoE limit should be less than or equal to {current_state.power_limit_max}"
            )

        data = {
            "operation": "update",
            "new": [
                {
                    "unit": 1,
                    "limit": limit,
                },
            ],
        }
        result = await self._core_api.post(URL_POE_GLOBAL, data)
        _LOGGER.debug("POE_SET_RESULT: %s", result)

    async def set_port_poe_settings(
        self,
        port_number: int,
        enabled: bool,
        priority: PoePriority,
        power_limit: PoePowerLimit | float,
    ) -> None:
        if not await self.is_feature_available(FEATURE_POE):
            raise ActionError("POE feature is not supported by device")
        """Change port poe settings."""
        if port_number < 1:
            raise ActionError("Port number should be greater than or equals to 1")
        if port_number > await self.get_poe_port_count():
            raise ActionError(
                f"Port number should be less than or equals to {poe_ports_count}"
            )

        ppriority = _POE_PRIORITIES_SET_MAP.get(priority)
        if ppriority == None:
            raise ActionError("Invalid PoePriority specified")

        if isinstance(power_limit, PoePowerLimit):
            ppowerlimit = int(power_limit)
            if ppowerlimit == None:
                raise ActionError("Invalid PoePowerLimit specified")
        elif isinstance(power_limit, float):
            if 0.1 <= power_limit <= 30.0:  # hardcoded in Tp-Link javascript
                ppowerlimit = 9
            else:
                raise ActionError("Power limit must be in range of 0.1-30.0")
        else:
            raise ActionError("Invalid power_limit specified")

        port =  {
                    "key": str(port_number),
                    "poeStatus": 1 if enabled else 0,
                    "poePriority": ppriority,
                    "powerLimit": ppowerlimit,
                }
        if ppowerlimit == 9:
            port["powerLimitValue"] = power_limit

        data = {
            "operation": "update",
            "tab": "unit1",
            "new": [ port, ],
        }
        result = await self._core_api.post(URL_POE_PORT_SETTINGS, data)
        _LOGGER.debug("POE_PORT_SETTINGS_SET_RESULT: %s", result)
