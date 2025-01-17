"""TP-Link web api core functions."""

import asyncio
import logging
import re
from enum import Enum
from typing import Callable, Dict, Final, Iterable, Tuple, TypeAlias

import aiohttp
import json
import json5
from aiohttp import ClientResponse, ServerDisconnectedError

TIMEOUT: Final = 5.0

APICALL_ERRCODE_UNAUTHORIZED: Final = -2
APICALL_ERRCODE_REQUEST: Final = -3
APICALL_ERRCODE_DISCONNECTED: Final = -4

APICALL_ERRCAT_CREDENTIALS: Final = "user_pass_err"
APICALL_ERRCAT_REQUEST: Final = "request_error"
APICALL_ERRCAT_UNAUTHORIZED: Final = "unauthorized"
APICALL_ERRCAT_DISCONNECTED: Final = "disconnected"

AUTH_FAILURE_GENERAL: Final = "auth_general"
AUTH_FAILURE_CREDENTIALS: Final = "auth_invalid_credentials"
AUTH_USER_BLOCKED: Final = "auth_user_blocked"
AUTH_TOO_MANY_USERS: Final = "auth_too_many_users"
AUTH_SESSION_TIMEOUT: Final = "auth_session_timeout"

_SCRIPT_REGEX = r".*<script>(.*)<\/script>"
_VARIABLES_REGEX = r".*var\s+(?P<variable>[a-zA-Z0-9_]+)\s*=\s*(?P<value>[^;]+);\s*"
_ARRAY_VALUES_REGEX = r"\s*new\s*Array\s*\((?P<items>[^\)]+)\)"

_LOGGER = logging.getLogger(__name__)

VariableValue: TypeAlias = str | int | list[str] | dict[str, any]

_VAR_LOGON_INFO: str = "logonInfo"


# ---------------------------
#   VariableType
# ---------------------------
class VariableType(Enum):
    Str = 0
    Int = 1
    List = 2
    Dict = 3


# ---------------------------
#   AuthenticationError
# ---------------------------
class AuthenticationError(Exception):
    def __init__(self, message: str, reason_code: str) -> None:
        """Initialize."""
        super().__init__(message)
        self._message = message
        self._reason_code = reason_code

    @property
    def reason_code(self) -> str | None:
        """Error reason code."""
        return self._reason_code

    def __str__(self, *args, **kwargs) -> str:
        """Return str(self)."""
        return f"{self._message}; reason: {self._reason_code}"

    def __repr__(self) -> str:
        """Return repr(self)."""
        return self.__str__()


# ---------------------------
#   ApiCallError
# ---------------------------
class ApiCallError(Exception):
    def __init__(
        self, message: str, error_code: int | None, error_category: str | None
    ):
        """Initialize."""
        super().__init__(message)
        self._message = message
        self._error_code = error_code
        self._error_category = error_category

    @property
    def code(self) -> int | None:
        """Error code."""
        return self._error_code

    @property
    def category(self) -> int | None:
        """Error category."""
        return self._error_category

    def __str__(self, *args, **kwargs) -> str:
        """Return str(self)."""
        return f"{self._message}; code: {self._error_code}, category: {self._error_category}"

    def __repr__(self) -> str:
        """Return repr(self)."""
        return self.__str__()


# ---------------------------
#   _get_response_json
# ---------------------------
async def _get_response_json(response: ClientResponse) -> str:
    content_bytes = await response.content.read()
    text = content_bytes.decode("utf-8")
    return json.loads(text)



# ---------------------------
#   _check_authorized
# ---------------------------
def _check_authorized(response: ClientResponse, result: Dict) -> bool:
    if response.status != 200:
        return False
    if not result:
        return False
    if not result["success"]:
        return False
    return True


# ---------------------------
#   TpLinkJsonApi
# ---------------------------
class TpLinkJsonApi:
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
        _LOGGER.debug("New instance of TpLinkJsonApi created")
        self._user: str = user
        self._password: str = password
        self._verify_ssl: bool = verify_ssl
        self._session: aiohttp.ClientSession | None = None
        self._active_csrf: Dict | None = None
        self._is_initialized: bool = False
        self._call_locker = asyncio.Lock()
        self._auth_token: str = None

        schema = "https" if use_ssl else "http"
        self._base_url: str = f"{schema}://{host}:{port}"

    @property
    def device_url(self) -> str:
        """Return switch's configuration url."""
        return self._base_url

    def _get_url(self, path) -> str:
        """Return full address to the endpoint."""
        url = self._base_url + "/data/" + path
        if self._auth_token:
            url += "?" + self._auth_token
        return url

    async def _ensure_initialized(self) -> None:
        """Ensure that initial authorization was completed successfully."""
        if not self._is_initialized:
            await self.authenticate()
            self._is_initialized = True

    async def _post_raw(self, path: str, data: Dict) -> ClientResponse:
        """Perform POST request to the specified relative URL with specified body and return raw ClientResponse."""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            }
            _LOGGER.debug("Performing POST to %s", path)
            response = await self._session.post(
                url=self._get_url(path),
                data=json.dumps(data),
                headers=headers,
                verify_ssl=self._verify_ssl,
                timeout=TIMEOUT,
            )
            _LOGGER.debug("POST to %s performed, status: %s", path, response.status)
            return response
        except ServerDisconnectedError as sde:
            raise ApiCallError(
                f"Can not perform POST request at {path} cause of {repr(sde)}",
                APICALL_ERRCODE_DISCONNECTED,
                APICALL_ERRCAT_DISCONNECTED,
            )
        except Exception as ex:
            _LOGGER.error("POST %s failed: %s", path, str(ex))
            raise ApiCallError(
                f"Can not perform POST request at {path} cause of {repr(ex)}",
                APICALL_ERRCODE_REQUEST,
                APICALL_ERRCAT_REQUEST,
            )

    def _refresh_session(self) -> None:
        """Initialize the client session (if not exists) and clear cookies."""
        _LOGGER.debug("Refresh session called")
        if self._session is None:
            """Unsafe cookies for IP addresses instead of domain names"""
            jar = aiohttp.CookieJar(unsafe=True)
            self._session = aiohttp.ClientSession(cookie_jar=jar)
            _LOGGER.debug("Session created")
        self._session.cookie_jar.clear()
        self._auth_token = None
        self._active_csrf = None

    async def authenticate(self) -> None:
        """Perform authentication and return true when authentication success"""
        try:
            _LOGGER.debug("Authentication started")
            self._refresh_session()
            _LOGGER.debug("Performing logon")
            response = await self._post_raw(
                "login.json",
                {"username": self._user, "password": self._password, "operation": "write"},
            )

            if response.status != 200:
                _LOGGER.error(
                    "Authentication failed: can not perform POST, status is %s",
                    response.status,
                )
                raise AuthenticationError("Failed to get index", AUTH_FAILURE_GENERAL)

            result = await _get_response_json(response)
            if not result:
                raise AuthenticationError(
                    "Failed to get Logon response body", AUTH_FAILURE_GENERAL
                )

            if result["success"]:
                _LOGGER.debug("Authentication success")
                self._auth_token = "_tid_={}&usrLvl={}".format(result["data"]["_tid_"], result["data"]["usrLvl"])
                return
            elif result["errorcode"] == 1:
                raise AuthenticationError(
                    "The user name or the password is wrong", AUTH_FAILURE_CREDENTIALS
                )
            elif result["errorcode"] == 2:
                raise AuthenticationError(
                    "The user is not allowed to login", AUTH_USER_BLOCKED
                )
            elif result["errorcode"] == 3:
                raise AuthenticationError(
                    "The number of the user that allowed to login has been full",
                    AUTH_TOO_MANY_USERS,
                )
            elif result["errorcode"] == 4:
                raise AuthenticationError(
                    "The number of the login user has been full, it is allowed 16 people to login at the same time",
                    AUTH_TOO_MANY_USERS,
                )
            elif result["errorcode"] == 5:
                raise AuthenticationError(
                    "The session is timeout.",
                    AUTH_SESSION_TIMEOUT,
                )
            else:
                raise AuthenticationError(
                    "Unknonwn error '{}'".format(result["errorcode"]), AUTH_FAILURE_GENERAL
                )

        except AuthenticationError as ex:
            _LOGGER.warning("Authentication failed: %s", {repr(ex)})
            raise
        except ApiCallError as ex:
            _LOGGER.warning("Authentication failed: %s", {repr(ex)})
            raise AuthenticationError(
                "Authentication failed due to api call error", AUTH_FAILURE_GENERAL
            )
        except Exception as ex:
            _LOGGER.warning("Authentication failed: %s", {repr(ex)})
            raise AuthenticationError(
                "Authentication failed due to unknown error", AUTH_FAILURE_GENERAL
            )

    async def post(
        self, path: str, data: dict | None = None, **kwargs: any
    ) -> str | None:
        """Perform POST request to the relative address."""
        async with self._call_locker:
            await self._ensure_initialized()

            check_authorized: Callable[[ClientResponse, str], bool] = (
                kwargs.get("check_authorized") or _check_authorized
            )

            response = await self._post_raw(path, data)
            response_json = await _get_response_json(response)
            _LOGGER.debug("Response: %s", response_json)

            if not check_authorized(response, response_json):
                _LOGGER.debug("POST seems unauthorized, trying to re-authenticate")
                await self.authenticate()

                response = await self._post_raw(path, data)
                response_json = await _get_response_json(response)

                if not check_authorized(response, response_json):
                    raise ApiCallError(
                        f"Api call error, status:{response.status}",
                        APICALL_ERRCODE_UNAUTHORIZED,
                        APICALL_ERRCAT_UNAUTHORIZED,
                    )

            if not response_json["success"]:
                raise ApiCallError(
                    f"Api call error, status:{response.status}",
                    response_json["errorcode"],
                    APICALL_ERRCAT_DISCONNECTED,
                )

            return response_json["data"] if "data" in response_json else None

    async def get_variables(self, path: str) -> list | dict | None:
        """Perform GET request to the relative address and get the value of the specified variable."""
        result = await self.post(path, { 'operation': 'load', 'tab': 'unit1' })
        return result if result else None

    async def disconnect(self) -> None:
        """Close session."""
        _LOGGER.debug("Disconnecting")
        if self._session is not None:
            if self._auth_token is not None:
                await self.post("logout.json")
                self._auth_token = None
            await self._session.close()
            self._session = None
