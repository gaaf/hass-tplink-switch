import asyncio
import logging
#import pytest

from client.tplink_api import TpLinkApi
from client.classes import PoePriority, PoePowerLimit

logging.basicConfig(level=logging.DEBUG)
_LOGGER = logging.getLogger(__name__)


#@pytest.fixture
#def loop():
    #loop = asyncio.new_event_loop()
    #yield loop
    #loop.close()


#def test_coroutine2(loop: asyncio.AbstractEventLoop):
    #res = loop.run_until_complete(test_login())
    #assert res == 0


async def test_api():
    error = 0

    # Test connection
    _LOGGER.info("logging in")
    api = TpLinkApi(
        host="switch1",
        port=80,
        use_ssl=False,
        user="hass",
        password="Gc+04:f>aE:9ifzO",
        verify_ssl=False,
    )
    try:
        #res = await api.get_device_info()
        #_LOGGER.info("Device info: %s", res)

        res = await api.get_port_states()
        _LOGGER.info("Port States: %s", res)

        #res = await api.set_poe_limit(241)
        #_LOGGER.info("PoE State: %s", res)

        #res = await api.get_poe_state()
        #_LOGGER.info("PoE State: %s", res)

        res = await api.set_port_poe_settings(4, True, PoePriority.LOW, PoePowerLimit.CLASS_4)
        _LOGGER.info("PoE Port States: %s", res)

        #res = await api.get_port_poe_states()
        #_LOGGER.info("PoE Port States: %s", res)



    except Exception as ex:
        _LOGGER.warning("API failed: %s", {str(ex)})
        error = 1
    finally:
        await api.disconnect()

    return error


loop = asyncio.get_event_loop()
loop.run_until_complete(test_api())
loop.close()
