"""
Module for Kill Switch based on Network Manager.


Copyright (c) 2023 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from typing import Optional, TYPE_CHECKING

import subprocess  # nosec B404:blacklist

from proton.vpn.killswitch.interface import KillSwitch
from proton.vpn.killswitch.backend.linux.wireguard.killswitch_connection_handler\
    import KillSwitchConnectionHandler
from proton.vpn.killswitch.backend.linux.wireguard.util import is_ipv6_disabled
from proton.vpn import logging

if TYPE_CHECKING:
    from proton.vpn.connection import VPNServer


logger = logging.getLogger(__name__)


class WGKillSwitch(KillSwitch):
    """
    Kill Switch implementation using NetworkManager.

    A dummy Network Manager connection is created to block all non-VPN traffic.

    The way it works is that the dummy connection blocking non-VPN traffic is
    added with a lower priority than the VPN connection but with a higher
    priority than the other network manager connections. This way, the routing
    table uses the dummy connection for any traffic that does not go to the
    primary VPN connection.
    """

    def __init__(
            self, ks_handler: Optional[KillSwitchConnectionHandler] = None
    ):
        self._ks_handler = ks_handler or KillSwitchConnectionHandler()
        super().__init__()

    async def enable(
            self, vpn_server: Optional["VPNServer"] = None, permanent: bool = False
    ):  # noqa
        """Enables the kill switch."""
        # Block all traffic.
        await self._ks_handler.add_kill_switch_connection(permanent)

        if not vpn_server:
            return

        # Allow traffic going to the VPN server IP.
        await self._ks_handler.add_vpn_server_route(
            server_ip=vpn_server.server_ip
        )

    async def disable(self):
        """Disables general kill switch."""
        await self._ks_handler.remove_killswitch_connection()
        await self._ks_handler.remove_vpn_server_route()

    async def enable_ipv6_leak_protection(self, permanent: bool = False):
        """Enables IPv6 kill switch."""
        # Note that IPv6 leak protection is not required when using wireguard,
        # since wireguard already prevents IPv6 leaks. IPv6 leak protection is
        # added in case this kill switch implementation is also used on OpenVPN.
        await self._ks_handler.add_ipv6_leak_protection()

    async def disable_ipv6_leak_protection(self):
        """Disables IPv6 kill switch."""
        await self._ks_handler.remove_ipv6_leak_protection()

    @staticmethod
    def _get_priority() -> int:
        # The priority value is higher than the previous KS implementation (100)
        # so that this implementation takes precedence if both are installed.
        return 101

    @staticmethod
    def _validate(validate_params: dict = None):
        if not validate_params or validate_params.get("protocol") != "wireguard":
            return False

        try:
            KillSwitchConnectionHandler().is_network_manager_running  # noqa pylint: disable=expression-not-assigned
        except (ModuleNotFoundError, ImportError):
            logger.error("NetworkManager is not running.")
            return False

        try:
            subprocess.run(
                ["/usr/bin/apt", "show", "libnetplan1"],
                capture_output=True,
                check=True, shell=False
            )  # nosec B603:subprocess_without_shell_equals_true
        except subprocess.CalledProcessError:
            # if the apt command or the libnetplan1 package are not available then it's fine.
            return True

        # if libnetplan1 is installed (most probably ubuntu 24)
        # and IPv6 is disabled then the KS backend becomes invalid.
        if is_ipv6_disabled():
            logger.error(
                "Kill switch could not be enabled using libnetplan1 "
                "while IPv6 is disabled via the ipv6.disabled=1 kernel parameter."
            )
            return False

        return True
