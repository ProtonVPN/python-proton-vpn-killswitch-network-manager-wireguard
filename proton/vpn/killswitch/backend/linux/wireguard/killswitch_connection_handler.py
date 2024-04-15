"""
This modules contains the classes that communicate with NetworkManager.


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
from ipaddress import ip_network
import asyncio
import concurrent.futures

from proton.vpn import logging
from proton.vpn.killswitch.backend.linux.wireguard.nmclient import NMClient
from proton.vpn.killswitch.backend.linux.wireguard.killswitch_connection import (
    KillSwitchConnection, KillSwitchGeneralConfig, KillSwitchIPConfig
)

logger = logging.getLogger(__name__)


def _get_connection_id(permanent: bool, ipv6: bool = False):
    if ipv6:
        return f"pvpn-killswitch-ipv6{'-perm' if permanent else ''}"

    return f"pvpn-killswitch{'-perm' if permanent else ''}"


def _get_interface_name(permanent: bool, ipv6: bool = False):
    if ipv6:
        return f"ipv6leakintrf{'1' if permanent else '0'}"

    return f"pvpnksintrf{'1' if permanent else '0'}"


async def _wrap_future(future: concurrent.futures.Future, timeout=5):
    """Wraps a concurrent.future.Future object in an asyncio.Future object."""
    return await asyncio.wait_for(
        asyncio.wrap_future(future, loop=asyncio.get_running_loop()),
        timeout=timeout
    )


class KillSwitchConnectionHandler:
    """Kill switch connection management."""

    def __init__(self, nm_client: NMClient = None):
        self._nm_client = nm_client
        self._ipv6_ks_settings = KillSwitchIPConfig(
            addresses=["fdeb:446c:912d:08da::/64"],
            dns=["::1"],
            dns_priority=-1400,
            gateway="fdeb:446c:912d:08da::1",
            ignore_auto_dns=True,
            route_metric=95
        )

    @staticmethod
    def _get_ipv4_ks_settings(server_ip: str = None):
        if server_ip:
            # accept/block all routes except the server IP route.
            routes = list(ip_network('0.0.0.0/0').address_exclude(ip_network(server_ip)))
            gateway = None
        else:
            routes = []  # accept/block all routes.
            gateway = "100.85.0.1"

        return KillSwitchIPConfig(
            addresses=["100.85.0.1/24"],
            dns=["0.0.0.0"],
            dns_priority=-1400,
            gateway=gateway,
            ignore_auto_dns=True,
            route_metric=98,
            routes=routes
        )

    @property
    def nm_client(self):
        """Returns the NetworkManager client."""
        if self._nm_client is None:
            self._nm_client = NMClient()

        return self._nm_client

    @property
    def is_network_manager_running(self) -> bool:
        """Returns if the Network Manager daemon is running or not."""
        return self.nm_client.get_nm_running()

    @property
    def is_connectivity_check_enabled(self) -> bool:
        """Returns if connectivity_check property is enabled or not."""
        return self.nm_client.connectivity_check_get_enabled()

    async def add_kill_switch_connection(self, permanent: bool):
        """Adds a dummy connection that swallows all traffic it receives.

        This dummy connection has more priority than an ethernet/wifi
        interface but with less priority than the VPN connection."""
        await self._ensure_connectivity_check_is_disabled()

        connection_id = _get_connection_id(permanent)
        connection = self.nm_client.get_active_connection(
            conn_id=connection_id
        )

        if connection:
            logger.debug("Kill switch was already present.")
            return

        interface_name = _get_interface_name(permanent)
        general_config = KillSwitchGeneralConfig(
            human_readable_id=connection_id,
            interface_name=interface_name
        )

        kill_switch = KillSwitchConnection(
            general_config,
            ipv4_settings=self._get_ipv4_ks_settings(),
            ipv6_settings=self._ipv6_ks_settings,
        )
        await _wrap_future(
            self.nm_client.add_connection_async(kill_switch.connection, save_to_disk=permanent)
        )
        logger.debug(f"{'Permanent' if permanent else 'Non-permanent'} kill switch added.")
        await self._remove_connection(
            connection_id=_get_connection_id(permanent=not permanent)
        )
        logger.debug(f"{'Non-permanent' if permanent else 'Permanent'} kill switch removed.")

    async def add_vpn_server_route(self, new_server_ip: str, old_server_ip: str = None):
        """Add route to allow outgoing traffic to the specified IP."""
        await self._ensure_connectivity_check_is_disabled()

        devices = self.nm_client.get_physical_devices()
        for device in devices:
            await _wrap_future(
                self.nm_client.add_route_to_device(
                    device, new_server_ip=new_server_ip, old_server_ip=old_server_ip
                )
            )
        logger.debug("VPN server route added.")

    async def remove_vpn_server_route(self, server_ip: str):
        """
        Remove a previously added VPN server route.
        If the route is not found then nothing happens.
        """
        devices = self.nm_client.get_physical_devices()
        for device in devices:
            await _wrap_future(
                self.nm_client.remove_route_from_device(device, server_ip)
            )
        logger.debug("VPN server route removed.")

    async def add_ipv6_leak_protection(self):
        """Adds IPv6 kill switch to prevent IPv6 leaks while using IPv4."""
        await self._ensure_connectivity_check_is_disabled()

        connection_id = _get_connection_id(permanent=False, ipv6=True)
        connection = self.nm_client.get_active_connection(
            conn_id=connection_id)

        if connection:
            logger.debug("IPv6 leak protection already present.")
            return

        interface_name = _get_interface_name(permanent=False, ipv6=True)
        general_config = KillSwitchGeneralConfig(
            human_readable_id=connection_id,
            interface_name=interface_name
        )

        kill_switch = KillSwitchConnection(
            general_config,
            ipv4_settings=None,
            ipv6_settings=self._ipv6_ks_settings,
        )

        await _wrap_future(
            self.nm_client.add_connection_async(kill_switch.connection, save_to_disk=False)
        )
        logger.debug("IPv6 leak protection added.")

    async def remove_killswitch_connection(self):
        """Removes full kill switch connection."""
        logger.debug("Removing full kill switch...")
        await self._remove_connection(_get_connection_id(permanent=True))
        await self._remove_connection(_get_connection_id(permanent=False))
        logger.debug("Full kill switch removed.")

    async def remove_ipv6_leak_protection(self):
        """Removes IPv6 kill switch connection."""
        logger.debug("Removing IPv6 leak protection...")
        await self._remove_connection(_get_connection_id(permanent=False, ipv6=True))
        logger.debug("IP6 leak protection removed.")

    async def _remove_connection(self, connection_id: str):
        connection = self.nm_client.get_connection(
            conn_id=connection_id)

        logger.debug(f"Attempting to remove {connection_id}: {connection}")

        if not connection:
            logger.debug(f"There was no {connection_id} to remove")
            return

        await _wrap_future(self.nm_client.remove_connection_async(connection))

    async def _ensure_connectivity_check_is_disabled(self):
        if self.is_connectivity_check_enabled:
            await _wrap_future(self.nm_client.disable_connectivity_check())
            logger.info("Network connectivity check was disabled.")
