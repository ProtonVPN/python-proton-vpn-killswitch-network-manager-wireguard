"""
Wrapper over the NetworkManager client.


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
from concurrent.futures import Future
from threading import Thread, Lock
from typing import Optional, List

from packaging.version import Version

import gi
gi.require_version("NM", "1.0")
from gi.repository import NM, GLib, Gio, GObject  # pylint: disable=C0413 # noqa: E402

from proton.vpn import logging  # noqa: E402 pylint: disable=wrong-import-position

logger = logging.getLogger(__name__)


def _create_future():
    """Creates a future and sets its internal state as running."""
    future = Future()
    future.set_running_or_notify_cancel()
    return future


class NMClient:
    """
    Wrapper over the NetworkManager client.
    It also starts the GLib main loop used by the NetworkManager client.
    """
    _lock = Lock()
    _main_context = None
    _nm_client = None

    @classmethod
    def initialize_nm_client_singleton(cls):
        """
        Initializes the NetworkManager client singleton.

        If the singleton was initialized, this method will do nothing. However,
        if the singleton wasn't initialized it will initialize it, starting
        a new GLib MainLoop.

        A double-checked lock is used to avoid the possibility of multiple
        threads concurrently creating multiple instances of the NM client
        (with their own main loops).
        """
        if cls._nm_client:
            return

        with cls._lock:
            if not cls._nm_client:
                cls._initialize_nm_client_singleton()

    @classmethod
    def _initialize_nm_client_singleton(cls):
        cls._main_context = GLib.MainContext()

        # Setting daemon=True when creating the thread makes that this thread
        # exits abruptly when the python process exits. It would be better to
        # exit the thread running the main loop calling self._main_loop.quit().
        Thread(target=cls._run_glib_loop, daemon=True).start()

        def _init_nm_client():
            # It's important the NM.Client instance is created in the thread
            # running the GLib event loop so that then that's the thread used
            # for all GLib asynchronous operations.
            return NM.Client.new(cancellable=None)

        cls._nm_client = cls._run_on_glib_loop_thread(_init_nm_client).result()

    @classmethod
    def _run_glib_loop(cls):
        main_loop = GLib.MainLoop(cls._main_context)
        cls._main_context.push_thread_default()
        main_loop.run()

    @classmethod
    def _assert_running_on_glib_loop_thread(cls):
        """
        This method asserts that the thread running it is the one i:terating
        GLib's main loop.

        It's useful to call this method at the beginning of any code block
        that's supposed to run in GLib's main loop, to avoid hard-to-debug
        issues.

        For more info:
        https://developer.gnome.org/documentation/tutorials/main-contexts.html#checking-threading
        """
        if not cls._main_context.is_owner():
            raise RuntimeError("Code being run outside GLib's main loop.")

    @classmethod
    def _run_on_glib_loop_thread(cls, function, *args, **kwargs) -> Future:
        future = _create_future()

        def wrapper():
            cls._assert_running_on_glib_loop_thread()
            try:
                future.set_result(function(*args, **kwargs))
            except BaseException as exc:  # pylint: disable=broad-except
                future.set_exception(exc)

        cls._main_context.invoke_full(priority=GLib.PRIORITY_DEFAULT, function=wrapper)

        return future

    def __init__(self):
        self.initialize_nm_client_singleton()

    def add_connection_async(
        self, connection: NM.Connection, save_to_disk: bool = False
    ) -> Future:
        """
        Adds a new connection asynchronously.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/Client.html#NM.Client.add_connection_async
        :param connection: connection to be added.
        :return: a Future to keep track of completion.
        """
        future_conn_activated = _create_future()

        def _on_connection_added(nm_client, res, _user_data):
            if (
                    not nm_client or not res or
                    not (remote_connection := nm_client.add_connection_finish(res))
            ):
                future_conn_activated.set_exception(
                    RuntimeError(f"Error setting adding KS connection: {nm_client=}, {res=}")
                )
                return

            def _on_interface_state_changed(_device, new_state, _old_state, _reason):
                logger.debug(
                    f"{remote_connection.get_interface_name()} interface state changed "
                    f"to {NM.DeviceState(new_state).value_name}"
                )
                if (
                        NM.DeviceState(new_state) == NM.DeviceState.ACTIVATED
                        and not future_conn_activated.done()
                ):
                    future_conn_activated.set_result(remote_connection)

            device = self._nm_client.get_device_by_iface(remote_connection.get_interface_name())
            handler_id = device.connect("state-changed", _on_interface_state_changed)
            future_conn_activated.add_done_callback(
                lambda f: self._run_on_glib_loop_thread(
                    GObject.signal_handler_disconnect, device, handler_id
                ).result()
            )

            # The callback is manually called here because sometimes is never called. I assume that
            # when we connect to the state-changes signal the interface has already been activated.
            _on_interface_state_changed(device, device.get_state().real, None, None)

        def _add_connection_async():
            self._nm_client.add_connection_async(
                connection=connection,
                save_to_disk=save_to_disk,
                cancellable=None,
                callback=_on_connection_added,
                user_data=None
            )

        self._run_on_glib_loop_thread(_add_connection_async).result()

        return future_conn_activated

    def get_physical_devices(self) -> List[NM.Device]:
        """Returns all the active ethernet/wifi devices."""
        return [
            device for device in self._nm_client.get_devices() if (
                device.get_device_type() in (NM.DeviceType.ETHERNET, NM.DeviceType.WIFI) and
                device.get_state() is NM.DeviceState.ACTIVATED and
                device.get_active_connection()  # Maybe this is redundant.
            )
        ]

    @classmethod
    def _get_ipv4_gateway_from(cls, device: NM.Device) -> str:
        cls._assert_running_on_glib_loop_thread()

        connection = device.get_active_connection().get_connection()
        config = connection.get_setting_ip4_config()
        gateway = config.get_gateway()

        if not gateway:
            # If a static gateway is not found, try to get it from the DHCP config.
            dhcp_config = device.get_dhcp4_config()
            if dhcp_config and "routers" in dhcp_config.get_options():
                gateway = dhcp_config.get_options()["routers"]
                # There may be multiple gateways separated by comma. We get the first one
                gateway = gateway.split(",")[0].strip()

        if not gateway:
            raise RuntimeError(f"Gateway not found for interface {device.get_iface()}")

        return gateway

    @classmethod
    def _add_ipv4_route(cls, device, server_ip: str, gateway: str) -> NM.RemoteConnection:
        cls._assert_running_on_glib_loop_thread()

        connection = device.get_active_connection().get_connection()
        config = connection.get_setting_ip4_config()

        config.add_route(
            NM.IPRoute.new(
                family=GLib.SYSDEF_AF_INET,
                dest=server_ip,
                prefix=32,
                next_hop=gateway,
                metric=-1  # -1 just means that the default metric is applied.
            )
        )

        return connection

    @classmethod
    def _remove_ipv4_routes(cls, device, server_ip: str) -> NM.RemoteConnection:
        cls._assert_running_on_glib_loop_thread()

        connection = device.get_active_connection().get_connection()
        config = connection.get_setting_ip4_config()

        routes_to_remove = []
        for i in range(config.get_num_routes()):
            route = config.get_route(i)
            if route.get_dest() == server_ip and route.get_prefix() == 32:
                routes_to_remove.append(route)

        for route in routes_to_remove:
            config.remove_route_by_value(route)

        return connection

    @classmethod
    def _apply_connection_async(
            cls, device: NM.Device, connection: NM.RemoteConnection, future: Future
    ):
        cls._assert_running_on_glib_loop_thread()

        def on_device_reapplied(device, result, _data=None):
            try:
                device.reapply_finish(result)
                future.set_result(None)
            except Exception as exc:  # pylint: disable=broad-except
                future.set_exception(exc)

        def on_connection_commited(connection, result, _data=None):
            try:
                connection.commit_changes_finish(result)
                device.reapply_async(
                    # Not sure if it's ok to always pass version_id and flags set to 0.
                    connection, version_id=0, flags=0,
                    cancellable=None, callback=on_device_reapplied
                )
            except Exception as exc:  # pylint: disable=broad-except
                future.set_exception(exc)

        # By not saving the changes to disk, the route is gone after a restart.
        connection.commit_changes_async(
            save_to_disk=False, cancellable=None, callback=on_connection_commited
        )

    @classmethod
    def add_route_to_device(
            cls, device: NM.Device, new_server_ip: str, old_server_ip: Optional[str] = None
    ) -> Future:
        """
        Adds a route to the device to reach the new server ip via the gateway configured
        on the device.

        :param device: the device to apply the route to.
        :param new_server_ip: the IP to apply the route for.
        :param old_server_ip: if specified, routes for this IP will be removed before
          adding the new one.
        """
        route_added_future = _create_future()

        def _add_ipv4_route():
            try:
                if old_server_ip:
                    cls._remove_ipv4_routes(device, old_server_ip)

                gateway = cls._get_ipv4_gateway_from(device)
                connection = cls._add_ipv4_route(device, new_server_ip, gateway)

                cls._apply_connection_async(device, connection, route_added_future)
            except Exception as exc:  # pylint: disable=broad-except
                route_added_future.set_exception(exc)

        cls._run_on_glib_loop_thread(_add_ipv4_route)

        return route_added_future

    @classmethod
    def remove_route_from_device(cls, device: NM.Device, server_ip: str) -> Future:
        """
        Removes all the routes pointing to the specified server IP
        for the specified device.
        """
        route_removed_future = _create_future()

        def _remove_ipv4_routes():
            try:
                connection = cls._remove_ipv4_routes(device, server_ip)
                cls._apply_connection_async(device, connection, route_removed_future)
            except Exception as exc:  # pylint: disable=broad-except
                route_removed_future.set_exception(exc)

        cls._run_on_glib_loop_thread(_remove_ipv4_routes)

        return route_removed_future

    def remove_connection_async(
            self, connection: NM.RemoteConnection
    ) -> Future:
        """
        Removes the specified connection asynchronously.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/RemoteConnection.html#NM.RemoteConnection.delete_async
        :param connection: connection to be removed.
        :return: a Future to keep track of completion.
        """
        future_interface_removed = _create_future()

        def _on_connection_removed(connection, result, _user_data):
            if not connection or not result or not connection.delete_finish(result):
                future_interface_removed.set_exception(
                    RuntimeError(f"Error removing KS connection: {connection=}, {result=}")
                )
                return

        def _on_interface_state_changed(device, new_state, _old_state, _reason):
            logger.debug(
                f"{device.get_iface()} interface state changed to "
                f"{NM.DeviceState(new_state).value_name}"
            )
            if (
                    NM.DeviceState(new_state) == NM.DeviceState.DISCONNECTED
                    and not future_interface_removed.done()
            ):
                future_interface_removed.set_result(None)

        def _remove_connection_async():
            device = self._nm_client.get_device_by_iface(connection.get_interface_name())
            handler_id = device.connect("state-changed", _on_interface_state_changed)
            future_interface_removed.add_done_callback(
                lambda f: self._run_on_glib_loop_thread(
                    GObject.signal_handler_disconnect, device, handler_id
                ).result()
            )

            connection.delete_async(
                None,
                _on_connection_removed,
                None
            )

        self._run_on_glib_loop_thread(_remove_connection_async).result()

        return future_interface_removed

    def get_active_connection(self, conn_id: str) -> Optional[NM.ActiveConnection]:
        """
        Returns the specified active connection, if existing.
        :param conn_id: ID of the active connection.
        :return: the active connection if it was found. Otherwise, None.
        """
        def _get_active_connection():
            active_connections = self._nm_client.get_active_connections()

            for connection in active_connections:
                if connection.get_id() == conn_id:
                    return connection

            return None

        return self._run_on_glib_loop_thread(_get_active_connection).result()

    def get_connection(self, conn_id: str) -> Optional[NM.RemoteConnection]:
        """
        Returns the specified connection, if existing.
        :param conn_id: ID of the connection.
        :return: the connection if it was found. Otherwise, None.
        """
        return self._run_on_glib_loop_thread(
            self._nm_client.get_connection_by_id, conn_id
        ).result()

    def get_nm_running(self) -> bool:
        """Returns if NetworkManager daemon is running or not."""
        return self._run_on_glib_loop_thread(
            self._nm_client.get_nm_running
        ).result()

    def connectivity_check_get_enabled(self) -> bool:
        """Returns if connectivity check is enabled or not."""
        return self._run_on_glib_loop_thread(
            self._nm_client.connectivity_check_get_enabled
        ).result()

    def disable_connectivity_check(self) -> Future:
        """Since `connectivity_check_set_enabled` has been deprecated,
        we have to resort to lower lever commands.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/Client.html#NM.Client.connectivity_check_set_enabled

        This change is necessary since if this feature is enabled,
        dummy connection are inflated with a value of 20000.

        https://developer-old.gnome.org/NetworkManager/stable/NetworkManager.conf.html
        (see under `connectivity section`)
        """
        if Version(self._nm_client.get_version()) < Version("1.24.0"):
            # NM.Client.connectivity_check_set_enabled is deprecated since version 1.22
            # but the replacement method is only available in version 1.24.
            return self._run_on_glib_loop_thread(
                self._nm_client.connectivity_check_set_enabled, False
            )

        return self._dbus_set_property(
            object_path="/org/freedesktop/NetworkManager",
            interface_name="org.freedesktop.NetworkManager",
            property_name="ConnectivityCheckEnabled",
            value=GLib.Variant("b", False),
            timeout_msec=-1,
            cancellable=None
        )

    def _dbus_set_property(  # pylint: disable=too-many-arguments
            self, *userdata, object_path: str, interface_name: str, property_name: str,
            value: GLib.Variant, timeout_msec: int = -1,
            cancellable: Gio.Cancellable = None,
    ) -> Future:
        """Set NM properties since dedicated methods have been deprecated deprecated.
        Source: https://lazka.github.io/pgi-docs/#NM-1.0/classes/Client.html"""  # noqa

        future = _create_future()

        def _on_property_set(nm_client, res, _user_data):
            if not nm_client or not res or not nm_client.dbus_set_property_finish(res):
                future.set_exception(
                    RuntimeError(
                        f"Error disabling network connectivity check: {nm_client=}, {res=}"
                    )
                )
                return

            future.set_result(None)

        def _set_property_async():
            self._assert_running_on_glib_loop_thread()
            self._nm_client.dbus_set_property(
                object_path, interface_name, property_name,
                value, timeout_msec, cancellable, _on_property_set,
                userdata
            )

        self._run_on_glib_loop_thread(_set_property_async).result()

        return future
