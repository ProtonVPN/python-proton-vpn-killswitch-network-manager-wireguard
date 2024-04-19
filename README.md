# Proton VPN Kill Switch for Wireguard

The `proton-vpn-killswitch-networ-managerwireguard` component is the implementation of the `proton-vpn-killswitch`
interface adapted for Wireguard.

## Development

Even though our CI pipelines always test and build releases using Linux distribution packages,
you can use pip to set up your development environment.

### Proton package registry

If you didn't do it yet, you'll need to set up our internal package registry.
[Here](https://gitlab.protontech.ch/help/user/packages/pypi_repository/index.md#authenticate-to-access-packages-within-a-group)
you have the documentation on how to do that.

### Known issues

This component depends on the PyGObject package. 
To be able to pip install PyGObject, please check the required distribution packages in the
[official documentation](https://pygobject.readthedocs.io/en/latest/devguide/dev_environ.html).

### Virtual environment

You can create the virtual environment and install the rest of dependencies as follows:

```shell
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Tests

You can run the tests with:

```shell
pytest
```
