#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-vpn-killswitch-network-manager-wireguard",
    version="0.1.2",
    description="Proton VPN kill switch for Wireguard",
    author="Proton AG",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonVPN/pyhon-proton-vpn-killswitch-network-manager-wireguard",
    packages=find_namespace_packages(include=['proton.vpn.killswitch.backend.linux.wireguard']),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=["proton-vpn-api-core", "proton-vpn-logger", "pygobject", "pycairo", "packaging"],
    extras_require={
        "development": ["wheel", "pytest", "pytest-cov", "pytest-asyncio", "flake8", "pylint==2.15.5"]
    },
    entry_points={
        "proton_loader_killswitch": [
            "wireguard = proton.vpn.killswitch.backend.linux.wireguard:WGKillSwitch",
        ]
    },
    license="GPLv3",
    platforms="OS Independent",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ]
)
