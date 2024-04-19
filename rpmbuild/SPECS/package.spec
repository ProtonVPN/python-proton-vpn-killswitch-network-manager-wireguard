%define unmangled_name proton-vpn-killswitch-network-manager-wireguard
%define version 0.0.2
%define release 1

Prefix: %{_prefix}

Name: python3-%{unmangled_name}
Version: %{version}
Release: %{release}%{?dist}
Summary: %{unmangled_name} library

Group: ProtonVPN
License: GPLv3
Vendor: Proton Technologies AG <opensource@proton.me>
URL: https://github.com/ProtonVPN/%{unmangled_name}
Source0: %{unmangled_name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot

BuildRequires: python3-proton-vpn-killswitch
BuildRequires: python3-proton-vpn-logger
BuildRequires: python3-setuptools
BuildRequires: python3-gobject
BuildRequires: NetworkManager
BuildRequires: python3-packaging

Requires: python3-proton-vpn-killswitch
Requires: python3-proton-vpn-logger
Requires: python3-gobject
Requires: NetworkManager
Requires: python3-packaging

%{?python_disable_dependency_generator}

%description
Package %{unmangled_name} library.


%prep
%setup -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES


%files -f INSTALLED_FILES
%{python3_sitelib}/proton/
%{python3_sitelib}/proton_vpn_killswitch_network_manager_wireguard-%{version}*.egg-info/
%defattr(-,root,root)

%changelog
* Wed Apr 24 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.0.2
- Fix connection glitch after adding route to VPN server

* Fri Apr 12 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.0.1
- Adapt kill switch to wireguard protocol
