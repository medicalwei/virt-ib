Name: libmlx4
Version: 1.0.5
Release: 1%{?dist}
Summary: Mellanox ConnectX InfiniBand HCA Userspace Driver

Group: System Environment/Libraries
License: GPLv2 or BSD
Url: http://openfabrics.org/
Source: http://openfabrics.org/downloads/mlx4/libmlx4-1.0.5.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: libibverbs-devel >= 1.1-0.1.rc2

%description
libmlx4 provides a device-specific userspace driver for Mellanox
ConnectX HCAs for use with the libibverbs library.

%package devel
Summary: Development files for the libmlx4 driver
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release}
Provides: libmlx4-static = %{version}-%{release}

%description devel
Static version of libmlx4 that may be linked directly to an
application, which may be useful for debugging.

%prep
%setup -q -n %{name}-1.0.5

%build
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=%{buildroot} install
# remove unpackaged files from the buildroot
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la $RPM_BUILD_ROOT%{_libdir}/libmlx4.so

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libmlx4-rdmav2.so
%{_sysconfdir}/libibverbs.d/mlx4.driver
%doc AUTHORS COPYING README

%files devel
%defattr(-,root,root,-)
%{_libdir}/libmlx4.a

%changelog
* Mon Mar 28 2012 Roland Dreier <roland@digitalvampire.org> - 1.0.5-1
- New upstream release

* Mon Mar 28 2012 Roland Dreier <roland@digitalvampire.org> - 1.0.4-1
- New upstream release

* Mon Mar 26 2012 Roland Dreier <roland@digitalvampire.org> - 1.0.3-1
- New upstream release

* Wed Jul 6 2011 Roland Dreier <roland@digitalvampire.org> - 1.0.2-1
- New upstream release

* Wed Jun 17 2009 Roland Dreier <rdreier@cisco.com> - 1.0.1-1
- New upstream release
- Change openib.org URLs to openfabrics.org URLs

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Sun Jan 27 2008 Roland Dreier <rdreier@cisco.com> - 1.0-2
- Spec file cleanups, based on Fedora review: don't mark
  libmlx4.driver as a config file, since it is not user modifiable,
  and change the name of the -devel-static package to plain -devel,
  since it would be empty without the static library.

* Sun Dec  9 2007 Roland Dreier <rdreier@cisco.com> - 1.0-1
- New upstream release

* Fri Apr  6 2007 Roland Dreier <rdreier@cisco.com> - 1.0-0.1.rc1
- Initial Fedora spec file
