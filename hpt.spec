%define reldate 20111128
%define reltype C
# may be one of: C (current), R (release), S (stable)

Name: hpt
Version: 1.9.%{reldate}%{reltype}
Release: 1
Group: Applications/FTN
Summary: HPT - the Husky Project tosser
URL: http://husky.sf.net
License: GPL
Requires: smapi >= 2.5, areafix >= 1.9
Source: %{name}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
HPT is the FTN tosser from the Husky Project.

%prep
%setup -q -n %{name}

%build
make
(cd fidoroute; make)

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install
test -s fidoroute/fidoroute \
	&& install -m 755 fidoroute/fidoroute %{buildroot}%{_bindir}/fidoroute

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%{_prefix}/*
