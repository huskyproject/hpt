%define reldate 20160624
%define reltype C
# may be one of: C (current), R (release), S (stable)

Name: hpt
Version: 1.9.%{reldate}%{reltype}
Release: 1
Group: Applications/FTN
Summary: HPT - the Husky Project tosser
URL: http://huskyproject.org
License: GPL
Requires: fidoconf >= 1.9, perl >= 5.8.8
BuildRequires: huskylib >= 1.9, smapi >= 2.5
BuildRequires: fidoconf >= 1.9, areafix >= 1.9
Source: %{name}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
HPT is the FTN tosser from the Husky Project.

%prep
%setup -q -n %{name}

%build
sed -i -re 's,#LFLAGS =-s,LFLAGS =-s -static,g' makefile.inc
make
(cd fidoroute; make)

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install
test -s fidoroute/fidoroute \
	&& install -m 755 fidoroute/fidoroute %{buildroot}%{_bindir}/fidoroute
chmod -R a+rX,u+w,go-w %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%{_bindir}/*
%{_mandir}/man1/*
