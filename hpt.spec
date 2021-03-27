%global ver_major 1
%global ver_minor 9
%global ver_patch 0
%global reldate 20210327
%global reltype C
# may be one of: C (current), R (release), S (stable)

# release number for Release: header
%global relnum 1

# on default static application binary is built but using
# 'rpmbuild --without static' produces an application binary that uses
# dynamic libraries from other subprojects of Husky project
%if "%_vendor" == "alt"
    %def_with static
%else
    %bcond_without static
%endif

# if you use 'rpmbuild --with debug' then debug binary is produced
%if "%_vendor" == "alt"
    %def_without debug
%else
    %bcond_with debug
%endif

%global debug_package %nil

# if you use 'rpmbuild --without perl', then the application binary will be
# built without Perl
%if "%_vendor" == "alt"
    %def_with perl
%else
    %bcond_without perl
%endif

# for generic build; will override for some distributions
%global vendor_prefix %nil
%global vendor_suffix %nil
%global pkg_group Applications/Communications

# for CentOS, Fedora and RHEL
%if "%_vendor" == "redhat"
    %global vendor_suffix %dist
%endif

# for ALT Linux
%if "%_vendor" == "alt"
    %global vendor_prefix %_vendor
    %global pkg_group Networking/FTN
%endif

%global main_name hpt
%if %{with static}
Name: %main_name-static
%else
Name: %main_name
%endif
Version: %ver_major.%ver_minor.%reldate%reltype
Release: %{vendor_prefix}%relnum%{vendor_suffix}
%if "%_vendor" != "redhat"
Group: %pkg_group
%endif
Summary: HPT is the FTN tosser from the Husky Project
URL: https://github.com/huskyproject/%main_name/archive/v%ver_major.%ver_minor.%reldate.tar.gz
License: LGPLv2
Source: %main_name-%ver_major.%ver_minor.%reldate.tar.gz
BuildRequires: gcc
%if %{with static}
BuildRequires: huskylib-static >= 1.9, huskylib-static-devel >= 1.9
BuildRequires: smapi-static >= 2.5, smapi-static-devel >= 1.9
BuildRequires: fidoconf-static >= 1.9, fidoconf-static-devel >= 1.9
BuildRequires: areafix-static >= 1.9, areafix-static-devel >= 1.9
%else
BuildRequires: huskylib >= 1.9, huskylib-devel >= 1.9
BuildRequires: smapi >= 2.5, smapi-devel >= 1.9
BuildRequires: fidoconf >= 1.9, fidoconf-devel >= 1.9
BuildRequires: areafix >= 1.9, areafix-devel >= 1.9
Requires: huskylib >= 1.9, smapi >= 2.5, fidoconf >= 1.9, areafix >= 1.9
%endif
%if %{with perl}
%if "%_vendor" == "redhat"
BuildRequires: perl(:VERSION) >= 5.8.8, perl-devel >= 5.8.8
BuildRequires: perl(ExtUtils::Embed)
Requires: perl(:VERSION) >= 5.8.8
%else
BuildRequires: perl >= 5.8.8, perl-devel >= 5.8.8
Requires: perl >= 5.8.8
%endif
%endif

%description
HPT is the FTN tosser from the Husky Project


%package utils
%if "%_vendor" != "redhat"
Group: %pkg_group
%endif
Summary: Optional utilities for %name
%description utils
%summary

%prep
%setup -q -n %main_name-%ver_major.%ver_minor.%reldate

%build
%if %{with static}
    %if %{with debug}
        %if %{with perl}
            %make_build DEBUG=1
        %else
            %make_build PERL=0 DEBUG=1
        %endif
    %else
        %if %{with perl}
            %make_build
        %else
            %make_build PERL=0
        %endif
    %endif
%else
    %if %{with debug}
        %if %{with perl}
            %make_build DYNLIBS=1 DEBUG=1
        %else
            %make_build PERL=0 DYNLIBS=1 DEBUG=1
        %endif
    %else
        %if %{with perl}
            %make_build DYNLIBS=1
        %else
            %make_build PERL=0 DYNLIBS=1
        %endif
    %endif
%endif

%if %{with debug}
    %global __os_install_post %nil
%endif

%install
umask 022
%if %{with static}
    %if %{with debug}
        %make_install DEBUG=1
    %else
        %make_install
    %endif
%else
    %if %{with debug}
        %make_install DYNLIBS=1 DEBUG=1
    %else
        %make_install DYNLIBS=1
    %endif
%endif
chmod -R a+rX,u+w,go-w %buildroot

%files
%defattr(-,root,root)
%_bindir/hpt
%_mandir/man1/hpt.*

%files utils
%_bindir/*
%exclude %_bindir/hpt
%_mandir/man1/*
%exclude %_mandir/man1/hpt.*
