.. _CMake: http://www.cmake.org
.. _SWIG: http://www.swig.org
.. _Xcode: https://developer.apple.com/xcode/
.. _MacPorts: http://www.macports.org
.. _Fink: http://www.finkproject.org
.. _Homebrew: http://mxcl.github.com/homebrew
.. _bro downloads page: http://bro.org/download/index.html

.. _installing-bro:

==============
Installing Bro
==============

.. contents::

Prerequisites
=============

Before installing Bro, you'll need to ensure that some dependencies
are in place.

Required Dependencies
---------------------

Bro requires the following libraries and tools to be installed
before you begin:

    * Libpcap                           (http://www.tcpdump.org)
    * OpenSSL libraries                 (http://www.openssl.org)
    * BIND8 library
    * Libmagic
    * Libz
    * Bash (for BroControl)

To build Bro from source, the following additional dependencies are required:

    * CMake 2.6.3 or greater            (http://www.cmake.org)
    * SWIG                              (http://www.swig.org)
    * Bison (GNU Parser Generator)
    * Flex  (Fast Lexical Analyzer)
    * Libpcap headers                   (http://www.tcpdump.org)
    * OpenSSL headers                   (http://www.openssl.org)
    * libmagic headers
    * zlib headers
    * Perl

To install the required dependencies, you can use:

* RPM/RedHat-based Linux:

  .. console::

     sudo yum install cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python-devel swig zlib-devel file-devel

* DEB/Debian-based Linux:

  .. console::

     sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev libmagic-dev

* FreeBSD:

  Most required dependencies should come with a minimal FreeBSD install
  except for the following.

  .. console::

      sudo pkg_add -r bash cmake swig bison python

  Note that ``bash`` needs to be in ``PATH``, which by default it is
  not. The FreeBSD package installs the binary into
  ``/usr/local/bin``.

* Mac OS X:

  Compiling source code on Macs requires first downloading Xcode_,
  then going through its "Preferences..." -> "Downloads" menus to
  install the "Command Line Tools" component.

  Lion (10.7) and Mountain Lion (10.8) come with all required
  dependencies except for CMake_, SWIG_, and ``libmagic``.

  Distributions of these dependencies can likely be obtained from your
  preferred Mac OS X package management system (e.g. MacPorts_, Fink_,
  or Homebrew_).

  Specifically for MacPorts, the ``swig``, ``swig-ruby``, ``swig-python``
  and ``file`` packages provide the required dependencies.


Optional Dependencies
---------------------

Bro can make use of some optional libraries and tools if they are found at
build time:

    * LibGeoIP (for geo-locating IP addresses)
    * gperftools (tcmalloc is used to improve memory and CPU usage)
    * ipsumdump (for trace-summary; http://www.cs.ucla.edu/~kohler/ipsumdump)
    * Ruby executable, library, and headers (for Broccoli Ruby bindings)

LibGeoIP is probably the most interesting and can be easily installed
on most platforms:

* RedHat Enterprise Linux:

  .. console::

      sudo yum install geoip-devel sendmail

* CentOS Linux:

  .. console::
  
      sudo yum install GeoIP-devel sendmail

* DEB/Debian-based Linux:

  .. console::

      sudo apt-get install libgeoip-dev sendmail

* FreeBSD using ports:

  .. console::

      sudo pkg_add -r GeoIP

* Mac OS X:

  Vanilla OS X installations don't ship with libGeoIP, but if
  installed from your preferred package management system (e.g.
  MacPorts, Fink, or Homebrew), they should be automatically detected
  and Bro will compile against them.

Additional steps may be needed to :ref:`get the right GeoIP database
<geolocation>`.


Installing Bro
==============

Bro can be downloaded in either pre-built binary package or source
code forms.


Using Pre-Built Binary Release Packages
=======================================

See the `bro downloads page`_ for currently supported/targeted
platforms for binary releases.

* RPM

  .. console::

      sudo yum localinstall Bro-*.rpm

* DEB

  .. console::

      sudo gdebi Bro-*.deb

* MacOS Disk Image with Installer

  Just open the ``Bro-*.dmg`` and then run the ``.pkg`` installer.
  Everything installed by the package will go into ``/opt/bro``.

The primary install prefix for binary packages is ``/opt/bro``.
Non-MacOS packages that include BroControl also put variable/runtime
data (e.g. Bro logs) in ``/var/opt/bro``.

Installing From Source
==========================

Bro releases are bundled into source packages for convenience and
available from the `bro downloads page`_. Alternatively, the latest
Bro development version can be obtained through git repositories
hosted at ``git.bro.org``.  See our `git development documentation
<http://bro.org/development/process.html>`_ for comprehensive
information on Bro's use of git revision control, but the short story
for downloading the full source code experience for Bro via git is:

.. console::

    git clone --recursive git://git.bro.org/bro

.. note:: If you choose to clone the ``bro`` repository
   non-recursively for a "minimal Bro experience", be aware that
   compiling it depends on several of the other submodules as well.

The typical way to build and install from source is (for more options,
run ``./configure --help``):

.. console::

    ./configure
    make
    make install

The default installation path is ``/usr/local/bro``, which would typically
require root privileges when doing the ``make install``.  A different 
installation path can be chosen by specifying the ``--prefix`` option.
Note that ``/usr`` and ``/opt/bro`` are the
standard prefixes for binary Bro packages to be installed, so those are
typically not good choices unless you are creating such a package.

Depending on the Bro package you downloaded, there may be auxiliary
tools and libraries available in the ``aux/`` directory. Some of them
will be automatically built and installed along with Bro. There are
``--disable-*`` options that can be given to the configure script to
turn off unwanted auxiliary projects that would otherwise be installed
automatically.  Finally, use ``make install-aux`` to install some of
the other programs that are in the ``aux/bro-aux`` directory.

OpenBSD users, please see our at `FAQ
<http://www.bro.org/documentation/faq.html>`_ if you are having
problems installing Bro.

Configure the Run-Time Environment
==================================

Just remember that you may need to adjust your ``PATH`` environment variable
according to the platform/shell/package you're using.  For example:

Bourne-Shell Syntax:

.. console::

   export PATH=/usr/local/bro/bin:$PATH

C-Shell Syntax:

.. console::

   setenv PATH /usr/local/bro/bin:$PATH

Or substitute ``/opt/bro/bin`` instead if you installed from a binary package.

