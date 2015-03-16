Heartbleed-tester
=================

Test a server for heartbleed vunlnerability using a non-invasive test. This test will send a heartbeat packet with a padding that is too small for the spec and that
will be dropped in patched versions of OpenSSL. Since it provides as much data as it is asking for, it will not bleed memory. 

Installation
=================

Copy files to a path and install Zend Framework 1.12.11 such that /usr/share/php/ZendFramework/ZendFramework-1.12.11/library is valid. Or change the config.php locations.

Usage
=================

./heartbleed -c test -s example.com -p 443 -v

./heartbleed -c test -s example.com -v

./heartbleed -c test -s example.com
