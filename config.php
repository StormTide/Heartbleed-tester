<?php
define('ZFW_VERSION','1.12.11');
define('ZFW_PREFIX','/usr/share/php/ZendFramework'); //For a /usr/share/php/ZendFramework/ZendFramework-1.12.5/library install path
define('HEARTBLEED_TEST_SIZE', 16384); //Ideal is 16384, 4096 seems to be minimum. If you set lower than 16kb will get 16 bytes of padding from server.
define('HEARTBLEED_PADDING_SIZE', 16); //Spec defines a minimum of 16 bytes padding. We bleed into this data to test.
define('HEARTBLEED_TLS_VERSION', '03 01'); // 03 01 is TLSv1.0
