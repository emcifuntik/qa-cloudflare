<?php

/*
	Plugin Name: Cloudflare User IP support
	Plugin URI: https://github.com/InfinityLF/q2a-cloudflare
	Plugin Description: Get visitors real IP address instead of CloudFlare's
	Plugin Version: 0.1
	Plugin Date: 2014-03-19
	Plugin Author: InfinityLF
	Plugin Author URI: https://github.com/InfinityLF
	Plugin License: GPLv2
	Plugin Minimum Question2Answer Version: 1.6
	Plugin Update Check URI: https://github.com/InfinityLF/q2a-cloudflare
*/

if (!defined('QA_VERSION')) { // don't allow this page to be requested directly from browser
	header('Location: ../../');
	exit;
}

qa_register_plugin_overrides('ip-override.php');
