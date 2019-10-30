<?php

function qa_remote_ip_address()
{
	$ipv4 = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/12',
		'172.64.0.0/13',
		'131.0.72.0/22'
	);
	
	$ipv6 = array(
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32'
	);

	$checkedIps = [];

	$checkIPv4 = function(?string $requestIp, string $ip)
	{
			$cacheKey = $requestIp.'-'.$ip;
			if (isset($checkedIps[$cacheKey])) {
					return $checkedIps[$cacheKey];
			}

			if (!filter_var($requestIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
					return $checkedIps[$cacheKey] = false;
			}

			if (false !== strpos($ip, '/')) {
					list($address, $netmask) = explode('/', $ip, 2);

					if ('0' === $netmask) {
							return $checkedIps[$cacheKey] = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
					}

					if ($netmask < 0 || $netmask > 32) {
							return $checkedIps[$cacheKey] = false;
					}
			} else {
					$address = $ip;
					$netmask = 32;
			}

			if (false === ip2long($address)) {
					return $checkedIps[$cacheKey] = false;
			}

			return $checkedIps[$cacheKey] = 0 === substr_compare(sprintf('%032b', ip2long($requestIp)), sprintf('%032b', ip2long($address)), 0, $netmask);
	};

	$checkIPv6 = function(?string $requestIp, string $ip)
	{
			$cacheKey = $requestIp.'-'.$ip;
			if (isset($checkedIps[$cacheKey])) {
					return $checkedIps[$cacheKey];
			}

			if (!((\extension_loaded('sockets') && \defined('AF_INET6')) || @inet_pton('::1'))) {
					throw new \RuntimeException('Unable to check Ipv6. Check that PHP was not compiled with option "disable-ipv6".');
			}

			if (false !== strpos($ip, '/')) {
					list($address, $netmask) = explode('/', $ip, 2);

					if ('0' === $netmask) {
							return (bool) unpack('n*', @inet_pton($address));
					}

					if ($netmask < 1 || $netmask > 128) {
							return $checkedIps[$cacheKey] = false;
					}
			} else {
					$address = $ip;
					$netmask = 128;
			}

			$bytesAddr = unpack('n*', @inet_pton($address));
			$bytesTest = unpack('n*', @inet_pton($requestIp));

			if (!$bytesAddr || !$bytesTest) {
					return $checkedIps[$cacheKey] = false;
			}

			for ($i = 1, $ceil = ceil($netmask / 16); $i <= $ceil; ++$i) {
					$left = $netmask - 16 * ($i - 1);
					$left = ($left <= 16) ? $left : 16;
					$mask = ~(0xffff >> $left) & 0xffff;
					if (($bytesAddr[$i] & $mask) != ($bytesTest[$i] & $mask)) {
							return $checkedIps[$cacheKey] = false;
					}
			}

			return $checkedIps[$cacheKey] = true;
	};

	$checkIP = function(?string $requestIp, $ips) use ($checkIPv6, $checkIPv4)
	{
		if (!\is_array($ips)) {
			$ips = [$ips];
		}

		$isIpV6 = substr_count($requestIp, ':') > 1;
		$method = substr_count($requestIp, ':') > 1 ? $checkIPv6 : $checkIPv4;

		foreach ($ips as $ip) {
			if (($isIpV6 && $checkIPv6($requestIp, $ip)) || (!$isIpV6 && $checkIPv4($requestIp, $ip))) {
				return true;
			}
		}

		return false;
	};

	if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
		$client_ip = qa_remote_ip_address_base();

		if($checkIP($client_ip, $ipv4) || $checkIP($client_ip, $ipv6))
		{
			return @$_SERVER['HTTP_CF_CONNECTING_IP'];
		}
		else
		{
			return $client_ip;
		}
	}
	else {
		return qa_remote_ip_address_base();
	}
}
