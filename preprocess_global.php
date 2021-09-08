<?php
/*
remember, preprocess_global.php is called each time the php interpeter is started

brian 2021-03-11 added !function_exists() around each function for easier debugging (since preprocess_global.php is called before every php script, including itself!)
*/
// set up exceptions
$CheckForHacking = true;
$CheckForAdvertiserID = true;
$LogIPAddress = true; // <- if logging gets to be too much, disable it here

// look for cases when hack checks should be excluded
if ($CheckForHacking) {
	switch ($_SERVER['SCRIPT_URL']) {
		case '/admin/access-log-ip-is-blocked.phtml': // <- if it WAS triggered, allow the team to unblock
		case '/admin/access-log-too-many-times.phtml': // <- sometimes $_GET has something which triggers blocking
		case '/admin/access-log-output-problem-ip-addresses.phtml':
		case '/admin/gen-sitemap-2020.php':
		case '/admin/test-email.phtml': // <- automated
		case '/blogs/gen-blog-sitemap.php':
		case '/img/server-image.php':
		case '/inc/eccouncil.json.php':
		case '/lib/preprocess_global.inc.php':
		case '/lib/preprocess_global.php':
		case '/error/oops.html':
		case '/portal/instructor-portal/ajax/main_ajax.php':
		case '/robots.txt': // <- let robots.txt be seen
		case '/webhook/ipregistry/ipregistry.api.php':
			$CheckForHacking = false;
			$CheckForAdvertiserID = false;
			$LogIPAddress = false;
			break;
	}
}

if ($CheckForHacking) {
	// whitelist
	if (@strpos($_SERVER['SCRIPT_URL'], "st-john's", 1)) {
		$CheckForHacking = false;
	} elseif (@strpos($_SERVER['SCRIPT_URL'], '/student-portal/edit-account.phtml', 1)) {
		// QS data sometimes has single quote
		$CheckForHacking = false;
		$CheckForAdvertiserID = false;
	} elseif (@strpos($_SERVER['SCRIPT_URL'], '/portal/instructor-portal/ajax/main_ajax.php', 1)) {
		// QS data sometimes has single quote
		$CheckForHacking = false;
		$CheckForAdvertiserID = false;
	} elseif (@strpos($_SERVER['SCRIPT_URL'], '/esi-validate-email-address.php', 1)) {
		// QS data sometimes has single quote
		$CheckForHacking = false;
	}
	
	if (!$CheckForHacking) {
		//@mail('brian@netcomlearning.com','/lib/preprocess_global.php > No Hack Check', serialize($_SERVER));
	}
}

if ($CheckForHacking) {
	// some of the recent webhooks are coming in from 
	$pos = strpos($_SERVER['SCRIPT_URL'], '/webhook/');
	if ($pos === false) {
		// wasn't found
	} else {
		// was found!
		//@mail('brian@netcomlearning.com','/lib/preprocess_global.php', '/webhook/ found: ' . $_SERVER['SCRIPT_URL']);
		$CheckForHacking = false;
		$CheckForAdvertiserID = false;
	}
}

if ($CheckForHacking) {
	require_once("$_SERVER[DOCUMENT_ROOT]/lib/preprocess_global.inc.php"); 
	foreach (ExemptIPAddresses() as $ExemptIPAddress) {
		if ($ExemptIPAddress == $_SERVER['REMOTE_ADDR']) {
			$CheckForHacking = false;
			$CheckForAdvertiserID = true;
			break;
		}
	}
	/*	
	switch ($_SERVER['REMOTE_ADDR']) {
		case '203.122.18.26': // India
			$CheckForHacking = false;
			$CheckForAdvertiserID = true;
			break;
		case '206.252.202.130': // NYC
			$CheckForHacking = false;
			$CheckForAdvertiserID = true;
			break;
	}
	*/
}

if ($LogIPAddress) {
	require_once("$_SERVER[DOCUMENT_ROOT]/lib/preprocess_global.inc.php");
	LogIPAddress($_SERVER['REMOTE_ADDR']);
}

if ($CheckForHacking) {
	require_once("$_SERVER[DOCUMENT_ROOT]/lib/preprocess_global.inc.php"); 
	
	SlowDownByIPAddressTOO($_SERVER); // <- this does NOT write to blockade
	
	SlowDownByIPAddress($_SERVER); // <- this does NOT write to blockade
	
	SlowDownByUserAgent($_SERVER); // <- this does NOT write to blockade
	
	# SQLI Watch #1
	$QS = $_GET;
	$QS['SCRIPT_URI_(other)'] = $_SERVER['SCRIPT_URI']; // <- some of the *fake* QS aren't caught
	//WatchForSQLInjection($_GET); // <- 2018-05-17 - this writes to blockade
	// brian 2019-04-26 I just noticed $QS was put together but never used!
	WatchForSQLInjection($QS); // <- 2018-05-17 - this writes to blockade
	
	// brian - 2018-05-21 - some use urlredirect. "$_GET" is different (we're safe, but should still block these IP addresses)
	# SQLI Watch #2
	//WatchForSQLInjection(array(0 => $_SERVER['SCRIPT_URI'])); // <- 2018-05-17 - this writes to blockade
	
	WatchForKnownHackingRequests($_SERVER); // <- 2018-05-17 - this writes to blockade
	
	// brian - 2018-05-21 - confirmed that POST is also seen by this script
	//if (strtoupper($_SERVER['REQUEST_METHOD']) <> 'GET') {
		//@mail('brian@netcomlearning.com', 'not get', serialize($_SERVER));
	//}
	
	//WatchContentType($_SERVER);
	
	// PCI Fix
	if (preg_match("/(dir=|script>|javascript:alert)/i",$_SERVER['REQUEST_URI'])) {
		die("Error found - xss issue. (1)");
	/*
	} else if (preg_match("/(advid=%27)$/i",$_SERVER['REQUEST_URI'])) {
		die("advid not recognized, error found.");
	*/
	}
	
	if (preg_match("/(dir=|script>|javascript:alert>)/i",$_SERVER['QUERY_STRING'])) {
		die("Error found - xss issue. (2)");
	}
	
	/*
	if (isset($_REQUEST['ID'])) {
		if (!is_numeric($_REQUEST['ID'])) {
			// these scripts do not need to apply
			if (preg_match("/(popupUpload2.phtml|popupUpload.phtml)/",$_SERVER['SCRIPT_URL'])) {
	
			} else {
				die("Error found - proper format for ID required.");
			}
		}
	}
	*/
}

if ($CheckForAdvertiserID) {
	if (isset($_GET['advid'])) {
		if ($_GET['advid']) { // <- is_numeric(NULL) would be false
			if (!is_numeric($_GET['advid'])) {
				//@mail('brian@netcomlearning.com', '/lib/preprocess_global.php > bad advid format ($_GET)', "\$_GET\r\n\r\n" . serialize($_GET) . "\r\n\r\n\$_SERVER\r\n\r\n" . serialize($_SERVER));
				unset($_GET['advid']);
			}
		}
	}
	
	if (isset($_POST['advid'])) {
		if ($_POST['advid']) { // <- is_numeric(NULL) would be false
			if (!is_numeric($_POST['advid'])) {
				//@mail('brian@netcomlearning.com', '/lib/preprocess_global.php > bad advid format ($_POST)', serialize($_POST));
				unset($_POST['advid']);
			}
		}
	}
	
	if (isset($_COOKIE['advdata'])) {
		if ($_COOKIE['advdata']) { // <- is_numeric(NULL) would be false
			if (!is_numeric($_COOKIE['advdata'])) {
				//@mail('brian@netcomlearning.com', '/lib/preprocess_global.php > bad advdata format (cookie)', serialize($_COOKIE));
				setcookie(
					'advdata', 
					(int)$_COOKIE['advdata'] ? (int)$_COOKIE['advdata'] : 49, // <- try to salvage, if not: unknown advertiser
					CookieExpire(), // <- expire
					CookiePath(), // <- path
					CookieDomain() // <- domain - add this so mkt.netcomlearning.com can see it, too
				);
			}
		}
	}

	if (isset($_GET['advid']) && (int)$_GET['advid']) {
		// cookie coming from GET
		setcookie(
			'advdata', // <- name
			(int)$_GET['advid'], // <- value
			CookieExpire(), // <- expire
			CookiePath(), // <- path
			CookieDomain() // <- domain - add this so mkt.netcomlearning.com can see it, too
		);
	} elseif (isset($_POST['advid']) && (int)$_POST['advid']) {
		// cookie coming from POST
		setcookie(
			'advdata', // <- name
			(int)$_POST['advid'], // <- value
			CookieExpire(), // <- expire
			CookiePath(), // <- path
			CookieDomain() // <- domain - add this so mkt.netcomlearning.com can see it, too
		);
	} elseif (strpos($_SERVER['REQUEST_URI'], 'advid')) { // <- URL rewriting makes this tricky
		// it LOOKS like passed via GET, but URL rewrite masks it
		$ServerParts = parse_url($_SERVER['REQUEST_URI']);
		if ($ServerParts['query']) {
			$QSParts = explode('&', $ServerParts['query']);
			foreach ((array)$QSParts as $Index => $QSValue) {
				$QSPieces = explode('=', $QSValue);
				if (strtolower($QSPieces[0]) == 'advid' && $QSPieces[1]) {
					setcookie(
						'advdata', 
						(int)$QSPieces[1], 
						CookieExpire(), // <- expire
						CookiePath(), // <- path
						CookieDomain() // <- domain - add this so mkt.netcomlearning.com can see it, too
					);
					break;
				}
			}
		}
	}
}

function CookieDomain() {
	return "netcomlearning.com"; // (add this so mkt.netcomlearning.com can see it, too)
}

function CookieExpire() {
	return time() + (60*60*24*365);
}

function CookiePath() {
	return '/';
}

function EmailServerDetailsToMyself($AdditionalData = '') {
	$DebugBacktrace = debug_backtrace(true, 2);
	$CallingFunction = $DebugBacktrace[1]['function'];
	
	$EmailMyself = true; // <- assume true until proven false

	// 172.16.5.4 = staging
	// 13.77.111.32 = staging
	// 172.16.5.6 = www6
	// 40.70.12.82 = www6
	// 40.70.9.120 = www6
	// 172.16.5.7 = www7
	// 104.210.15.9 = www7
	// 104.210.15.9 = www

	$IsWWWNetCom = false;
	switch (strtolower($_SERVER['HTTP_HOST'])) { // <- ignore www, but find the ones who are hitting www7 and staging directly
		case 'www.netcomlearning.com':
		//case '104.210.15.9': // <- ip address for www.netcomlearning.com
			$IsWWWNetCom = true;
			break;
	}

	$WPLogin = false;
	if ($EmailMyself) {
		if (strpos($_SERVER['SCRIPT_URI'], '/wp-login.php')) {
			$EmailMyself = false;
		}
	}
	
	if ($EmailMyself) {
		if ($_SERVER['REMOTE_ADDR'] != $_SERVER['SERVER_ADDR']) { // <- this is me. internal testing.
			//$EmailMyself = false;
		}
	}
	
	if ($EmailMyself) {
		if (strtolower($CallingFunction) == 'watchforknownhackingrequests') { // <- this one already limited to 404 requests
			if ($IsWWWNetCom) {
				//$EmailMyself = false; // <- ignore www, but find the ones who are hitting www7 and staging directly
			}
		} 
	}
	
	if ($EmailMyself) {
		if (strtolower($CallingFunction) == 'slowdownbyipaddress') { 
			if ($IsWWWNetCom) {
				$EmailMyself = false; // <- ignore www, but find the ones who are hitting www7 and staging directly
			}
		}
	}
	
	if ($EmailMyself) {
		if (strtolower($CallingFunction) == 'slowdownbyuseragent') {
			if ($IsWWWNetCom) {
				$EmailMyself = false; // <- ignore www, but find the ones who are hitting www7 and staging directly
			}
		}
	}
	
	if ($EmailMyself) {
		if (strtolower($CallingFunction) == 'watchforsqlinjection') {
			if (strlen($_SERVER['QUERY_STRING']) < 20) {
				// really short strings are usually ID=73'A=0 and can be ignored 
				$EmailMyself = false;
			}
		}
	}
	
	if ($EmailMyself) {
		$Message = "";
		switch (strtolower($CallingFunction)) {
			case 'slowdownbyipaddress':
				$Message .= "$_SERVER[REMOTE_ADDR]\r\n\r\n";
				break;
			case 'slowdownbyuseragent':
				$Message .= "$_SERVER[HTTP_USER_AGENT]\r\n\r\n";
				break;
			case 'watchforknownhackingrequests':
				$Message .= "$_SERVER[SCRIPT_URI]\r\n\r\n";
				break;
			case 'watchforsqlinjection':
				$Message .= "$_SERVER[QUERY_STRING]\r\n\r\n";
				break;
		}

		$Message .= $AdditionalData ? "Matched: $AdditionalData\r\n\r\n" : "";

		ksort($_SERVER);
		foreach ($_SERVER as $Key => $Value) {
			switch (strtoupper($Key)) {
				case 'HTTP_HOST':
				case 'HTTP_USER_AGENT':
				case 'QUERY_STRING':
				case 'REMOTE_ADDR':
				case 'REMOTE_PORT':
				case 'REQUEST_METHOD':
				case 'REQUEST_URI':
				case 'SCRIPT_URI':
				case 'SCRIPT_URL':
				case 'SERVER_ADDR':
					$Message .= "- $Key > $Value\r\n";
					break;
				case 'REQUEST_TIME':
					$Message .= "- $Key > " . date('r', $Value) . "\r\n";
					break;
				default:
					// skip
					break;	
			}
		}
		$Headers = "";
		$Headers .= "From: Preprocess Global <preprocess-global@netcomlearning.com>";
		@mail('brian@netcomlearning.com', '/lib/preprocess_global > ' . $CallingFunction . '()', $Message, $Headers);
	}
}

function robots_meta_tag($Content = 'index,follow') {
	// this function will create a robots file which default to noindex,nofollow if not on www.netcomlearning.com
	/*<?= robots_meta_tag(); ?>*/
	
	// brian 2021-03-23 switch back to never allowing www6 and go back to original pages and remove robots from cache
	// brian 2021-03-11 since www6 is *technically* the same and gets cached in the same location as www, treat it as if it is ok
	
	switch (strtolower($_SERVER['HTTP_HOST'])) {
		case 'www.netcomlearning.com':
			$UsePassedContent = true;
			break;
		default:
			$UsePassedContent = false;
			break;
	}
	
	if ($UsePassedContent) {
		$RobotsRiseUp = trim($Content) ? trim($Content) : "index,follow";
	} else {
		$RobotsRiseUp = "noindex,nofollow";
	}
	
	return "<meta id='MetaRobots' name='robots' content='{$RobotsRiseUp}' />";
}

function SlowDownByUserAgent($Server) {
	$SlowDown = false;
	
	if (trim($Server['HTTP_USER_AGENT'])) {
		if (BadUserAgentMatch($Server['HTTP_USER_AGENT'])) {
			$SlowDown = true;
		}
		
		if ($SlowDown) {
			// brian 2019-04-26 remove blocking by common requests from here (required useragent + filename)
			/*
			// brian 2018-12-21 watch for a few really common file requests to add to IP blockade
			// quick hack
			$LookFor = array(
				'/1.php',
				'/etc/passwd',
				'/phpMyAdmin.php',
				'/wp-login.php',
				'/xmlrpc.php',
			);
			foreach ($LookFor as $Needle) {
				if (stripos($Server['SCRIPT_URL'], $Needle)) {
					//@mail('brian@netcomlearning.com', '/lib/preprocess_global.php', "$Needle found: $Server[SCRIPT_URL]");
					BlockadeFile_Append_XML($Server, 24*6.5);
					break;
				}
			}
			*/
			
			/*
			switch ($Server['SCRIPT_URL']) {
				case '/1.php':
				case '/wp-login.php':
				case '/phpMyAdmin.php':
				case '/xmlrpc.php':
					//@mail('brian@netcomlearning.com', 'look in blockade.xml for this one', serialize($Server));
					BlockadeFile_Append_XML($Server, 24*6.5);
					break;
			}
			*/
			
			$Redirect = '/error/oops.html?UA';
			if ($_SERVER['REQUEST_URI'] != $Redirect) { // <- don't redirect if already there
				/*
				$ServerMAX = $_SERVER;
				foreach ($Server as $Key => $Value) {
					$ServerMAX[$Key] = $Value;
				}
				if ($_POST) {
					$ServerMAX['POST'] = $_POST;
				}
				
				if (!AddToLoggingToEmailLater($ServerMAX, array(), 'block-ua')) {
					@mail('brian@netcomlearning.com', '/lib/preprocess_global.inc.php > BlockadeFile_Append_XML()', "fatal error! couldn't write to log\r\n\r\n" . serialize($Server) . "\r\n\r\n" . serialize($MiscData));
				}
				*/
				//EmailServerDetailsToMyself(BadUserAgentMatch($Server['HTTP_USER_AGENT'])); // <- no need to ever alert myself if looking at the $Redirect page
				// brian 2020-08-01 adding 404 code so they think we've gone away
				//header("Location: {$Redirect}", true, 404);
				// brian 2021-06-15 changing to 429 for better tracking
				header("Location: {$Redirect}", true, 429);
				exit();
			}
		}
	} else {
		//@mail('brian@netcomlearning.com', '/lib/preprocess_global.php > SlowDownByUserAgent()', "No User Agent found?\r\n\r\n" . serialize($Server));
	}
}

function SlowDownByIPAddress($Server) {
	$SlowDown = false;
	
	if (IPAddressMightExistInBlockade_XML($Server['REMOTE_ADDR'])) { // <- 0.001 seconds faster for IP addresses NOT in list; 0.05 seconds slower for IP addresses IN list
		$IPRange = SlowDownByIPAddress_Range();
		
		if ($IPRange) {
			//@mail('brian@netcomlearning.com', '$Server', serialize($Server));
			if ($Server['REMOTE_ADDR']) {
				if ($IPRange[$Server['REMOTE_ADDR']]) {
					//@mail('brian@netcomlearning.com', 'In $IPRange', serialize($Server) . "\r\n\r\n");
					$SlowDown = true;
				}
			}
		}
	}
		
	if ($SlowDown) {
		$Redirect = '/error/oops.html?IP';
		if ($_SERVER['REQUEST_URI'] != $Redirect) { // <- don't redirect if already there
			/*
			$ServerMAX = $_SERVER;
			foreach ($Server as $Key => $Value) {
				$ServerMAX[$Key] = $Value;
			}
			if ($_POST) {
				$ServerMAX['POST'] = $_POST;
			}
			if (!AddToLoggingToEmailLater($ServerMAX, array(), 'block-ip')) {
				@mail('brian@netcomlearning.com', '/lib/preprocess_global.inc.php > BlockadeFile_Append_XML()', "fatal error! couldn't write to log\r\n\r\n" . serialize($Server) . "\r\n\r\n" . serialize($MiscData));
			}
			*/
			//EmailServerDetailsToMyself(); // <- no need to ever alert myself if looking at the $Redirect page
			// brian 2020-08-01 adding 404 code so they think we've gone away
			//header("Location: {$Redirect}", true, 404);
			// brian 2021-06-15 changing to 429 for better tracking
			header("Location: {$Redirect}", true, 429);
			exit();
		}
	}
}

function SlowDownByIPAddressTOO($Server) {
	$SlowDown = false;
	
	if (ProblemExternalIPAddress_SearchForIPAddress($Server['REMOTE_ADDR'])) {
		$SlowDown = true;
	}
	
	if ($SlowDown) {
		$Redirect = '/error/oops.html?IP2';
		if ($_SERVER['REQUEST_URI'] != $Redirect) { // <- don't redirect if already there
			// brian 2020-08-01 adding 404 code so they think we've gone away
			//header("Location: {$Redirect}", true, 404);
			// brian 2021-06-15 changing to 429 for better tracking
			header("Location: {$Redirect}", true, 429);
			//header("Location: {$Redirect}");
			exit();
		}
	}
}

function WatchForKnownHackingRequests($Server) {
	$HackRequest = array();
	$HackRequestFound = false;
	
	//if ($Server['REDIRECT_STATUS']) {
	//	@mail('brian@netcomlearning.com', 'REDIRECT_STATUS', serialize($Server));
	//}
	
	if ($Server['REDIRECT_STATUS'] == '404') {
		if ($Server['SCRIPT_URL']) {
			if ($HackRequest = WatchForKnownHackingRequests_IsFound($Server['SCRIPT_URL'])) {
				$HackRequestFound = true;
			}
		} else {
			//@mail('brian@netcomlearning.com', '/lib/preprocess_global.php', "SCRIPT_URL not found?\r\n\r\n" . serialize($Server));
		}
	} elseif ($Server['REDIRECT_STATUS'] == '302') { // 302 = redirect from http to https. this always happens even if it turns out the file doesn't exist, but the 404 is never known
		// be very careful
		if ($Server['SCRIPT_URL']) {
			// add VERY SPECIFIC requests that COULDN'T POSSIBLY give a false positive (longer = better)
			switch ($Server['SCRIPT_URL']) { // match EXACTLY
				case '/admin_aspcms/_system/AspCms_SiteSetting.asp':
				case '/plus/90sec.php':
				case '//plus/mytag_js.php':
				case '/w00tw00t.at.blackhats.romanian.anti-sec:)':
				case '/FCKeditor/editor/filemanager/connectors/asp/connector.asp':
				case '/utility/convert/data/config.inc.php':
				case '/uploads/dede/sys_verifies.php':
					if ($HackRequest = WatchForKnownHackingRequests_IsFound($Server['SCRIPT_URL'])) {
						$HackRequestFound = true;
						@mail('brian@netcomlearning.com', 'WatchForKnownHackingRequests() triggered!!!!! Yes!!!!!', serialize($HackRequest) . "\n\n" . serialize($Server));
					}
					break;
			}
		} else {
			@mail('brian@netcomlearning.com', '/lib/preprocess_global.php', "SCRIPT_URL not found?\r\n\r\n" . serialize($Server));
		}
	}
	
	if ($HackRequestFound) {
		//@mail('brian@netcomlearning.com', '/lib/preprocess_global.php', "\$_SERVER:\r\n" . serialize($_SERVER));
		$Redirect = '/error/oops.html?HR';
		if ($_SERVER['REQUEST_URI'] != $Redirect) { // <- don't redirect if already there
			if (!BlockadeFile_Read_XML($Server['REMOTE_ADDR'])) {
				$ServerMAX = $_SERVER;
				foreach ($Server as $Key => $Value) {
					$ServerMAX[$Key] = $Value;
				}
				if ($_POST) {
					$ServerMAX['POST'] = $_POST;
				}
				BlockadeFile_Append_XML($Server, $HackRequest['HoursToBlock']);
			}
			
			/*
			if (!AddToLoggingToEmailLater($ServerMAX, array(), 'block-hr')) {
				@mail('brian@netcomlearning.com', '/lib/preprocess_global.inc.php > BlockadeFile_Append_XML()', "fatal error! couldn't write to log\r\n\r\n" . serialize($_SERVER) . "\r\n\r\n" . serialize($Server));
			}
			*/
			
			//if ($HoursBlocked) {
			//	EmailServerDetailsToMyself($HackRequest); // <- no need to ever alert myself if looking at the $Redirect page
			//}
			// brian 2020-08-01 adding 404 code so they think we've gone away
			//header("Location: {$Redirect}", true, 404);
			// brian 2021-06-15 changing to 429 for better tracking
			header("Location: {$Redirect}", true, 429);
			exit();
		}
	} else {
		//if (WatchForKnownHackingRequests_IsFound($Server['SCRIPT_URL'])) {
		//	@mail('brian@netcomlearning.com', 'hacking request (not 404)', serialize($Server));
		//}
	}
}

function WatchForSQLInjection($Get) { // <- $Get *must* be an array
	$Break = false;
	
	$IsException = false;
	if (@strpos($_SERVER['SCRIPT_URI'], "/search/", 1)) {
		$IsException = true;
	} elseif (strpos($_SERVER['SCRIPT_URI'], "/corporate-portal/search.php")) {
		$IsException = true;
	}
	
	if ($Get && !$IsException) {
		foreach ($Get as $Key => $Array1) {
			if (is_array($Array1)) {
				foreach ($Array1 as $Key2 => $Array2) {
					if (is_array($Array2)) {
						foreach ($Array2 as $Key3 => $Array3) {
							if (is_array($Array3)) {
								// probably don't need to go this deep
								@mail('brian@netcomlearning.com', 'preprocess_global > WatchForSQLInjection() > array too deep!', serialize($Get) . "\r\n\r\n" . $_SERVER['QUERY_STRING']);
							} else {
								$Value = $Array3; // <- unnecessary, but easier to read
								if (SQLInjectionFound($Value)) {
									$Break = true;
									break;
								}
							}
						}
					} else {
						$Value = $Array2; // <- unnecessary, but easier to read
						if (SQLInjectionFound($Value)) {
							$Break = true;
							break;
						}
					}
				}
			} else {
				$Value = $Array1; // <- unnecessary, but easier to read
				if (SQLInjectionFound($Value)) {
					$Break = true;
					break;
				}
			}
		}
	}
	
	if ($Break) {
		$Redirect = '/error/oops.html?SI';
		if ($_SERVER['REQUEST_URI'] != $Redirect) { // <- don't redirect if already there
			if (!BlockadeFile_Read_XML($_SERVER['REMOTE_ADDR'])) {
				$ServerMAX = $_SERVER;
				if ($_POST) {
					$ServerMAX['POST'] = $_POST;
				}
				BlockadeFile_Append_XML($ServerMAX, SQLInjectionBlockHours());
			}
			/*
			if (!AddToLoggingToEmailLater($Server, $Get, 'block-si')) {
				@mail('brian@netcomlearning.com', '/lib/preprocess_global.inc.php > BlockadeFile_Append_XML()', "fatal error! couldn't write to log\r\n\r\n" . serialize($Server) . "\r\n\r\n" . serialize($MiscData));
			}
			*/
			// brian 2020-08-01 adding 404 code so they think we've gone away
			//header("Location: {$Redirect}", true, 404);
			// brian 2021-06-15 changing to 429 for better tracking
			header("Location: {$Redirect}", true, 429);
			
			exit();
		}
	}
}
?>
