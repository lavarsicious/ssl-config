var constants = require('constants');

var TLS_VERSIONS = [
	{
		"name": "tlsv12",
		"option": constants.SSL_OP_NO_TLSv1_2
	},
	{
		"name": "tlsv11",
		"option": constants.SSL_OP_NO_TLSv1_1
	},
	{
		"name": "tlsv1",
		"option": constants.SSL_OP_NO_TLSv1
	},
	{
		"name": "sslv3",
		"option": constants.SSL_OP_NO_SSLv3
	},
	{
		"name": "sslv2",
		"option": constants.SSL_OP_NO_SSLv2
	}
]

function minimumTLSVersion(tlsVersionName){
	var index = TLS_VERSIONS.findIndex(function(tlsVersion){
		return ( tlsVersion.name === tlsVersionName )
	})
	if ( index === -1 ) {
		throw new Error('Invalid TLS version', tlsVersionName);
	}
	var relevant = TLS_VERSIONS.slice(index + 1) // +1 because we want to exclude older versions.
	var minimumTLSVersionValue = 0;
	// '|'' is a bitwise or
	// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Bitwise_Operators#.7c_%28Bitwise_OR%29
	relevant.forEach(function (tlsVersion) {
		minimumTLSVersionValue = minimumTLSVersionValue | tlsVersion.option;
	});
	return minimumTLSVersionValue
}

var log = console.log.bind(console);

// This object should be free of node-specific logic on order to be kept up to date with Mozilla
// see https://github.com/mozilla/server-side-tls/blob/gh-pages/ssl-config-generator/index.html
var cryptoLevels = {
	modern: {
		oldestBrowsers: 'Firefox 27, Chrome 30, IE 11 on Windows 7, Edge, Opera 17, Safari 9, Android 5.0, and Java 8',
		minimumTLSVersion: 'tlsv12',
		cipherSuites: [
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			"ECDHE-RSA-CHACHA20-POLY1305",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-AES256-SHA384",
			"ECDHE-RSA-AES256-SHA384",
			"ECDHE-ECDSA-AES128-SHA256",
			"ECDHE-RSA-AES128-SHA256",
			"!aNULL",
			"!eNULL",
			"!EXPORT",
			"!DES",
			"!RC4",
			"!3DES",
			"!MD5",
			"!PSK"
		]
	},
	intermediate: {
		oldestBrowsers: 'Firefox 1, Chrome 1, IE 7, Opera 5, Safari 1, Windows XP IE8, Android 2.3, Java 7',
		minimumTLSVersion: 'tlsv1',
		cipherSuites: [
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			"ECDHE-RSA-CHACHA20-POLY1305",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"DHE-RSA-AES128-GCM-SHA256",
			"DHE-RSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-AES128-SHA256",
			"ECDHE-RSA-AES128-SHA256",
			"ECDHE-ECDSA-AES128-SHA",
			"ECDHE-RSA-AES256-SHA384",
			"ECDHE-RSA-AES128-SHA",
			"ECDHE-ECDSA-AES256-SHA384",
			"ECDHE-ECDSA-AES256-SHA",
			"ECDHE-RSA-AES256-SHA",
			"DHE-RSA-AES128-SHA256",
			"DHE-RSA-AES128-SHA",
			"DHE-RSA-AES256-SHA256",
			"DHE-RSA-AES256-SHA",
			"ECDHE-ECDSA-DES-CBC3-SHA",
			"ECDHE-RSA-DES-CBC3-SHA",
			"EDH-RSA-DES-CBC3-SHA",
			"AES128-GCM-SHA256",
			"AES256-GCM-SHA384",
			"AES128-SHA256",
			"AES256-SHA256",
			"AES128-SHA",
			"AES256-SHA",
			"DES-CBC3-SHA",
			"!DSS",
			"!aNULL",
			"!eNULL",
			"!EXPORT",
			"!DES",
			"!RC4",
			"!MD5",
			"!PSK",
			"!aECDH",
			"!EDH-DSS-DES-CBC3-SHA",
			"!EDH-RSA-DES-CBC3-SHA",
			"!KRB5-DES-CBC3-SHA"
		]
	},
	old: {
		oldestBrowsers: 'Windows XP IE6, Java 6',
		minimumTLSVersion: 'sslv3',
		cipherSuites: [
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			"ECDHE-RSA-CHACHA20-POLY1305",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"DHE-RSA-AES128-GCM-SHA256",
			"DHE-DSS-AES128-GCM-SHA256",
			"kEDH+AESGCM",
			"ECDHE-RSA-AES128-SHA256",
			"ECDHE-ECDSA-AES128-SHA256",
			"ECDHE-RSA-AES128-SHA",
			"ECDHE-ECDSA-AES128-SHA",
			"ECDHE-RSA-AES256-SHA384",
			"ECDHE-ECDSA-AES256-SHA384",
			"ECDHE-RSA-AES256-SHA",
			"ECDHE-ECDSA-AES256-SHA",
			"DHE-RSA-AES128-SHA256",
			"DHE-RSA-AES128-SHA",
			"DHE-DSS-AES128-SHA256",
			"DHE-RSA-AES256-SHA256",
			"DHE-DSS-AES256-SHA",
			"DHE-RSA-AES256-SHA",
			"ECDHE-RSA-DES-CBC3-SHA",
			"ECDHE-ECDSA-DES-CBC3-SHA",
			"EDH-RSA-DES-CBC3-SHA",
			"AES128-GCM-SHA256",
			"AES256-GCM-SHA384",
			"AES128-SHA256",
			"AES256-SHA256",
			"AES128-SHA",
			"AES256-SHA",
			"AES",
			"DES-CBC3-SHA",
			"HIGH",
			"SEED",
			"!aNULL",
			"!eNULL",
			"!EXPORT",
			"!DES",
			"!RC4",
			"!MD5",
			"!PSK",
			"!RSAPSK",
			"!aDH",
			"!aECDH",
			"!EDH-DSS-DES-CBC3-SHA",
			"!KRB5-DES-CBC3-SHA",
			"!SRP"
		]
	}
};

module.exports = function(cryptoLevelName) {
	var cryptoLevel = cryptoLevels[cryptoLevelName];
	if ( ! cryptoLevel ) {
		throw new Error('No matching crypto level', cryptoLevelName);
	}
	var nodeSettings = {};

	// node shows cipherSuites as a string called 'ciphers'
	nodeSettings.ciphers = cryptoLevel.cipherSuites.join(':');
	nodeSettings.minimumTLSVersion = minimumTLSVersion(cryptoLevel.minimumTLSVersion);
	return nodeSettings;
};
