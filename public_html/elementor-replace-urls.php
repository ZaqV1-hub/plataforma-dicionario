<?php
// Temporary script to replace old URLs inside Elementor data without wp-admin/WP-CLI.
// Delete this file after use.

define( 'WP_USE_THEMES', false );
require __DIR__ . '/wp-load.php';

if ( ! class_exists( '\\Elementor\\Utils' ) ) {
	http_response_code( 500 );
	echo 'Elementor not loaded';
	exit;
}

// Change these two URLs to match your old/new domains.
$from = 'https://dicionario.abiquifi.org.br';
$to   = 'https://dicionario.abiquifi.questione.ai';

try {
	$result = \Elementor\Utils::replace_urls( $from, $to );
	echo $result;
} catch ( Exception $e ) {
	http_response_code( 500 );
	echo $e->getMessage();
}
