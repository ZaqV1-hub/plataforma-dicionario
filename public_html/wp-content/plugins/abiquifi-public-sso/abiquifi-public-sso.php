<?php
/**
 * Plugin Name: Abiquifi Public SSO
 * Description: Login publico unificado para dicionario, Fabricamos e site principal.
 * Version: 1.0.0
 * Author: Codex
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/includes/class-abiquifi-public-sso.php';

register_activation_hook( __FILE__, array( 'Abiquifi_Public_SSO', 'activate' ) );

Abiquifi_Public_SSO::instance();
