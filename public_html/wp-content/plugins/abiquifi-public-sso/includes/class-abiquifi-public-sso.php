<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Abiquifi_Public_SSO {
	const COOKIE_NAME = 'abiquifi_public_sso';
	const COOKIE_DOMAIN = '.abiquifi.questione.ai';
	const SESSION_TTL = 604800;
	const OPTION_SECRET = 'abiquifi_public_sso_secret';
	const OPTION_MIGRATION = 'abiquifi_public_sso_migration_v1';
	const OPTION_PUBLIC_AUTH_PAGES = 'abiquifi_public_sso_public_auth_pages_v1';
	const META_SOURCE = '_abiquifi_public_sso_source';
	const INTERNAL_SECRET_FALLBACK = 'abiquifi-public-sso-2026';

	protected static $instance = null;
	protected $resolved_session = null;
	protected $resolved_user = null;
	protected $resolved_token = null;
	protected $did_bootstrap = false;
	protected $local_auth_cookie_expiration = 0;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public static function activate() {
		$self = self::instance();
		$self->ensure_secret();
		$self->maybe_create_session_table();
	}

	protected function __construct() {
		add_action( 'init', array( $this, 'bootstrap' ), 1 );
		add_action( 'init', array( $this, 'maybe_ensure_public_auth_pages' ), 10 );
		add_action( 'init', array( $this, 'maybe_run_migration' ), 20 );
		add_action( 'init', array( $this, 'register_shortcodes' ), 20 );
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
		add_action( 'template_redirect', array( $this, 'maybe_handle_frontend_actions' ), 1 );
		add_action( 'admin_post_nopriv_abiquifi_public_sso_login', array( $this, 'handle_dictionary_login_form' ) );
		add_action( 'admin_post_abiquifi_public_sso_login', array( $this, 'handle_dictionary_login_form' ) );
		add_action( 'admin_post_nopriv_abiquifi_public_sso_register', array( $this, 'handle_dictionary_register_form' ) );
		add_action( 'admin_post_abiquifi_public_sso_register', array( $this, 'handle_dictionary_register_form' ) );
		add_action( 'admin_post_nopriv_abiquifi_public_sso_forgot_password', array( $this, 'handle_public_forgot_password_form' ) );
		add_action( 'admin_post_abiquifi_public_sso_forgot_password', array( $this, 'handle_public_forgot_password_form' ) );
		add_action( 'admin_post_nopriv_abiquifi_public_sso_reset_password', array( $this, 'handle_public_reset_password_form' ) );
		add_action( 'admin_post_abiquifi_public_sso_reset_password', array( $this, 'handle_public_reset_password_form' ) );
		add_action( 'admin_post_nopriv_abiquifi_public_sso_logout', array( $this, 'handle_public_logout' ) );
		add_action( 'admin_post_abiquifi_public_sso_logout', array( $this, 'handle_public_logout' ) );
		add_filter( 'the_content', array( $this, 'filter_dictionary_pages' ), 50 );
		add_filter( 'elementor/frontend/the_content', array( $this, 'filter_elementor_content' ), 20 );
		add_filter( 'template_include', array( $this, 'filter_public_page_template' ), 99 );
		add_filter( 'body_class', array( $this, 'filter_body_class' ) );
		add_filter( 'allowed_redirect_hosts', array( $this, 'filter_allowed_redirect_hosts' ) );
		add_filter( 'show_admin_bar', array( $this, 'filter_show_admin_bar' ) );
		add_filter( 'auth_cookie_expiration', array( $this, 'filter_auth_cookie_expiration' ), 10, 3 );
		add_action( 'wp_head', array( $this, 'print_public_session_script' ), 5 );
		add_action( 'wp_head', array( $this, 'print_public_ui_styles' ), 20 );
	}

	public function register_shortcodes() {
		add_shortcode( 'dsf_user_menu', array( $this, 'render_dsf_user_menu_shortcode' ) );
	}

	public function bootstrap() {
		if ( $this->did_bootstrap ) {
			return;
		}

		$this->did_bootstrap = true;
		$this->ensure_secret();

		if ( $this->is_authority_site() ) {
			$this->maybe_create_session_table();
		}

		if ( $this->should_skip_bootstrap() ) {
			return;
		}

		$this->resolved_token = $this->read_cookie_token();

		if ( '' === $this->resolved_token ) {
			if ( $this->bootstrap_existing_authority_public_session() ) {
				return;
			}

			$this->maybe_logout_stale_local_public_session();
			return;
		}

		if ( $this->is_authority_site() ) {
			$session = $this->resolve_authority_session( $this->resolved_token );
		} else {
			$session = $this->fetch_remote_session( $this->resolved_token );
		}

		if ( empty( $session['user'] ) || empty( $session['token'] ) ) {
			$this->clear_public_cookie();
			$this->maybe_logout_stale_local_public_session();
			return;
		}

		$this->resolved_session = $session;
		$this->resolved_user    = $session['user'];

		if ( $this->should_bootstrap_wordpress_user() ) {
			$user_id = $this->ensure_local_wordpress_user( $session['user'] );
			if ( $user_id ) {
				$this->login_local_user( $user_id );
			}
		}
	}

	protected function should_skip_bootstrap() {
		$is_ajax = function_exists( 'wp_doing_ajax' ) ? wp_doing_ajax() : ( defined( 'DOING_AJAX' ) && DOING_AJAX );

		if ( is_admin() && ! $is_ajax ) {
			return true;
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST && ! $this->is_authority_site() ) {
			return true;
		}

		return false;
	}

	protected function bootstrap_existing_authority_public_session() {
		if ( ! $this->is_authority_site() || ! is_user_logged_in() ) {
			return false;
		}

		$user = wp_get_current_user();
		if ( ! $user instanceof WP_User || ! $user->exists() ) {
			return false;
		}

		if ( user_can( $user, 'edit_posts' ) ) {
			return false;
		}

		$session = $this->create_public_session( (int) $user->ID, true );
		if ( empty( $session['token'] ) || empty( $session['expires_at'] ) ) {
			return false;
		}

		$this->set_public_cookie( $session['token'], (int) $session['expires_at'] );
		$this->resolved_token   = $session['token'];
		$this->resolved_user    = $this->normalize_user( $user );
		$this->resolved_session = array(
			'token'      => $session['token'],
			'expires_at' => (int) $session['expires_at'],
			'user'       => $this->resolved_user,
		);

		return true;
	}

	protected function should_bootstrap_wordpress_user() {
		if ( $this->is_main_site() ) {
			return false;
		}

		if ( $this->is_fabricamos_site() && is_page( 'fabricante' ) ) {
			return false;
		}

		if ( $this->is_fabricamos_site() && is_page( 'painel' ) ) {
			return false;
		}

		return true;
	}

	public function register_rest_routes() {
		register_rest_route(
			'abiquifi-sso/v1',
			'/login',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'rest_login' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'abiquifi-sso/v1',
			'/register',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'rest_register' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'abiquifi-sso/v1',
			'/logout',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'rest_logout' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'abiquifi-sso/v1',
			'/session',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'rest_session' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'abiquifi-sso/v1',
			'/sync-user',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'rest_sync_user' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	public function rest_login( WP_REST_Request $request ) {
		if ( ! $this->is_authority_site() ) {
			return new WP_Error( 'abiquifi_sso_not_authority', 'Este endpoint so pode ser executado no dicionario.', array( 'status' => 403 ) );
		}

		$login    = sanitize_text_field( (string) $request->get_param( 'login' ) );
		$password = (string) $request->get_param( 'password' );
		$remember = $this->to_bool( $request->get_param( 'remember' ) );

		$result = $this->authenticate_credentials( $login, $password, $remember );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( $result );
	}

	public function rest_register( WP_REST_Request $request ) {
		if ( ! $this->is_authority_site() ) {
			return new WP_Error( 'abiquifi_sso_not_authority', 'Este endpoint so pode ser executado no dicionario.', array( 'status' => 403 ) );
		}

		$name            = sanitize_text_field( (string) $request->get_param( 'name' ) );
		$email           = sanitize_email( (string) $request->get_param( 'email' ) );
		$password        = (string) $request->get_param( 'password' );
		$password_repeat = (string) $request->get_param( 'password_repeat' );
		$remember        = true;
		$profile         = array(
			'first_name'       => sanitize_text_field( (string) $request->get_param( 'first_name' ) ),
			'last_name'        => sanitize_text_field( (string) $request->get_param( 'last_name' ) ),
			'institution_name' => sanitize_text_field( (string) $request->get_param( 'institution_name' ) ),
			'phone'            => sanitize_text_field( (string) $request->get_param( 'phone' ) ),
			'activity_sector'  => sanitize_text_field( (string) $request->get_param( 'activity_sector' ) ),
			'department'       => sanitize_text_field( (string) $request->get_param( 'department' ) ),
			'job_title'        => sanitize_text_field( (string) $request->get_param( 'job_title' ) ),
			'privacy_accept'   => $this->to_bool( $request->get_param( 'privacy_accept' ) ),
		);

		$result = $this->register_public_user( $name, $email, $password, $password_repeat, $remember, $profile );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( $result );
	}

	public function rest_logout( WP_REST_Request $request ) {
		if ( ! $this->is_authority_site() ) {
			return new WP_Error( 'abiquifi_sso_not_authority', 'Este endpoint so pode ser executado no dicionario.', array( 'status' => 403 ) );
		}

		$token = sanitize_text_field( (string) $request->get_param( 'token' ) );
		if ( '' === $token ) {
			$token = $this->read_cookie_token();
		}

		if ( '' !== $token ) {
			$this->revoke_session_token( $token );
		}

		return rest_ensure_response(
			array(
				'success' => true,
			)
		);
	}

	public function rest_session( WP_REST_Request $request ) {
		if ( ! $this->is_authority_site() ) {
			return new WP_Error( 'abiquifi_sso_not_authority', 'Este endpoint so pode ser executado no dicionario.', array( 'status' => 403 ) );
		}

		$token = sanitize_text_field( (string) $request->get_param( 'token' ) );
		if ( '' === $token ) {
			$token = $this->read_cookie_token();
		}

		$session = $this->resolve_authority_session( $token );
		if ( empty( $session['user'] ) ) {
			return new WP_Error( 'abiquifi_sso_invalid_session', 'Sessao invalida.', array( 'status' => 401 ) );
		}

		return rest_ensure_response( $session );
	}

	public function rest_sync_user( WP_REST_Request $request ) {
		if ( ! $this->is_authority_site() ) {
			return new WP_Error( 'abiquifi_sso_not_authority', 'Este endpoint so pode ser executado no dicionario.', array( 'status' => 403 ) );
		}

		$secret = sanitize_text_field( (string) $request->get_param( 'secret' ) );
		if ( ! $this->is_internal_secret_valid( $secret ) ) {
			return new WP_Error( 'abiquifi_sso_forbidden', 'Segredo invalido.', array( 'status' => 403 ) );
		}

		$mode = sanitize_text_field( (string) $request->get_param( 'mode' ) );

		if ( 'export' === $mode ) {
			return rest_ensure_response(
				array(
					'users' => $this->export_public_users(),
				)
			);
		}

		$user = $request->get_param( 'user' );
		if ( ! is_array( $user ) ) {
			return new WP_Error( 'abiquifi_sso_invalid_user', 'Usuario invalido.', array( 'status' => 400 ) );
		}

		$user_id = $this->ensure_local_wordpress_user( $user );
		if ( ! $user_id ) {
			return new WP_Error( 'abiquifi_sso_sync_failed', 'Nao foi possivel espelhar o usuario.', array( 'status' => 500 ) );
		}

		return rest_ensure_response(
			array(
				'success' => true,
				'user_id' => (int) $user_id,
			)
		);
	}

	public function handle_dictionary_login_form() {
		$redirect = home_url( '/log-in/' );

		if ( ! isset( $_POST['abiquifi_public_sso_login_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['abiquifi_public_sso_login_nonce'] ) ), 'abiquifi_public_sso_login' ) ) {
			wp_safe_redirect( add_query_arg( 'login_error', 'nonce', $redirect ) );
			exit;
		}

		$login      = sanitize_text_field( isset( $_POST['log'] ) ? wp_unslash( $_POST['log'] ) : '' );
		$password   = isset( $_POST['pwd'] ) ? (string) wp_unslash( $_POST['pwd'] ) : '';
		$remember   = ! empty( $_POST['rememberme'] );
		$redirect_to = esc_url_raw( isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : $this->dictionary_home_url() );
		if ( '' === $redirect_to ) {
			$redirect_to = $this->dictionary_home_url();
		}

		$result = $this->authenticate_credentials( $login, $password, $remember );
		if ( is_wp_error( $result ) ) {
			wp_safe_redirect( add_query_arg( 'login_error', 'invalid', $redirect ) );
			exit;
		}

		$this->set_public_cookie( $result['token'], $result['expires_at'] );
		$this->login_local_user( (int) $result['user']['ID'] );
		wp_safe_redirect( $redirect_to );
		exit;
	}

	public function handle_dictionary_register_form() {
		$redirect = home_url( '/cadastro/' );

		if ( ! isset( $_POST['abiquifi_public_sso_register_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['abiquifi_public_sso_register_nonce'] ) ), 'abiquifi_public_sso_register' ) ) {
			wp_safe_redirect( add_query_arg( 'register_error', 'nonce', $redirect ) );
			exit;
		}

		$name            = sanitize_text_field( isset( $_POST['register_name'] ) ? wp_unslash( $_POST['register_name'] ) : '' );
		$email           = sanitize_email( isset( $_POST['register_email'] ) ? wp_unslash( $_POST['register_email'] ) : '' );
		$password        = isset( $_POST['register_password'] ) ? (string) wp_unslash( $_POST['register_password'] ) : '';
		$password_repeat = isset( $_POST['register_password_repeat'] ) ? (string) wp_unslash( $_POST['register_password_repeat'] ) : '';
		if ( '' === $password_repeat && '' !== $password ) {
			$password_repeat = $password;
		}
		$redirect_to     = esc_url_raw( isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : $this->dictionary_home_url() );
		$profile         = array(
			'first_name'       => sanitize_text_field( isset( $_POST['register_name'] ) ? wp_unslash( $_POST['register_name'] ) : '' ),
			'last_name'        => sanitize_text_field( isset( $_POST['register_last_name'] ) ? wp_unslash( $_POST['register_last_name'] ) : '' ),
			'institution_name' => sanitize_text_field( isset( $_POST['register_institution_name'] ) ? wp_unslash( $_POST['register_institution_name'] ) : '' ),
			'phone'            => sanitize_text_field( isset( $_POST['register_phone'] ) ? wp_unslash( $_POST['register_phone'] ) : '' ),
			'activity_sector'  => sanitize_text_field( isset( $_POST['register_activity_sector'] ) ? wp_unslash( $_POST['register_activity_sector'] ) : '' ),
			'department'       => sanitize_text_field( isset( $_POST['register_department'] ) ? wp_unslash( $_POST['register_department'] ) : '' ),
			'job_title'        => sanitize_text_field( isset( $_POST['register_job_title'] ) ? wp_unslash( $_POST['register_job_title'] ) : '' ),
			'privacy_accept'   => ! empty( $_POST['register_privacy_accept'] ),
		);
		if ( '' === $redirect_to ) {
			$redirect_to = $this->dictionary_home_url();
		}

		$result = $this->register_public_user( $name, $email, $password, $password_repeat, true, $profile );
		if ( is_wp_error( $result ) ) {
			$error_code = $result->get_error_code();
			$map        = array(
				'abiquifi_sso_required'         => 'required',
				'abiquifi_sso_invalid_email'    => 'email',
				'abiquifi_sso_password_mismatch'=> 'password',
				'abiquifi_sso_password_short'   => 'password_length',
				'abiquifi_sso_invalid_phone'    => 'phone',
				'abiquifi_sso_invalid_choice'   => 'choice',
				'abiquifi_sso_privacy_required' => 'privacy',
				'abiquifi_sso_email_exists'     => 'exists',
			);
			$state      = isset( $map[ $error_code ] ) ? $map[ $error_code ] : 'error';

			wp_safe_redirect( add_query_arg( 'register_error', $state, $redirect ) );
			exit;
		}

		$this->set_public_cookie( $result['token'], $result['expires_at'] );
		$this->login_local_user( (int) $result['user']['ID'] );
		wp_safe_redirect( add_query_arg( 'registered', '1', $redirect_to ) );
		exit;
	}

	public function handle_public_forgot_password_form() {
		$redirect_to = esc_url_raw( isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : $this->dictionary_home_url() );
		if ( '' === $redirect_to ) {
			$redirect_to = $this->dictionary_home_url();
		}

		$redirect = $this->public_forgot_password_url( $redirect_to );

		if ( ! isset( $_POST['abiquifi_public_sso_forgot_password_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['abiquifi_public_sso_forgot_password_nonce'] ) ), 'abiquifi_public_sso_forgot_password' ) ) {
			wp_safe_redirect( add_query_arg( 'reset_error', 'nonce', $redirect ) );
			exit;
		}

		$login_or_email = sanitize_text_field( isset( $_POST['user_login'] ) ? wp_unslash( $_POST['user_login'] ) : '' );
		$user           = $this->find_user_by_login_or_email( $login_or_email );

		if ( ! $user instanceof WP_User ) {
			wp_safe_redirect( add_query_arg( 'reset_error', 'not_found', $redirect ) );
			exit;
		}

		$key = get_password_reset_key( $user );
		if ( is_wp_error( $key ) || ! is_string( $key ) || '' === $key ) {
			wp_safe_redirect( add_query_arg( 'reset_error', 'invalid', $redirect ) );
			exit;
		}

		$reset_url = $this->public_reset_password_url( $user->user_login, $key, $redirect_to );
		if ( ! $this->send_public_password_reset_email( $user, $reset_url ) ) {
			wp_safe_redirect( add_query_arg( 'reset_error', 'email', $redirect ) );
			exit;
		}

		wp_safe_redirect( add_query_arg( 'reset_sent', '1', $redirect ) );
		exit;
	}

	public function handle_public_reset_password_form() {
		$login       = sanitize_text_field( isset( $_POST['login'] ) ? wp_unslash( $_POST['login'] ) : '' );
		$key         = sanitize_text_field( isset( $_POST['key'] ) ? wp_unslash( $_POST['key'] ) : '' );
		$redirect_to = esc_url_raw( isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : $this->dictionary_home_url() );
		if ( '' === $redirect_to ) {
			$redirect_to = $this->dictionary_home_url();
		}

		$redirect = $this->public_reset_password_url( $login, $key, $redirect_to );

		if ( ! isset( $_POST['abiquifi_public_sso_reset_password_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['abiquifi_public_sso_reset_password_nonce'] ) ), 'abiquifi_public_sso_reset_password' ) ) {
			wp_safe_redirect( add_query_arg( 'reset_error', 'nonce', $redirect ) );
			exit;
		}

		$user = $this->validate_public_password_reset_key( $login, $key );
		if ( is_wp_error( $user ) ) {
			$state = $this->password_reset_error_state_from_code( $user->get_error_code() );
			wp_safe_redirect( add_query_arg( 'reset_error', $state, $redirect ) );
			exit;
		}

		$password        = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : '';
		$password_repeat = isset( $_POST['pass2'] ) ? (string) wp_unslash( $_POST['pass2'] ) : '';

		if ( '' === $password ) {
			wp_safe_redirect( add_query_arg( 'reset_error', 'empty', $redirect ) );
			exit;
		}

		if ( strlen( $password ) < 8 ) {
			wp_safe_redirect( add_query_arg( 'reset_error', 'short', $redirect ) );
			exit;
		}

		if ( $password !== $password_repeat ) {
			wp_safe_redirect( add_query_arg( 'reset_error', 'mismatch', $redirect ) );
			exit;
		}

		reset_password( $user, $password );
		wp_safe_redirect( add_query_arg( 'password_reset', '1', $this->public_login_url( $redirect_to ) ) );
		exit;
	}

	public function handle_public_logout() {
		$redirect = esc_url_raw( isset( $_GET['redirect_to'] ) ? wp_unslash( $_GET['redirect_to'] ) : home_url( '/' ) );
		if ( '' === $redirect ) {
			$redirect = home_url( '/' );
		}
		$token    = $this->read_cookie_token();

		if ( $this->is_authority_site() ) {
			if ( '' !== $token ) {
				$this->revoke_session_token( $token );
			}
		} else {
			$this->remote_logout( $token );
		}

		$this->clear_public_cookie();
		wp_logout();
		wp_safe_redirect( $redirect );
		exit;
	}

	public function maybe_handle_frontend_actions() {
		if ( is_admin() ) {
			return;
		}

		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) $_SERVER['REQUEST_METHOD'] ) : 'GET';

		if ( $this->request_path_matches( 'recuperar-senha' ) ) {
			if ( 'POST' === $method ) {
				$this->handle_public_forgot_password_form();
			}

			$target       = $this->public_forgot_password_url();
			$query_string = isset( $_SERVER['QUERY_STRING'] ) ? trim( (string) wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '';
			if ( '' !== $query_string ) {
				$target .= '?' . $query_string;
			}

			wp_safe_redirect( $target );
			exit;
		}

		if ( $this->request_path_matches( 'sair' ) ) {
			$this->handle_public_logout();
		}

		if ( ! $this->is_authority_site() || 'POST' !== $method ) {
			return;
		}

		if ( $this->request_path_matches( 'log-in' ) ) {
			$this->handle_dictionary_login_form();
		}

		if ( $this->request_path_matches( 'cadastro' ) ) {
			$this->handle_dictionary_register_form();
		}

		if ( $this->request_path_matches( 'esqueceu-sua-senha' ) ) {
			$this->handle_public_forgot_password_form();
		}

		if ( $this->request_path_matches( 'redefinir-senha' ) ) {
			$this->handle_public_reset_password_form();
		}
	}

	public function filter_dictionary_pages( $content ) {
		if ( ! $this->is_authority_site() || is_admin() ) {
			return $content;
		}

		if ( is_page( 'log-in' ) ) {
			return $this->render_dictionary_login_page();
		}

		if ( is_page( 'cadastro' ) ) {
			return $this->render_dictionary_register_page();
		}

		if ( is_page( 'esqueceu-sua-senha' ) ) {
			return $this->render_dictionary_forgot_password_page();
		}

		if ( is_page( 'redefinir-senha' ) ) {
			return $this->render_dictionary_reset_password_page();
		}

		if ( is_page( 'account' ) ) {
			return $this->render_public_account_page();
		}

		return $content;
	}

	public function filter_elementor_content( $content ) {
		if ( false !== strpos( $content, '[dsf_user_menu]' ) ) {
			$content = str_replace( '[dsf_user_menu]', $this->render_dsf_user_menu_shortcode(), $content );
		}

		return $content;
	}

	public function filter_public_page_template( $template ) {
		if ( ! $this->is_authority_site() || is_admin() ) {
			return $template;
		}

		if ( is_page( 'log-in' ) || is_page( 'cadastro' ) || is_page( 'esqueceu-sua-senha' ) || is_page( 'redefinir-senha' ) || is_page( 'account' ) ) {
			$plugin_template = dirname( __DIR__ ) . '/templates/public-auth-page.php';
			if ( file_exists( $plugin_template ) ) {
				return $plugin_template;
			}
		}

		return $template;
	}

	public function render_current_public_page_content() {
		if ( is_page( 'log-in' ) ) {
			return $this->render_dictionary_login_page();
		}

		if ( is_page( 'cadastro' ) ) {
			return $this->render_dictionary_register_page();
		}

		if ( is_page( 'esqueceu-sua-senha' ) ) {
			return $this->render_dictionary_forgot_password_page();
		}

		if ( is_page( 'redefinir-senha' ) ) {
			return $this->render_dictionary_reset_password_page();
		}

		if ( is_page( 'account' ) ) {
			return $this->render_public_account_page();
		}

		return '';
	}

	public function filter_body_class( $classes ) {
		if ( $this->get_public_user() ) {
			$classes = array_values(
				array_filter(
					(array) $classes,
					static function ( $class ) {
						return ! in_array( $class, array( 'logged-in', 'admin-bar', 'user-subscriber', 'role-subscriber' ), true );
					}
				)
			);
			$classes[] = 'abiquifi-public-session';
		}

		if ( $this->is_main_site() && $this->get_public_user() ) {
			$classes[] = 'abiquifi-public-recognized';
		}

		if ( $this->is_authority_site() && is_page( 'log-in' ) ) {
			$classes[] = 'abiquifi-public-view-login';
		}

		if ( $this->is_authority_site() && is_page( 'cadastro' ) ) {
			$classes[] = 'abiquifi-public-view-register';
		}

		if ( $this->is_authority_site() && is_page( 'esqueceu-sua-senha' ) ) {
			$classes[] = 'abiquifi-public-view-forgot-password';
		}

		if ( $this->is_authority_site() && is_page( 'redefinir-senha' ) ) {
			$classes[] = 'abiquifi-public-view-reset-password';
		}

		if ( $this->is_authority_site() && is_page( 'account' ) ) {
			$classes[] = 'abiquifi-public-view-account';
		}

		return $classes;
	}

	public function filter_show_admin_bar( $show ) {
		if ( ! is_admin() && $this->is_public_authenticated() ) {
			return false;
		}

		return $show;
	}

	public function filter_allowed_redirect_hosts( $hosts ) {
		$hosts   = (array) $hosts;
		$allowed = array(
			'abiquifi.questione.ai',
			'dicionario.abiquifi.questione.ai',
			'fabricamos.abiquifi.questione.ai',
		);

		foreach ( $allowed as $host ) {
			if ( ! in_array( $host, $hosts, true ) ) {
				$hosts[] = $host;
			}
		}

		return $hosts;
	}

	public function print_public_ui_styles() {
		if ( is_admin() ) {
			return;
		}

		?>
		<style id="abiquifi-public-sso-ui">
			:root {
				--abq-surface: #ffffff;
				--abq-bg: #eef1f6;
				--abq-border: #d4dbe5;
				--abq-shadow: 0 20px 44px rgba(23, 46, 84, 0.08);
				--abq-text: #203b67;
				--abq-text-strong: #1a3156;
				--abq-muted: #62728b;
				--abq-primary: #234785;
				--abq-primary-hover: #1a3568;
				--abq-radius-xl: 28px;
				--abq-radius-lg: 22px;
				--abq-radius-md: 16px;
				--abq-radius-sm: 12px;
			}

			body.abiquifi-public-session {
				overflow-x: hidden;
			}

			.abiquifi-public-session.user-subscriber header,
			.abiquifi-public-session.user-subscriber .site-header,
			.abiquifi-public-session.user-subscriber .elementor-location-header {
				display: block !important;
			}

			.jupiterx-header .elementor-widget-shortcode,
			.jupiterx-header .elementor-widget-shortcode .elementor-widget-container,
			.jupiterx-header .elementor-widget-shortcode .elementor-shortcode {
				display: flex;
				justify-content: flex-end;
				width: 100%;
				overflow: visible;
			}

			.jupiterx-header .dsf-user-menu {
				position: relative !important;
				top: auto !important;
				right: auto !important;
				z-index: 40 !important;
				display: inline-flex;
				align-items: center;
				max-width: min(100%, 220px);
				min-width: 0;
			}

			.jupiterx-header .dsf-user-menu__trigger {
				display: inline-flex;
				align-items: center;
				gap: 12px;
				padding: 6px 18px 6px 10px;
				background: #ffffff;
				border: 1px solid var(--abq-border);
				border-radius: 999px;
				box-shadow: 0 6px 14px rgba(22, 42, 77, 0.08);
				color: #2a4268;
				max-width: 100%;
				min-width: 0;
				white-space: nowrap;
				font: inherit;
				cursor: pointer;
			}

			.jupiterx-header .dsf-user-icon {
				position: relative;
				display: inline-flex;
				align-items: center;
				justify-content: center;
				width: 42px;
				height: 42px;
				flex: 0 0 42px;
				border-radius: 999px;
				background: #ffffff;
				border: 1px solid #cfd6e0;
			}

			.jupiterx-header .dsf-user-icon::before {
				content: "";
				position: absolute;
				top: 8px;
				width: 12px;
				height: 12px;
				border: 2px solid #7c8594;
				border-radius: 999px;
			}

			.jupiterx-header .dsf-user-icon::after {
				content: "";
				position: absolute;
				bottom: 8px;
				width: 22px;
				height: 12px;
				border: 2px solid #7c8594;
				border-top: 0;
				border-radius: 0 0 12px 12px;
			}

			.jupiterx-header .dsf-user-icon__ring,
			.jupiterx-header .dsf-user-icon__head {
				display: none;
			}

			.jupiterx-header .dsf-user-label {
				display: block;
				font-size: 15px;
				line-height: 1;
				letter-spacing: -0.02em;
				max-width: 120px;
				min-width: 0;
				overflow: hidden;
				text-overflow: ellipsis;
				white-space: nowrap;
			}

			.jupiterx-header .dsf-user-label strong {
				font-weight: 700;
			}

			.jupiterx-header .dsf-user-dropdown {
				position: absolute;
				top: calc(100% + 10px);
				right: 0;
				display: grid;
				gap: 2px;
				min-width: 170px;
				padding: 8px;
				background: #ffffff;
				border: 1px solid var(--abq-border);
				border-radius: 14px;
				box-shadow: 0 14px 30px rgba(20, 38, 71, 0.14);
				opacity: 0;
				visibility: hidden;
				transform: translateY(-4px);
				transition: opacity 0.16s ease, transform 0.16s ease, visibility 0.16s ease;
			}

			.jupiterx-header .dsf-user-dropdown a {
				display: block;
				padding: 10px 12px;
				border-radius: 10px;
				color: #2a4268;
				font-size: 14px;
				font-weight: 500;
				line-height: 1.2;
				text-decoration: none;
			}

			.jupiterx-header .dsf-user-dropdown a:hover,
			.jupiterx-header .dsf-user-dropdown a:focus {
				background: #eef3fb;
			}

			.jupiterx-header .dsf-user-menu:hover .dsf-user-dropdown,
			.jupiterx-header .dsf-user-menu:focus-within .dsf-user-dropdown {
				opacity: 1;
				visibility: visible;
				transform: translateY(0);
			}

			body.abiquifi-public-view-login .jupiterx-main-header,
			body.abiquifi-public-view-register .jupiterx-main-header,
			body.abiquifi-public-view-account .jupiterx-main-header,
			body.abiquifi-public-view-login .jupiterx-post-header,
			body.abiquifi-public-view-register .jupiterx-post-header,
			body.abiquifi-public-view-account .jupiterx-post-header {
				display: none !important;
			}

			body.abiquifi-public-view-login .jupiterx-main-content,
			body.abiquifi-public-view-register .jupiterx-main-content,
			body.abiquifi-public-view-account .jupiterx-main-content {
				padding-top: 24px !important;
			}

			.abiquifi-public-auth {
				max-width: 1480px;
				margin: 0 auto;
				padding: 36px 12px 40px;
				font-family: "Inter", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
			}

			.abiquifi-public-auth--login,
			.abiquifi-public-auth--register,
			.abiquifi-public-auth--account {
				display: block;
				min-height: calc(100vh - 220px);
			}

			.abiquifi-public-auth__shell {
				width: 100%;
				max-width: 520px;
				margin: 48px auto 0;
			}

			.abiquifi-public-auth__shell--wide {
				max-width: 980px;
			}

			.abiquifi-public-auth--login .abiquifi-public-auth__shell {
				margin-top: 128px;
			}

			.abiquifi-public-auth--register .abiquifi-public-auth__shell {
				margin-top: 64px;
			}

			.abiquifi-public-auth__card {
				background: var(--abq-surface);
				border: 1px solid #dde4ef;
				border-radius: var(--abq-radius-xl);
				box-shadow: var(--abq-shadow);
				padding: 34px;
				color: var(--abq-text);
				overflow: visible;
			}

			.abiquifi-public-auth__card h1 {
				margin: 0 0 24px;
				font-size: 34px;
				line-height: 1;
				letter-spacing: -0.04em;
				color: var(--abq-text-strong);
			}

			.abiquifi-public-auth__card p {
				margin: 0 0 16px;
				color: var(--abq-muted);
				line-height: 1.6;
			}

			.abiquifi-public-auth__card p strong {
				color: var(--abq-text-strong);
			}

			.abiquifi-public-auth__form {
				display: grid;
				gap: 14px;
			}

			.abiquifi-public-auth__form p {
				margin: 0;
			}

			.abiquifi-public-auth__grid {
				display: grid;
				gap: 14px;
			}

			.abiquifi-public-auth__grid--2 {
				grid-template-columns: repeat(2, minmax(0, 1fr));
			}

			.abiquifi-public-auth__form label {
				display: block;
				margin-bottom: 8px;
				font-size: 14px;
				font-weight: 600;
				color: var(--abq-text-strong);
			}

			.abiquifi-public-auth__form input[type="text"],
			.abiquifi-public-auth__form input[type="email"],
			.abiquifi-public-auth__form input[type="password"],
			.abiquifi-public-auth__form select {
				width: 100%;
				border: 1px solid #c8d1df;
				border-radius: 4px;
				background: #ffffff;
				color: var(--abq-text);
				padding: 11px 14px;
				font-size: 14px;
				outline: none;
				transition: border-color 0.2s ease, box-shadow 0.2s ease;
			}

			.abiquifi-public-auth__form input[type="text"]:focus,
			.abiquifi-public-auth__form input[type="email"]:focus,
			.abiquifi-public-auth__form input[type="password"]:focus,
			.abiquifi-public-auth__form select:focus {
				border-color: #77add8;
				box-shadow: 0 0 0 4px rgba(58, 160, 223, 0.12);
			}

			.abiquifi-public-auth__checkbox {
				display: inline-flex;
				align-items: center;
				gap: 10px;
				font-weight: 500;
				color: var(--abq-text);
			}

			.abiquifi-public-auth__checkbox--legal {
				display: flex;
				width: 100%;
				align-items: flex-start;
				font-size: 13px;
				line-height: 1.6;
			}

			.abiquifi-public-auth__checkbox--legal input {
				margin-top: 4px;
				flex: 0 0 auto;
			}

			.abiquifi-public-auth__checkbox--legal span {
				flex: 1 1 auto;
				min-width: 0;
			}

			.abiquifi-public-auth__req {
				color: #b44943;
			}

			.abiquifi-public-auth__button,
			.abiquifi-public-auth__actions a {
				display: inline-flex;
				align-items: center;
				justify-content: center;
				padding: 13px 18px;
				border: 0;
				border-radius: 4px;
				text-decoration: none;
				font-size: 14px;
				font-weight: 700;
				cursor: pointer;
				transition: background-color 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
			}

			.abiquifi-public-auth__button:hover,
			.abiquifi-public-auth__button:focus,
			.abiquifi-public-auth__actions a:hover,
			.abiquifi-public-auth__actions a:focus {
				transform: translateY(-1px);
			}

			.abiquifi-public-auth__button {
				background: var(--abq-primary);
				color: #ffffff;
				box-shadow: 0 10px 24px rgba(35, 71, 133, 0.12);
			}

			.abiquifi-public-auth__button:hover,
			.abiquifi-public-auth__button:focus {
				background: var(--abq-primary-hover);
				color: #ffffff;
			}

			.abiquifi-public-auth__actions {
				display: grid;
				gap: 12px;
				margin-top: 22px;
			}

			.abiquifi-public-auth__actions--inline {
				display: flex;
				flex-wrap: wrap;
				align-items: center;
				justify-content: flex-start;
				gap: 12px;
				margin-top: 10px;
			}

			.abiquifi-public-auth__actions--inline .abiquifi-public-auth__button,
			.abiquifi-public-auth__actions--inline a {
				min-width: 160px;
			}

			.abiquifi-public-auth__actions a:first-child {
				background: var(--abq-primary);
				color: #ffffff;
			}

			.abiquifi-public-auth__actions a:last-child {
				background: #ffffff;
				color: var(--abq-text);
				border: 1px solid #c8d1df;
			}

			.abiquifi-public-auth__footer {
				margin-top: 12px;
				font-size: 15px;
				color: var(--abq-muted);
			}

			.abiquifi-public-auth__submit {
				margin-top: 10px !important;
			}

			.abiquifi-public-auth__footer a {
				color: var(--abq-primary);
				font-weight: 600;
				text-decoration: none;
			}

			.abiquifi-public-auth__alert {
				margin: 0 0 18px;
				padding: 14px 18px;
				border-radius: 16px;
				font-weight: 600;
				background: rgba(180, 73, 67, 0.12);
				color: #b44943;
			}

			.abiquifi-public-auth__success {
				margin: 0 0 18px;
				padding: 14px 18px;
				border-radius: 16px;
				font-weight: 600;
				background: rgba(52, 132, 86, 0.12);
				color: #348456;
			}

			@media (max-width: 1024px) {
				.jupiterx-header .dsf-user-label {
					display: none;
				}
			}

			@media (max-width: 767px) {
				.abiquifi-public-auth__shell {
					margin-top: 24px;
				}

				.abiquifi-public-auth--login .abiquifi-public-auth__shell,
				.abiquifi-public-auth--register .abiquifi-public-auth__shell {
					margin-top: 36px;
				}

				body.abiquifi-public-view-login .jupiterx-main-content,
				body.abiquifi-public-view-register .jupiterx-main-content,
				body.abiquifi-public-view-account .jupiterx-main-content {
					padding-top: 16px !important;
				}

				.abiquifi-public-auth {
					padding-top: 20px;
					padding-bottom: 28px;
				}

				.abiquifi-public-auth__grid--2 {
					grid-template-columns: 1fr;
				}

				.abiquifi-public-auth__card {
					padding: 20px;
				}

				.abiquifi-public-auth__actions--inline {
					flex-direction: column;
					align-items: stretch;
				}

				.abiquifi-public-auth__actions--inline .abiquifi-public-auth__button,
				.abiquifi-public-auth__actions--inline a {
					width: 100%;
					min-width: 0;
				}
			}
		</style>
		<?php
	}

	public function print_public_session_script() {
		$user = $this->get_public_user();
		if ( ! $user ) {
			echo "<script>window.AbiquifiPublicSession={authenticated:false};</script>\n";
			return;
		}

		$payload = array(
			'authenticated' => true,
			'user'          => array(
				'id'           => (int) $user['ID'],
				'email'        => $user['user_email'],
				'display_name' => $user['display_name'],
			),
			'source'        => $this->site_role(),
		);

		echo '<script>window.AbiquifiPublicSession=' . wp_json_encode( $payload ) . ';</script>' . "\n";
	}

	public function render_dsf_user_menu_shortcode() {
		return '';
	}

	protected function render_public_account_page() {
		$user = $this->get_public_user();

		if ( ! $user ) {
			$this->require_public_authentication( $this->public_account_url() );
		}

		ob_start();
		?>
		<section class="abiquifi-public-auth abiquifi-public-auth--account">
			<div class="abiquifi-public-auth__shell">
				<div class="abiquifi-public-auth__card">
					<h1>Minha conta</h1>
					<p><strong>Nome:</strong> <?php echo esc_html( $user['display_name'] ); ?></p>
					<p><strong>E-mail:</strong> <?php echo esc_html( $user['user_email'] ); ?></p>
					<div class="abiquifi-public-auth__actions">
						<a href="<?php echo esc_url( $this->public_logout_url( home_url( '/' ) ) ); ?>">Sair</a>
					</div>
				</div>
			</div>
		</section>
		<?php

		return (string) ob_get_clean();
	}

	protected function render_dictionary_login_page() {
		$user        = $this->get_public_user();
		$login_error = isset( $_GET['login_error'] ) ? sanitize_text_field( wp_unslash( $_GET['login_error'] ) ) : '';
		$registered  = isset( $_GET['registered'] ) ? sanitize_text_field( wp_unslash( $_GET['registered'] ) ) : '';
		$password_reset = isset( $_GET['password_reset'] ) ? sanitize_text_field( wp_unslash( $_GET['password_reset'] ) ) : '';
		$redirect_to = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : $this->dictionary_home_url();
		if ( '' === $redirect_to ) {
			$redirect_to = $this->dictionary_home_url();
		}

		ob_start();
		?>
		<div class="abiquifi-public-auth abiquifi-public-auth--login">
			<div class="abiquifi-public-auth__shell abiquifi-public-auth__shell--wide">
				<div class="abiquifi-public-auth__card">
			<?php if ( $user ) : ?>
					<p>Você já está autenticado como <strong><?php echo esc_html( $user['display_name'] ); ?></strong>.</p>
					<div class="abiquifi-public-auth__actions">
						<a href="<?php echo esc_url( $this->dictionary_home_url() ); ?>">Ir para o dicionário</a>
						<a href="<?php echo esc_url( $this->public_logout_url( $this->dictionary_home_url() ) ); ?>">Sair</a>
					</div>
			<?php else : ?>
				<h1>Entrar</h1>
				<p>Entre com seu nome de usuário ou endereço de e-mail para acessar o dicionário.</p>
				<?php if ( '1' === $registered ) : ?>
					<p class="abiquifi-public-auth__success">Cadastro concluído. Sua sessão já foi iniciada.</p>
				<?php endif; ?>
				<?php if ( '1' === $password_reset ) : ?>
					<p class="abiquifi-public-auth__success">Senha redefinida com sucesso. Voce ja pode entrar com a nova senha.</p>
				<?php endif; ?>
				<?php if ( $login_error ) : ?>
					<p class="abiquifi-public-auth__alert">Usuário, e-mail ou senha inválidos.</p>
				<?php endif; ?>
				<form action="<?php echo esc_url( home_url( '/log-in/' ) ); ?>" method="post" class="abiquifi-public-auth__form">
					<input type="hidden" name="action" value="abiquifi_public_sso_login" />
					<input type="hidden" name="redirect_to" value="<?php echo esc_url( $redirect_to ); ?>" />
					<?php wp_nonce_field( 'abiquifi_public_sso_login', 'abiquifi_public_sso_login_nonce' ); ?>
					<p>
						<label for="abiquifi-sso-login-email">Nome de usuário ou endereço de e-mail <span class="abiquifi-public-auth__req">*</span></label>
						<input id="abiquifi-sso-login-email" name="log" type="text" required />
					</p>
					<p>
						<label for="abiquifi-sso-login-password">Senha <span class="abiquifi-public-auth__req">*</span></label>
						<input id="abiquifi-sso-login-password" name="pwd" type="password" required />
					</p>
					<p>
						<label class="abiquifi-public-auth__checkbox"><input name="rememberme" type="checkbox" value="1" /> Lembrar de mim</label>
					</p>
					<p><button type="submit" class="abiquifi-public-auth__button">Entrar</button></p>
				</form>
				<p class="abiquifi-public-auth__footer">Não tem conta? <a href="<?php echo esc_url( home_url( '/cadastro/' ) ); ?>">Crie sua conta &raquo;</a></p>
				<p class="abiquifi-public-auth__footer"><a href="<?php echo esc_url( $this->public_forgot_password_url( $redirect_to ) ); ?>">Esqueceu sua senha?</a></p>
			<?php endif; ?>
				</div>
			</div>
		</div>
		<?php

		return (string) ob_get_clean();
	}

	protected function privacy_policy_url() {
		if ( function_exists( 'wp_get_privacy_policy_url' ) ) {
			return (string) wp_get_privacy_policy_url();
		}

		$privacy_page_id = (int) get_option( 'wp_page_for_privacy_policy' );
		if ( $privacy_page_id > 0 ) {
			$url = get_permalink( $privacy_page_id );
			if ( is_string( $url ) ) {
				return $url;
			}
		}

		return '';
	}

	protected function terms_of_use_url() {
		$slugs = array(
			'termos-de-uso',
			'termos-e-condicoes-gerais-de-uso',
			'termos-e-condicoes',
			'termos',
		);

		foreach ( $slugs as $slug ) {
			$page = get_page_by_path( $slug, OBJECT, 'page' );
			if ( $page instanceof WP_Post ) {
				$url = get_permalink( $page );
				if ( is_string( $url ) && '' !== $url ) {
					return $url;
				}
			}
		}

		return '';
	}

	protected function render_dictionary_register_page() {
		$user           = $this->get_public_user();
		$register_error = isset( $_GET['register_error'] ) ? sanitize_text_field( wp_unslash( $_GET['register_error'] ) ) : '';
		$redirect_to    = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : $this->dictionary_home_url();
		$login_url      = home_url( '/log-in/' );
		$terms_url      = $this->terms_of_use_url();
		if ( '' === $terms_url ) {
			$terms_url = $this->privacy_policy_url();
		}
		if ( '' === $redirect_to ) {
			$redirect_to = $this->dictionary_home_url();
		}

		ob_start();
		?>
		<div class="abiquifi-public-auth abiquifi-public-auth--register">
			<div class="abiquifi-public-auth__shell abiquifi-public-auth__shell--wide">
				<div class="abiquifi-public-auth__card">
			<?php if ( $user ) : ?>
					<p>Você já possui uma conta ativa.</p>
					<div class="abiquifi-public-auth__actions">
						<a href="<?php echo esc_url( $this->dictionary_home_url() ); ?>">Ir para o dicionário</a>
						<a href="<?php echo esc_url( $this->public_logout_url( $this->dictionary_home_url() ) ); ?>">Sair</a>
					</div>
			<?php else : ?>
				<h1>Cadastro</h1>
				<?php if ( $register_error ) : ?>
					<p class="abiquifi-public-auth__alert"><?php echo esc_html( $this->registration_error_message( $register_error ) ); ?></p>
				<?php endif; ?>
				<form action="<?php echo esc_url( home_url( '/cadastro/' ) ); ?>" method="post" class="abiquifi-public-auth__form">
					<input type="hidden" name="action" value="abiquifi_public_sso_register" />
					<input type="hidden" name="redirect_to" value="<?php echo esc_url( $redirect_to ); ?>" />
					<?php wp_nonce_field( 'abiquifi_public_sso_register', 'abiquifi_public_sso_register_nonce' ); ?>
					<div class="abiquifi-public-auth__grid abiquifi-public-auth__grid--2">
						<p>
							<label for="abiquifi-sso-register-name">Nome <span class="abiquifi-public-auth__req">*</span></label>
							<input id="abiquifi-sso-register-name" name="register_name" type="text" placeholder="Digite seu nome" required />
						</p>
						<p>
							<label for="abiquifi-sso-register-last-name">Sobrenome <span class="abiquifi-public-auth__req">*</span></label>
							<input id="abiquifi-sso-register-last-name" name="register_last_name" type="text" placeholder="Digite seu sobrenome" required />
						</p>
					</div>
					<p>
						<label for="abiquifi-sso-register-email">E-mail <span class="abiquifi-public-auth__req">*</span></label>
						<input id="abiquifi-sso-register-email" name="register_email" type="email" required />
					</p>
					<p>
						<label for="abiquifi-sso-register-password">Senha <span class="abiquifi-public-auth__req">*</span></label>
						<input id="abiquifi-sso-register-password" name="register_password" type="password" minlength="8" required />
					</p>
					<p>
						<label for="abiquifi-sso-register-institution">Nome da Instituição <span class="abiquifi-public-auth__req">*</span></label>
						<input id="abiquifi-sso-register-institution" name="register_institution_name" type="text" placeholder="Empresa ou instituição" required />
					</p>
					<div class="abiquifi-public-auth__grid abiquifi-public-auth__grid--2">
						<p>
							<label for="abiquifi-sso-register-phone">Celular / WhatsApp <span class="abiquifi-public-auth__req">*</span></label>
							<input id="abiquifi-sso-register-phone" name="register_phone" type="text" placeholder="(00) 00000-0000" required />
						</p>
						<p>
							<label for="abiquifi-sso-register-activity">Ramo de Atividade <span class="abiquifi-public-auth__req">*</span></label>
							<select id="abiquifi-sso-register-activity" name="register_activity_sector" required>
								<option value="">Escolha uma opção</option>
								<?php foreach ( $this->dictionary_activity_options() as $option ) : ?>
									<option value="<?php echo esc_attr( $option ); ?>"><?php echo esc_html( $option ); ?></option>
								<?php endforeach; ?>
							</select>
						</p>
					</div>
					<div class="abiquifi-public-auth__grid abiquifi-public-auth__grid--2">
						<p>
							<label for="abiquifi-sso-register-department">Departamento <span class="abiquifi-public-auth__req">*</span></label>
							<select id="abiquifi-sso-register-department" name="register_department" required>
								<option value="">Escolha uma opção</option>
								<?php foreach ( $this->dictionary_department_options() as $option ) : ?>
									<option value="<?php echo esc_attr( $option ); ?>"><?php echo esc_html( $option ); ?></option>
								<?php endforeach; ?>
							</select>
						</p>
						<p>
							<label for="abiquifi-sso-register-job-title">Cargo <span class="abiquifi-public-auth__req">*</span></label>
							<select id="abiquifi-sso-register-job-title" name="register_job_title" required>
								<option value="">Escolha uma opção</option>
								<?php foreach ( $this->dictionary_job_title_options() as $option ) : ?>
									<option value="<?php echo esc_attr( $option ); ?>"><?php echo esc_html( $option ); ?></option>
								<?php endforeach; ?>
							</select>
						</p>
					</div>
					<p>
						<label class="abiquifi-public-auth__checkbox abiquifi-public-auth__checkbox--legal">
							<input name="register_privacy_accept" type="checkbox" value="1" required />
							<span>
								Li e aceito os
								<?php if ( $terms_url ) : ?>
									<a href="<?php echo esc_url( $terms_url ); ?>" target="_blank" rel="noopener">Termos de Uso</a>
								<?php else : ?>
									Termos de Uso
								<?php endif; ?>
								e autorizo o Dicionário de Substâncias Farmacêuticas (DSF) a coletar e armazenar os dados enviados neste formulário.
								<span class="abiquifi-public-auth__req">*</span>
							</span>
						</label>
					</p>
					<div class="abiquifi-public-auth__actions abiquifi-public-auth__actions--inline">
						<button type="submit" class="abiquifi-public-auth__button">Criar conta</button>
						<a href="<?php echo esc_url( $login_url ); ?>">Entrar</a>
					</div>
				</form>
				<p class="abiquifi-public-auth__footer"><a href="<?php echo esc_url( $this->public_forgot_password_url( $redirect_to ) ); ?>">Esqueceu sua senha?</a></p>
			<?php endif; ?>
				</div>
			</div>
		</div>
		<?php

		return (string) ob_get_clean();
	}

	protected function render_dictionary_forgot_password_page() {
		$user          = $this->get_public_user();
		$reset_error   = isset( $_GET['reset_error'] ) ? sanitize_text_field( wp_unslash( $_GET['reset_error'] ) ) : '';
		$reset_sent    = isset( $_GET['reset_sent'] ) ? sanitize_text_field( wp_unslash( $_GET['reset_sent'] ) ) : '';
		$redirect_to   = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : $this->dictionary_home_url();
		$login_url     = $this->public_login_url( $redirect_to );

		if ( '' === $redirect_to ) {
			$redirect_to = $this->dictionary_home_url();
			$login_url   = $this->public_login_url( $redirect_to );
		}

		ob_start();
		?>
		<div class="abiquifi-public-auth abiquifi-public-auth--forgot-password">
			<div class="abiquifi-public-auth__shell abiquifi-public-auth__shell--wide">
				<div class="abiquifi-public-auth__card">
			<?php if ( $user ) : ?>
					<p>Voce ja esta autenticado como <strong><?php echo esc_html( $user['display_name'] ); ?></strong>.</p>
					<div class="abiquifi-public-auth__actions">
						<a href="<?php echo esc_url( $this->dictionary_home_url() ); ?>">Ir para o dicionario</a>
						<a href="<?php echo esc_url( $this->public_logout_url( $this->dictionary_home_url() ) ); ?>">Sair</a>
					</div>
			<?php else : ?>
				<h1>Esqueceu sua senha?</h1>
				<p>Informe seu e-mail ou nome de usuario para receber o link de redefinicao de senha.</p>
				<?php if ( '1' === $reset_sent ) : ?>
					<p class="abiquifi-public-auth__success">Enviamos um e-mail com o link para redefinir a senha.</p>
				<?php endif; ?>
				<?php if ( $reset_error ) : ?>
					<p class="abiquifi-public-auth__alert"><?php echo esc_html( $this->forgot_password_error_message( $reset_error ) ); ?></p>
				<?php endif; ?>
				<form action="<?php echo esc_url( $this->public_forgot_password_url( $redirect_to ) ); ?>" method="post" class="abiquifi-public-auth__form">
					<input type="hidden" name="action" value="abiquifi_public_sso_forgot_password" />
					<input type="hidden" name="redirect_to" value="<?php echo esc_url( $redirect_to ); ?>" />
					<?php wp_nonce_field( 'abiquifi_public_sso_forgot_password', 'abiquifi_public_sso_forgot_password_nonce' ); ?>
					<p>
						<label for="abiquifi-sso-forgot-password-login">E-mail ou nome de usuario <span class="abiquifi-public-auth__req">*</span></label>
						<input id="abiquifi-sso-forgot-password-login" name="user_login" type="text" required />
					</p>
					<div class="abiquifi-public-auth__actions abiquifi-public-auth__actions--inline">
						<button type="submit" class="abiquifi-public-auth__button">Enviar link de redefinicao</button>
						<a href="<?php echo esc_url( $login_url ); ?>">Voltar ao login</a>
					</div>
				</form>
			<?php endif; ?>
				</div>
			</div>
		</div>
		<?php

		return (string) ob_get_clean();
	}

	protected function render_dictionary_reset_password_page() {
		$user        = $this->get_public_user();
		$reset_error = isset( $_GET['reset_error'] ) ? sanitize_text_field( wp_unslash( $_GET['reset_error'] ) ) : '';
		$redirect_to = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : $this->dictionary_home_url();
		$login       = isset( $_GET['login'] ) ? sanitize_text_field( wp_unslash( $_GET['login'] ) ) : '';
		$key         = isset( $_GET['key'] ) ? sanitize_text_field( wp_unslash( $_GET['key'] ) ) : '';
		$login_url   = $this->public_login_url( $redirect_to );

		if ( '' === $redirect_to ) {
			$redirect_to = $this->dictionary_home_url();
			$login_url   = $this->public_login_url( $redirect_to );
		}

		$reset_user = null;
		if ( '' !== $login && '' !== $key ) {
			$reset_user = $this->validate_public_password_reset_key( $login, $key );
			if ( is_wp_error( $reset_user ) && '' === $reset_error ) {
				$reset_error = $this->password_reset_error_state_from_code( $reset_user->get_error_code() );
			}
		} elseif ( '' === $reset_error ) {
			$reset_error = 'invalid_key';
		}

		ob_start();
		?>
		<div class="abiquifi-public-auth abiquifi-public-auth--reset-password">
			<div class="abiquifi-public-auth__shell abiquifi-public-auth__shell--wide">
				<div class="abiquifi-public-auth__card">
			<?php if ( $user && ! ( $reset_user instanceof WP_User ) ) : ?>
					<p>Voce ja esta autenticado como <strong><?php echo esc_html( $user['display_name'] ); ?></strong>.</p>
					<div class="abiquifi-public-auth__actions">
						<a href="<?php echo esc_url( $this->dictionary_home_url() ); ?>">Ir para o dicionario</a>
						<a href="<?php echo esc_url( $this->public_logout_url( $this->dictionary_home_url() ) ); ?>">Sair</a>
					</div>
			<?php else : ?>
				<h1>Redefinir senha</h1>
				<?php if ( $reset_error ) : ?>
					<p class="abiquifi-public-auth__alert"><?php echo esc_html( $this->reset_password_error_message( $reset_error ) ); ?></p>
				<?php endif; ?>
				<?php if ( $reset_user instanceof WP_User ) : ?>
					<p>Defina sua nova senha para a conta <strong><?php echo esc_html( $reset_user->user_email ); ?></strong>.</p>
					<form action="<?php echo esc_url( $this->public_reset_password_url( $login, $key, $redirect_to ) ); ?>" method="post" class="abiquifi-public-auth__form">
						<input type="hidden" name="action" value="abiquifi_public_sso_reset_password" />
						<input type="hidden" name="login" value="<?php echo esc_attr( $login ); ?>" />
						<input type="hidden" name="key" value="<?php echo esc_attr( $key ); ?>" />
						<input type="hidden" name="redirect_to" value="<?php echo esc_url( $redirect_to ); ?>" />
						<?php wp_nonce_field( 'abiquifi_public_sso_reset_password', 'abiquifi_public_sso_reset_password_nonce' ); ?>
						<p>
							<label for="abiquifi-sso-reset-password-1">Nova senha <span class="abiquifi-public-auth__req">*</span></label>
							<input id="abiquifi-sso-reset-password-1" name="pass1" type="password" minlength="8" required />
						</p>
						<p>
							<label for="abiquifi-sso-reset-password-2">Confirmar nova senha <span class="abiquifi-public-auth__req">*</span></label>
							<input id="abiquifi-sso-reset-password-2" name="pass2" type="password" minlength="8" required />
						</p>
						<div class="abiquifi-public-auth__actions abiquifi-public-auth__actions--inline">
							<button type="submit" class="abiquifi-public-auth__button">Salvar nova senha</button>
							<a href="<?php echo esc_url( $login_url ); ?>">Voltar ao login</a>
						</div>
					</form>
				<?php else : ?>
					<p><a href="<?php echo esc_url( $this->public_forgot_password_url( $redirect_to ) ); ?>">Solicitar um novo link</a></p>
				<?php endif; ?>
			<?php endif; ?>
				</div>
			</div>
		</div>
		<?php

		return (string) ob_get_clean();
	}

	protected function registration_error_message( $state ) {
		if ( 'required' === $state ) {
			return 'Preencha todos os campos obrigatórios.';
		}

		if ( 'email' === $state ) {
			return 'Informe um e-mail válido.';
		}

		if ( 'password' === $state ) {
			return 'As senhas informadas não coincidem.';
		}

		if ( 'password_length' === $state ) {
			return 'A senha precisa ter pelo menos 8 caracteres.';
		}

		if ( 'phone' === $state ) {
			return 'Informe um celular ou WhatsApp válido.';
		}

		if ( 'choice' === $state ) {
			return 'Selecione opções válidas para ramo, departamento e cargo.';
		}

		if ( 'privacy' === $state ) {
			return 'É necessário aceitar os Termos de Uso para continuar.';
		}

		if ( 'exists' === $state ) {
			return 'Já existe uma conta com este e-mail.';
		}

		return 'Não foi possível criar a conta.';
	}

	protected function forgot_password_error_message( $state ) {
		if ( 'required' === $state ) {
			return 'Informe seu e-mail ou nome de usuario.';
		}

		if ( 'not_found' === $state ) {
			return 'Nao foi encontrada uma conta com esse e-mail ou nome de usuario.';
		}

		if ( 'email' === $state ) {
			return 'Nao foi possivel enviar o e-mail de redefinicao agora.';
		}

		if ( 'nonce' === $state ) {
			return 'Sua solicitacao expirou. Tente novamente.';
		}

		if ( 'invalid' === $state ) {
			return 'Nao foi possivel iniciar a redefinicao de senha.';
		}

		return 'Nao foi possivel processar sua solicitacao.';
	}

	protected function reset_password_error_message( $state ) {
		if ( 'invalid_key' === $state || 'expired_key' === $state ) {
			return 'O link de redefinicao e invalido ou expirou.';
		}

		if ( 'empty' === $state ) {
			return 'Informe a nova senha.';
		}

		if ( 'short' === $state ) {
			return 'A senha precisa ter pelo menos 8 caracteres.';
		}

		if ( 'mismatch' === $state ) {
			return 'A confirmacao da senha nao confere.';
		}

		if ( 'nonce' === $state ) {
			return 'Sua solicitacao expirou. Tente novamente.';
		}

		return 'Nao foi possivel redefinir a senha.';
	}

	protected function dictionary_home_url() {
		return home_url( '/dicionario-dsf/' );
	}

	protected function dictionary_activity_options() {
		return array(
			'Agencia Governamental',
			'Consultorias',
			'Distribuidor / Importador',
			'Entidade de Classe',
			'Fabricante de IFA',
			'Fabricante de Medicamentos',
			'ICT - Instituto de Ciencia e Tecnologia',
			'Laboratorio Oficial',
			'Universidades',
			'Orgaos de Administracao Publica',
			'Outros',
		);
	}

	protected function dictionary_department_options() {
		return array(
			'Suprimentos',
			'Importacao',
			'MKT',
			'Vendas',
			'Exportacao',
			'PD&I',
			'Assuntos Regulatorios',
			'Novos Negocios',
			'Outros',
		);
	}

	protected function dictionary_job_title_options() {
		return array(
			'Analista',
			'Pesquisador',
			'Coordenador',
			'Gerente',
			'Especialista',
			'Consultor',
			'Diretor',
			'Presidente / Vice-Presidente / CEO',
			'Outros',
		);
	}

	protected function normalize_dictionary_choice_key( $value ) {
		$value = remove_accents( (string) $value );
		$value = strtolower( trim( $value ) );
		$value = preg_replace( '/[^a-z0-9]+/i', ' ', $value );

		return is_string( $value ) ? trim( preg_replace( '/\s+/', ' ', $value ) ) : '';
	}

	protected function resolve_dictionary_choice( $value, $options, $fallback_to_others = false ) {
		$value   = trim( (string) $value );
		$options = array_values( array_filter( array_map( 'strval', (array) $options ) ) );

		if ( '' === $value ) {
			return '';
		}

		if ( in_array( $value, $options, true ) ) {
			return $value;
		}

		$normalized_value = $this->normalize_dictionary_choice_key( $value );
		foreach ( $options as $option ) {
			if ( $normalized_value === $this->normalize_dictionary_choice_key( $option ) ) {
				return $option;
			}
		}

		if ( $fallback_to_others && in_array( 'Outros', $options, true ) ) {
			if ( function_exists( 'abiquifi_mailer_log' ) ) {
				abiquifi_mailer_log(
					'Cadastro publico recebeu opcao fora da lista e foi ajustado para Outros.',
					array(
						'original_value' => $value,
						'normalized'     => $normalized_value,
					)
				);
			}

			return 'Outros';
		}

		return '';
	}

	protected function normalize_dictionary_profile_choices( $profile ) {
		$profile = is_array( $profile ) ? $profile : array();

		if ( isset( $profile['activity_sector'] ) ) {
			$profile['activity_sector'] = $this->resolve_dictionary_choice( $profile['activity_sector'], $this->dictionary_activity_options(), true );
		}

		if ( isset( $profile['department'] ) ) {
			$profile['department'] = $this->resolve_dictionary_choice( $profile['department'], $this->dictionary_department_options(), true );
		}

		if ( isset( $profile['job_title'] ) ) {
			$profile['job_title'] = $this->resolve_dictionary_choice( $profile['job_title'], $this->dictionary_job_title_options(), true );
		}

		return $profile;
	}

	protected function is_valid_phone( $phone ) {
		$digits = preg_replace( '/\D+/', '', (string) $phone );
		$length = strlen( $digits );

		return $length >= 10 && $length <= 13;
	}

	protected function find_user_by_login_or_email( $login_or_email ) {
		$login_or_email = trim( (string) $login_or_email );
		if ( '' === $login_or_email ) {
			return null;
		}

		$user = null;
		if ( is_email( $login_or_email ) ) {
			$user = get_user_by( 'email', $login_or_email );
		}

		if ( ! $user ) {
			$user = get_user_by( 'login', $login_or_email );
		}

		return $user instanceof WP_User ? $user : null;
	}

	protected function validate_public_password_reset_key( $login, $key ) {
		$login = trim( (string) $login );
		$key   = trim( (string) $key );

		if ( '' === $login || '' === $key ) {
			return new WP_Error( 'invalid_key', 'Link invalido.', array( 'status' => 400 ) );
		}

		return check_password_reset_key( $key, $login );
	}

	protected function password_reset_error_state_from_code( $code ) {
		if ( 'expired_key' === $code ) {
			return 'expired_key';
		}

		return 'invalid_key';
	}

	protected function send_public_password_reset_email( $user, $reset_url ) {
		if ( ! $user instanceof WP_User || ! $user->exists() ) {
			return false;
		}

		$to = sanitize_email( (string) $user->user_email );
		if ( '' === $to || ! is_email( $to ) ) {
			return false;
		}

		$name     = $user->display_name ? $user->display_name : $user->user_login;
		$subject  = 'Redefinicao de senha | Dicionario';
		$headers  = array(
			'Content-Type: text/html; charset=UTF-8',
			'From: ' . $this->mail_from_name() . ' <' . $this->mail_from_email() . '>',
		);
		$message  = sprintf(
			'<html><body style="margin:0;padding:0;background:#f4f7fb;font-family:Arial,sans-serif;color:#162b40;">' .
			'<div style="max-width:640px;margin:0 auto;padding:32px 20px;">' .
			'<div style="background:#ffffff;border-radius:16px;padding:32px;border:1px solid #d9e2ec;">' .
			'<p style="margin:0 0 16px;font-size:14px;letter-spacing:.08em;text-transform:uppercase;color:#6c8195;">Abiquifi</p>' .
			'<h1 style="margin:0 0 20px;font-size:28px;line-height:1.2;color:#0d2236;">Redefinicao de senha</h1>' .
			'<p style="margin:0 0 16px;font-size:16px;line-height:1.6;">Ola %1$s, recebemos uma solicitacao para redefinir a senha da sua conta.</p>' .
			'<p style="margin:0 0 16px;font-size:16px;line-height:1.6;">Use o botao abaixo para criar uma nova senha.</p>' .
			'<p style="margin:0 0 24px;"><a href="%2$s" style="display:inline-block;background:#0d2236;color:#ffffff;text-decoration:none;padding:14px 20px;border-radius:999px;font-weight:700;">Redefinir senha</a></p>' .
			'<p style="margin:0 0 16px;font-size:14px;line-height:1.6;color:#6c8195;">Se voce nao solicitou esta redefinicao, ignore esta mensagem.</p>' .
			'<p style="margin:0;font-size:13px;line-height:1.6;color:#6c8195;">Mensagem automatica enviada por %3$s.</p>' .
			'</div></div></body></html>',
			esc_html( $name ),
			esc_url( $reset_url ),
			esc_html( $this->mail_from_name() )
		);

		return (bool) wp_mail( $to, $subject, $message, $headers );
	}

	protected function authenticate_credentials( $login, $password, $remember ) {
		$login = trim( (string) $login );

		if ( '' === $login || '' === $password ) {
			return new WP_Error( 'abiquifi_sso_required', 'Informe e-mail e senha.', array( 'status' => 400 ) );
		}

		$user = $this->find_user_by_login_or_email( $login );

		if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			return new WP_Error( 'abiquifi_sso_invalid_credentials', 'Credenciais invalidas.', array( 'status' => 401 ) );
		}

		return $this->build_session_payload( $user, $remember );
	}

	protected function register_public_user( $name, $email, $password, $password_repeat, $remember, $profile = array() ) {
		$name  = trim( (string) $name );
		$email = trim( (string) $email );
		$password = (string) $password;
		$password_repeat = (string) $password_repeat;
		if ( '' === $password_repeat && '' !== $password ) {
			$password_repeat = $password;
		}
		$profile = $this->normalize_dictionary_profile_choices( $profile );
		$first_name = empty( $profile['first_name'] ) ? $name : trim( (string) $profile['first_name'] );
		$last_name  = empty( $profile['last_name'] ) ? '' : trim( (string) $profile['last_name'] );
		$display_name = trim( $first_name . ' ' . $last_name );
		if ( '' === $display_name ) {
			$display_name = $name;
		}

		if ( '' === $name || '' === $email || '' === $password || '' === $password_repeat ) {
			if ( function_exists( 'abiquifi_mailer_log' ) ) {
				abiquifi_mailer_log(
					'Cadastro publico rejeitado por campos obrigatorios ausentes.',
					array(
						'name'             => '' !== $name,
						'email'            => '' !== $email,
						'password'         => '' !== $password,
						'password_repeat'  => '' !== $password_repeat,
						'institution_name' => ! empty( $profile['institution_name'] ),
						'phone'            => ! empty( $profile['phone'] ),
						'activity_sector'  => ! empty( $profile['activity_sector'] ),
						'department'       => ! empty( $profile['department'] ),
						'job_title'        => ! empty( $profile['job_title'] ),
						'privacy_accept'   => ! empty( $profile['privacy_accept'] ),
					)
				);
			}
			return new WP_Error( 'abiquifi_sso_required', 'Preencha os campos obrigatorios.', array( 'status' => 400 ) );
		}

		if ( ! is_email( $email ) ) {
			return new WP_Error( 'abiquifi_sso_invalid_email', 'E-mail invalido.', array( 'status' => 400 ) );
		}

		if ( $password !== $password_repeat ) {
			return new WP_Error( 'abiquifi_sso_password_mismatch', 'As senhas nao coincidem.', array( 'status' => 400 ) );
		}

		if ( strlen( $password ) < 8 ) {
			return new WP_Error( 'abiquifi_sso_password_short', 'A senha precisa ter ao menos 8 caracteres.', array( 'status' => 400 ) );
		}

		if ( '' !== $first_name || '' !== $last_name ) {
			if ( '' === $first_name || '' === $last_name ) {
				return new WP_Error( 'abiquifi_sso_required', 'Preencha nome e sobrenome.', array( 'status' => 400 ) );
			}
		}

		if ( ! empty( $profile ) ) {
			if ( empty( $profile['institution_name'] ) || empty( $profile['phone'] ) || empty( $profile['activity_sector'] ) || empty( $profile['department'] ) || empty( $profile['job_title'] ) ) {
				return new WP_Error( 'abiquifi_sso_required', 'Preencha os campos obrigatorios.', array( 'status' => 400 ) );
			}

			if ( ! $this->is_valid_phone( $profile['phone'] ) ) {
				return new WP_Error( 'abiquifi_sso_invalid_phone', 'Telefone invalido.', array( 'status' => 400 ) );
			}

			if ( ! in_array( $profile['activity_sector'], $this->dictionary_activity_options(), true ) || ! in_array( $profile['department'], $this->dictionary_department_options(), true ) || ! in_array( $profile['job_title'], $this->dictionary_job_title_options(), true ) ) {
				return new WP_Error( 'abiquifi_sso_invalid_choice', 'Opcao invalida.', array( 'status' => 400 ) );
			}

			if ( empty( $profile['privacy_accept'] ) ) {
				return new WP_Error( 'abiquifi_sso_privacy_required', 'Aceite da politica de privacidade obrigatorio.', array( 'status' => 400 ) );
			}
		}

		$user_id = $this->create_public_user_account(
			array(
				'name'         => $display_name,
				'email'        => $email,
				'password'     => $password,
				'first_name'   => $first_name,
				'last_name'    => $last_name,
				'display_name' => $display_name,
			)
		);

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		$this->seed_user_meta(
			$user_id,
			array(
				'display_name'     => $display_name,
				'user_email'       => $email,
				'first_name'       => $first_name,
				'last_name'        => $last_name,
				'institution_name' => empty( $profile['institution_name'] ) ? '' : $profile['institution_name'],
				'phone'            => empty( $profile['phone'] ) ? '' : $profile['phone'],
				'activity_sector'  => empty( $profile['activity_sector'] ) ? '' : $profile['activity_sector'],
				'department'       => empty( $profile['department'] ) ? '' : $profile['department'],
				'job_title'        => empty( $profile['job_title'] ) ? '' : $profile['job_title'],
				'privacy_accept'   => empty( $profile['privacy_accept'] ) ? false : true,
			)
		);

		$user = get_user_by( 'id', $user_id );
		if ( $user instanceof WP_User ) {
			$this->send_registration_confirmation_email( $user );
		}

		return $this->build_session_payload( $user, $remember );
	}

	protected function create_public_user_account( $args ) {
		$name         = isset( $args['name'] ) ? trim( (string) $args['name'] ) : '';
		$email        = isset( $args['email'] ) ? sanitize_email( (string) $args['email'] ) : '';
		$password     = isset( $args['password'] ) ? (string) $args['password'] : '';
		$first_name   = isset( $args['first_name'] ) ? trim( (string) $args['first_name'] ) : '';
		$last_name    = isset( $args['last_name'] ) ? trim( (string) $args['last_name'] ) : '';
		$display_name = isset( $args['display_name'] ) ? trim( (string) $args['display_name'] ) : $name;

		$existing_user = get_user_by( 'email', $email );
		if ( $existing_user instanceof WP_User ) {
			return new WP_Error( 'abiquifi_sso_email_exists', 'Ja existe uma conta com este e-mail.', array( 'status' => 409 ) );
		}

		for ( $attempt = 0; $attempt < 5; $attempt++ ) {
			$username = 0 === $attempt ? $this->generate_username_from_email( $email ) : $this->generate_username_from_email( $email . '+' . $attempt );
			$user_id  = wp_insert_user(
				array(
					'user_login'   => $username,
					'user_email'   => $email,
					'user_pass'    => $password,
					'display_name' => $display_name,
					'first_name'   => $first_name,
					'last_name'    => $last_name,
					'role'         => 'subscriber',
				)
			);

			if ( ! is_wp_error( $user_id ) ) {
				return $user_id;
			}

			$error_codes = $user_id->get_error_codes();
			if ( in_array( 'existing_user_email', $error_codes, true ) ) {
				return new WP_Error( 'abiquifi_sso_email_exists', 'Ja existe uma conta com este e-mail.', array( 'status' => 409 ) );
			}

			if ( ! in_array( 'existing_user_login', $error_codes, true ) ) {
				return new WP_Error( 'abiquifi_sso_registration_failed', 'Nao foi possivel criar a conta.', array( 'status' => 500 ) );
			}
		}

		return new WP_Error( 'abiquifi_sso_registration_failed', 'Nao foi possivel criar a conta.', array( 'status' => 500 ) );
	}

	protected function build_session_payload( $user, $remember ) {
		$session = $this->create_public_session( $user->ID, $remember );

		return array(
			'success'    => true,
			'token'      => $session['token'],
			'expires_at' => $session['expires_at'],
			'user'       => $this->normalize_user( $user ),
		);
	}

	protected function maybe_create_session_table() {
		global $wpdb;

		if ( ! $this->is_authority_site() ) {
			return;
		}

		$table_name      = $this->session_table_name();
		$charset_collate = $wpdb->get_charset_collate();
		$sql             = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			session_id varchar(64) NOT NULL,
			user_id bigint(20) unsigned NOT NULL,
			expires_at datetime NOT NULL,
			revoked_at datetime NULL DEFAULT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY session_id (session_id),
			KEY user_id (user_id),
			KEY expires_at (expires_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	protected function session_table_name() {
		global $wpdb;

		return $wpdb->prefix . 'abiquifi_public_sessions';
	}

	protected function create_public_session( $user_id, $remember ) {
		global $wpdb;

		$token      = wp_generate_password( 48, false, false ) . wp_generate_password( 16, false, false );
		$expires_at = time() + self::SESSION_TTL;
		$now        = current_time( 'mysql', true );

		$wpdb->insert(
			$this->session_table_name(),
			array(
				'session_id' => wp_hash( $token ),
				'user_id'    => (int) $user_id,
				'expires_at' => gmdate( 'Y-m-d H:i:s', $expires_at ),
				'created_at' => $now,
				'updated_at' => $now,
			),
			array( '%s', '%d', '%s', '%s', '%s' )
		);

		return array(
			'token'      => $token,
			'expires_at' => $expires_at,
		);
	}

	protected function resolve_authority_session( $token ) {
		global $wpdb;

		if ( '' === $token ) {
			return null;
		}

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$this->session_table_name()} WHERE session_id = %s LIMIT 1",
				wp_hash( $token )
			),
			ARRAY_A
		);

		if ( empty( $row ) ) {
			return null;
		}

		if ( ! empty( $row['revoked_at'] ) ) {
			return null;
		}

		if ( strtotime( $row['expires_at'] ) < time() ) {
			return null;
		}

		$user = get_user_by( 'id', (int) $row['user_id'] );
		if ( ! $user ) {
			return null;
		}

		return array(
			'token'      => $token,
			'expires_at' => strtotime( $row['expires_at'] ),
			'user'       => $this->normalize_user( $user ),
		);
	}

	protected function revoke_session_token( $token ) {
		global $wpdb;

		if ( '' === $token ) {
			return;
		}

		$wpdb->update(
			$this->session_table_name(),
			array(
				'revoked_at' => current_time( 'mysql', true ),
				'updated_at' => current_time( 'mysql', true ),
			),
			array(
				'session_id' => wp_hash( $token ),
			),
			array( '%s', '%s' ),
			array( '%s' )
		);
	}

	protected function normalize_user( $user ) {
		if ( is_array( $user ) ) {
			return $user;
		}

		return array(
			'ID'           => (int) $user->ID,
			'user_login'   => (string) $user->user_login,
			'user_email'   => (string) $user->user_email,
			'user_pass'    => (string) $user->user_pass,
			'display_name' => (string) $user->display_name,
			'first_name'   => (string) get_user_meta( $user->ID, 'first_name', true ),
			'last_name'    => (string) get_user_meta( $user->ID, 'last_name', true ),
			'institution_name' => (string) get_user_meta( $user->ID, 'dsf_institution_name', true ),
			'phone'        => (string) get_user_meta( $user->ID, 'dsf_phone', true ),
			'activity_sector' => (string) get_user_meta( $user->ID, 'dsf_activity_sector', true ),
			'department'   => (string) get_user_meta( $user->ID, 'dsf_department', true ),
			'job_title'    => (string) get_user_meta( $user->ID, 'dsf_job_title', true ),
			'roles'        => array_values( (array) $user->roles ),
		);
	}

	public function get_public_user() {
		if ( ! empty( $this->resolved_user ) ) {
			return $this->resolved_user;
		}

		return null;
	}

	public function is_public_authenticated() {
		return (bool) $this->get_public_user();
	}

	protected function maybe_logout_stale_local_public_session() {
		if ( is_admin() || ! is_user_logged_in() ) {
			return;
		}

		$user = wp_get_current_user();
		if ( $user instanceof WP_User && $user->exists() && ! user_can( $user, 'edit_posts' ) ) {
			wp_logout();
		}
	}

	public function require_public_authentication( $redirect_url ) {
		if ( $this->is_public_authenticated() ) {
			return;
		}

		wp_safe_redirect( $this->public_login_url( $redirect_url ) );
		exit;
	}

	public function public_logout_url( $redirect_to ) {
		return $this->public_frontend_url( 'sair', $redirect_to );
	}

	public function public_account_url() {
		return $this->is_authority_site() ? home_url( '/account/' ) : 'https://dicionario.abiquifi.questione.ai/account/';
	}

	public function public_login_url( $redirect_to = '' ) {
		return $this->public_frontend_url( 'log-in', $redirect_to );
	}

	public function public_register_url( $redirect_to = '' ) {
		return $this->public_frontend_url( 'cadastro', $redirect_to );
	}

	public function public_forgot_password_url( $redirect_to = '' ) {
		return $this->public_frontend_url( 'esqueceu-sua-senha', $redirect_to );
	}

	public function public_reset_password_url( $login = '', $key = '', $redirect_to = '' ) {
		$url = $this->public_frontend_url( 'redefinir-senha', $redirect_to );

		$args = array();
		if ( '' !== $login ) {
			$args['login'] = $login;
		}

		if ( '' !== $key ) {
			$args['key'] = $key;
		}

		if ( ! empty( $args ) ) {
			$url = add_query_arg( $args, $url );
		}

		return $url;
	}

	public function remote_login( $login, $password, $remember ) {
		return $this->request_authority(
			'/login',
			array(
				'method' => 'POST',
				'body'   => array(
					'login'    => $login,
					'password' => $password,
					'remember' => $remember ? '1' : '0',
				),
			)
		);
	}

	public function remote_register( $name, $email, $password, $password_repeat, $profile = array() ) {
		return $this->request_authority(
			'/register',
			array(
				'method' => 'POST',
				'body'   => array_merge(
					array(
						'name'            => $name,
						'email'           => $email,
						'password'        => $password,
						'password_repeat' => $password_repeat,
					),
					(array) $profile
				),
			)
		);
	}

	public function remote_logout( $token ) {
		return $this->request_authority(
			'/logout',
			array(
				'method' => 'POST',
				'body'   => array(
					'token' => $token,
				),
			)
		);
	}

	protected function fetch_remote_session( $token ) {
		return $this->request_authority(
			'/session',
			array(
				'method' => 'GET',
				'query'  => array(
					'token' => $token,
				),
			)
		);
	}

	protected function request_authority( $path, $args ) {
		$url    = trailingslashit( $this->authority_url() ) . 'wp-json/abiquifi-sso/v1' . $path;
		$query  = isset( $args['query'] ) ? (array) $args['query'] : array();
		$method = isset( $args['method'] ) ? strtoupper( $args['method'] ) : 'GET';
		$body   = isset( $args['body'] ) ? (array) $args['body'] : array();

		if ( ! empty( $query ) ) {
			$url = add_query_arg( $query, $url );
		}

		$response = wp_remote_request(
			$url,
			array(
				'method'      => $method,
				'timeout'     => 20,
				'redirection' => 2,
				'body'        => $body,
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'_transport_error' => $response->get_error_message(),
			);
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			$data = array();
		}

		$data['_http_status'] = $code;
		return $data;
	}

	public function maybe_ensure_public_auth_pages() {
		if ( ! $this->is_authority_site() ) {
			return;
		}

		if ( get_option( self::OPTION_PUBLIC_AUTH_PAGES ) ) {
			return;
		}

		$forgot_page = $this->ensure_public_auth_page( 'esqueceu-sua-senha', 'Esqueceu sua senha?' );
		$reset_page  = $this->ensure_public_auth_page( 'redefinir-senha', 'Redefinir senha' );

		if ( $forgot_page > 0 && $reset_page > 0 ) {
			update_option( self::OPTION_PUBLIC_AUTH_PAGES, current_time( 'mysql' ), false );
		}
	}

	public function maybe_run_migration() {
		if ( ! $this->is_fabricamos_site() ) {
			return;
		}

		if ( get_option( self::OPTION_MIGRATION ) ) {
			return;
		}

		$this->push_local_public_users_to_authority();
		$this->pull_authority_public_users_to_local();
		update_option( self::OPTION_MIGRATION, current_time( 'mysql' ), false );
	}

	protected function ensure_public_auth_page( $slug, $title ) {
		$page = get_page_by_path( $slug, OBJECT, 'page' );
		if ( $page instanceof WP_Post ) {
			return (int) $page->ID;
		}

		$page_id = wp_insert_post(
			array(
				'post_title'   => $title,
				'post_name'    => $slug,
				'post_type'    => 'page',
				'post_status'  => 'publish',
				'post_content' => '',
			),
			true
		);

		return is_wp_error( $page_id ) ? 0 : (int) $page_id;
	}

	protected function push_local_public_users_to_authority() {
		$users = $this->export_public_users();
		foreach ( $users as $user ) {
			$this->request_authority(
				'/sync-user',
				array(
					'method' => 'POST',
					'body'   => array(
						'secret' => $this->internal_secret(),
						'user'   => $user,
					),
				)
			);
		}
	}

	protected function pull_authority_public_users_to_local() {
		$response = $this->request_authority(
			'/sync-user',
			array(
				'method' => 'POST',
				'body'   => array(
					'secret' => $this->internal_secret(),
					'mode'   => 'export',
				),
			)
		);

		if ( empty( $response['users'] ) || ! is_array( $response['users'] ) ) {
			return;
		}

		foreach ( $response['users'] as $user ) {
			$this->ensure_local_wordpress_user( $user );
		}
	}

	protected function export_public_users() {
		$users   = get_users(
			array(
				'number'  => 500,
				'orderby' => 'ID',
				'order'   => 'ASC',
			)
		);
		$payload = array();

		foreach ( $users as $user ) {
			if ( in_array( 'fabricante', (array) $user->roles, true ) ) {
				continue;
			}

			$payload[] = $this->normalize_user( $user );
		}

		return $payload;
	}

	public function ensure_local_wordpress_user( $user_data ) {
		global $wpdb;

		if ( empty( $user_data['user_email'] ) ) {
			return 0;
		}

		$email = sanitize_email( $user_data['user_email'] );
		$user  = get_user_by( 'email', $email );

		if ( $user ) {
			wp_update_user(
				array(
					'ID'           => (int) $user->ID,
					'user_login'   => empty( $user_data['user_login'] ) ? $user->user_login : $user_data['user_login'],
					'user_email'   => $email,
					'display_name' => empty( $user_data['display_name'] ) ? $user->display_name : $user_data['display_name'],
					'first_name'   => empty( $user_data['first_name'] ) ? '' : $user_data['first_name'],
					'last_name'    => empty( $user_data['last_name'] ) ? '' : $user_data['last_name'],
				)
			);

			if ( ! empty( $user_data['user_pass'] ) ) {
				$wpdb->update(
					$wpdb->users,
					array( 'user_pass' => $user_data['user_pass'] ),
					array( 'ID' => (int) $user->ID ),
					array( '%s' ),
					array( '%d' )
				);
				clean_user_cache( (int) $user->ID );
			}

			$this->sync_user_roles( (int) $user->ID, $user_data );
			$this->seed_user_meta( (int) $user->ID, $user_data );

			return (int) $user->ID;
		}

		$desired_id = empty( $user_data['ID'] ) ? 0 : (int) $user_data['ID'];
		if ( $desired_id > 0 && ! get_user_by( 'id', $desired_id ) ) {
			$inserted = $wpdb->insert(
				$wpdb->users,
				array(
					'ID'               => $desired_id,
					'user_login'       => empty( $user_data['user_login'] ) ? $this->generate_username_from_email( $email ) : $user_data['user_login'],
					'user_pass'        => empty( $user_data['user_pass'] ) ? wp_hash_password( wp_generate_password( 24, true, true ) ) : $user_data['user_pass'],
					'user_nicename'    => sanitize_title( empty( $user_data['display_name'] ) ? $email : $user_data['display_name'] ),
					'user_email'       => $email,
					'user_url'         => '',
					'user_registered'  => current_time( 'mysql' ),
					'user_status'      => 0,
					'display_name'     => empty( $user_data['display_name'] ) ? $email : $user_data['display_name'],
				),
				array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
			);

			if ( $inserted ) {
				$this->seed_user_meta( $desired_id, $user_data );
				$this->sync_user_roles( $desired_id, $user_data );
				clean_user_cache( $desired_id );
				return $desired_id;
			}
		}

		$user_id = wp_insert_user(
			array(
				'user_login'   => empty( $user_data['user_login'] ) ? $this->generate_username_from_email( $email ) : $user_data['user_login'],
				'user_email'   => $email,
				'user_pass'    => empty( $user_data['user_pass'] ) ? wp_generate_password( 24, true, true ) : $user_data['user_pass'],
				'display_name' => empty( $user_data['display_name'] ) ? $email : $user_data['display_name'],
				'first_name'   => empty( $user_data['first_name'] ) ? '' : $user_data['first_name'],
				'last_name'    => empty( $user_data['last_name'] ) ? '' : $user_data['last_name'],
				'role'         => ! empty( $user_data['roles'][0] ) ? $user_data['roles'][0] : 'subscriber',
			)
		);

		if ( is_wp_error( $user_id ) ) {
			return 0;
		}

		if ( ! empty( $user_data['user_pass'] ) ) {
			$wpdb->update(
				$wpdb->users,
				array( 'user_pass' => $user_data['user_pass'] ),
				array( 'ID' => (int) $user_id ),
				array( '%s' ),
				array( '%d' )
			);
		}

		$this->seed_user_meta( (int) $user_id, $user_data );
		$this->sync_user_roles( (int) $user_id, $user_data );
		clean_user_cache( (int) $user_id );

		return (int) $user_id;
	}

	protected function seed_user_meta( $user_id, $user_data ) {
		update_user_meta( $user_id, 'nickname', empty( $user_data['display_name'] ) ? $user_data['user_email'] : $user_data['display_name'] );
		update_user_meta( $user_id, 'first_name', empty( $user_data['first_name'] ) ? '' : $user_data['first_name'] );
		update_user_meta( $user_id, 'last_name', empty( $user_data['last_name'] ) ? '' : $user_data['last_name'] );
		if ( isset( $user_data['institution_name'] ) ) {
			update_user_meta( $user_id, 'dsf_institution_name', (string) $user_data['institution_name'] );
		}
		if ( isset( $user_data['phone'] ) ) {
			update_user_meta( $user_id, 'dsf_phone', (string) $user_data['phone'] );
		}
		if ( isset( $user_data['activity_sector'] ) ) {
			update_user_meta( $user_id, 'dsf_activity_sector', (string) $user_data['activity_sector'] );
		}
		if ( isset( $user_data['department'] ) ) {
			update_user_meta( $user_id, 'dsf_department', (string) $user_data['department'] );
		}
		if ( isset( $user_data['job_title'] ) ) {
			update_user_meta( $user_id, 'dsf_job_title', (string) $user_data['job_title'] );
		}
		if ( ! empty( $user_data['privacy_accept'] ) ) {
			update_user_meta( $user_id, 'dsf_privacy_accepted_at', current_time( 'mysql' ) );
			update_user_meta( $user_id, 'dsf_privacy_policy_url', $this->privacy_policy_url() );
		}
		update_user_meta( $user_id, self::META_SOURCE, $this->site_role() );
	}

	protected function sync_user_roles( $user_id, $user_data ) {
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return;
		}

		$roles = empty( $user_data['roles'] ) ? array( 'subscriber' ) : array_values( array_unique( (array) $user_data['roles'] ) );

		if ( in_array( 'fabricante', $roles, true ) ) {
			return;
		}

		foreach ( $user->roles as $role ) {
			$user->remove_role( $role );
		}

		foreach ( $roles as $role ) {
			if ( get_role( $role ) ) {
				$user->add_role( $role );
			}
		}

		if ( empty( $user->roles ) ) {
			$user->set_role( 'subscriber' );
		}
	}

	protected function login_local_user( $user_id ) {
		$this->local_auth_cookie_expiration = self::SESSION_TTL;
		wp_set_current_user( $user_id );
		wp_set_auth_cookie( $user_id, true, is_ssl() );
		do_action( 'wp_login', get_userdata( $user_id )->user_login, get_userdata( $user_id ) );
		$this->local_auth_cookie_expiration = 0;
	}

	public function filter_auth_cookie_expiration( $length, $user_id, $remember ) {
		if ( $this->local_auth_cookie_expiration > 0 ) {
			return $this->local_auth_cookie_expiration;
		}

		return $length;
	}

	public function set_public_session_from_response( $response ) {
		if ( empty( $response['token'] ) || empty( $response['user'] ) ) {
			return false;
		}

		$this->set_public_cookie( $response['token'], empty( $response['expires_at'] ) ? time() + self::SESSION_TTL : (int) $response['expires_at'] );
		$this->resolved_user    = $response['user'];
		$this->resolved_session = $response;
		$this->resolved_token   = $response['token'];

		if ( ! $this->should_bootstrap_wordpress_user() ) {
			return true;
		}

		$user_id = $this->ensure_local_wordpress_user( $response['user'] );

		if ( $user_id ) {
			$this->login_local_user( $user_id );
			return true;
		}

		return false;
	}

	public function set_public_cookie( $token, $expires_at ) {
		$params = array(
			'expires'  => (int) $expires_at,
			'path'     => '/',
			'domain'   => self::COOKIE_DOMAIN,
			'secure'   => true,
			'httponly' => true,
			'samesite' => 'Lax',
		);

		if ( PHP_VERSION_ID >= 70300 ) {
			setcookie( self::COOKIE_NAME, $token, $params );
		} else {
			setcookie( self::COOKIE_NAME, $token, (int) $expires_at, '/; samesite=Lax', self::COOKIE_DOMAIN, true, true );
		}

		$_COOKIE[ self::COOKIE_NAME ] = $token;
	}

	public function clear_public_cookie() {
		if ( PHP_VERSION_ID >= 70300 ) {
			setcookie(
				self::COOKIE_NAME,
				'',
				array(
					'expires'  => time() - HOUR_IN_SECONDS,
					'path'     => '/',
					'domain'   => self::COOKIE_DOMAIN,
					'secure'   => true,
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		} else {
			setcookie( self::COOKIE_NAME, '', time() - HOUR_IN_SECONDS, '/; samesite=Lax', self::COOKIE_DOMAIN, true, true );
		}

		unset( $_COOKIE[ self::COOKIE_NAME ] );
	}

	protected function read_cookie_token() {
		return isset( $_COOKIE[ self::COOKIE_NAME ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_NAME ] ) ) : '';
	}

	protected function ensure_secret() {
		if ( ! get_option( self::OPTION_SECRET ) ) {
			update_option( self::OPTION_SECRET, $this->internal_secret(), false );
		}
	}

	protected function internal_secret() {
		$secret = get_option( self::OPTION_SECRET );
		if ( ! empty( $secret ) ) {
			return (string) $secret;
		}

		return self::INTERNAL_SECRET_FALLBACK;
	}

	protected function is_internal_secret_valid( $secret ) {
		return is_string( $secret ) && '' !== $secret && hash_equals( $this->internal_secret(), $secret );
	}

	public function authority_url() {
		$configured = esc_url_raw( (string) $this->read_env_value( 'ABIQUIFI_PUBLIC_SSO_AUTHORITY_URL', '' ) );
		if ( '' !== $configured ) {
			return trailingslashit( $configured );
		}

		if ( $this->is_authority_site() ) {
			return home_url( '/' );
		}

		return 'https://dicionario.abiquifi.questione.ai/';
	}

	public function fabricamos_url( $path = '' ) {
		$configured = esc_url_raw( (string) $this->read_env_value( 'ABIQUIFI_PUBLIC_SSO_FABRICAMOS_URL', '' ) );
		$base       = '' !== $configured
			? trailingslashit( $configured )
			: ( $this->is_fabricamos_site() ? home_url( '/' ) : 'https://fabricamos.abiquifi.questione.ai/' );

		if ( '' === $path ) {
			return $base;
		}

		return trailingslashit( $base ) . trim( $path, '/' ) . '/';
	}

	public function is_authority_site() {
		if ( 'authority' === $this->configured_site_role() ) {
			return true;
		}

		$host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		return is_string( $host ) && false !== strpos( $host, 'dicionario.' );
	}

	public function is_fabricamos_site() {
		if ( 'fabricamos' === $this->configured_site_role() ) {
			return true;
		}

		$host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		return is_string( $host ) && false !== strpos( $host, 'fabricamos.' );
	}

	public function is_main_site() {
		if ( 'main' === $this->configured_site_role() ) {
			return true;
		}

		$host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		return 'abiquifi.questione.ai' === $host;
	}

	protected function site_role() {
		if ( $this->is_authority_site() ) {
			return 'dictionary';
		}

		if ( $this->is_fabricamos_site() ) {
			return 'fabricamos';
		}

		return 'site';
	}

	protected function generate_username_from_email( $email ) {
		$base     = sanitize_user( current( explode( '@', $email ) ), true );
		$base     = '' === $base ? 'usuario' : $base;
		$username = $base;
		$index    = 1;

		while ( username_exists( $username ) ) {
			$username = $base . $index;
			$index++;
		}

		return $username;
	}

	protected function read_env_value( $key, $default = '' ) {
		$key = (string) $key;

		if ( '' === $key ) {
			return $default;
		}

		$value = getenv( $key );
		if ( false !== $value && '' !== trim( (string) $value ) ) {
			return trim( (string) $value );
		}

		if ( isset( $_ENV[ $key ] ) && '' !== trim( (string) $_ENV[ $key ] ) ) {
			return trim( (string) $_ENV[ $key ] );
		}

		if ( isset( $_SERVER[ $key ] ) && '' !== trim( (string) $_SERVER[ $key ] ) ) {
			return trim( (string) $_SERVER[ $key ] );
		}

		if ( defined( $key ) ) {
			$value = constant( $key );
			if ( is_scalar( $value ) && '' !== trim( (string) $value ) ) {
				return trim( (string) $value );
			}
		}

		return $default;
	}

	protected function configured_site_role() {
		$role = strtolower( (string) $this->read_env_value( 'ABIQUIFI_PUBLIC_SSO_SITE_ROLE', '' ) );

		return in_array( $role, array( 'authority', 'fabricamos', 'main' ), true ) ? $role : '';
	}

	protected function mail_from_email() {
		$sender = sanitize_email( $this->read_env_value( 'ABIQUIFI_MAIL_FROM_EMAIL', 'marketing@abiquifi.org.br' ) );

		if ( '' === $sender || ! is_email( $sender ) ) {
			$sender = sanitize_email( (string) get_option( 'admin_email', 'marketing@abiquifi.org.br' ) );
		}

		if ( '' === $sender || ! is_email( $sender ) ) {
			$sender = 'marketing@abiquifi.org.br';
		}

		return $sender;
	}

	protected function mail_from_name() {
		return $this->read_env_value( 'ABIQUIFI_MAIL_FROM_NAME', 'Fabricamos | Abiquifi' );
	}

	protected function send_registration_confirmation_email( $user ) {
		if ( ! $user instanceof WP_User || ! $user->exists() ) {
			return false;
		}

		$to = sanitize_email( (string) $user->user_email );
		if ( '' === $to || ! is_email( $to ) ) {
			return false;
		}

		$name           = $user->display_name ? $user->display_name : $user->user_login;
		$login_url      = $this->fabricamos_url( 'login' );
		$dictionary_url = trailingslashit( $this->authority_url() );
		$subject        = 'Cadastro confirmado | Fabricamos';
		$headers        = array(
			'Content-Type: text/html; charset=UTF-8',
			'From: ' . $this->mail_from_name() . ' <' . $this->mail_from_email() . '>',
		);
		$message        = sprintf(
			'<html><body style="margin:0;padding:0;background:#f4f7fb;font-family:Arial,sans-serif;color:#162b40;">' .
			'<div style="max-width:640px;margin:0 auto;padding:32px 20px;">' .
			'<div style="background:#ffffff;border-radius:16px;padding:32px;border:1px solid #d9e2ec;">' .
			'<p style="margin:0 0 16px;font-size:14px;letter-spacing:.08em;text-transform:uppercase;color:#6c8195;">Abiquifi</p>' .
			'<h1 style="margin:0 0 20px;font-size:28px;line-height:1.2;color:#0d2236;">Cadastro confirmado</h1>' .
			'<p style="margin:0 0 16px;font-size:16px;line-height:1.6;">Ola %1$s, seu cadastro foi concluido com sucesso.</p>' .
			'<p style="margin:0 0 16px;font-size:16px;line-height:1.6;">Ja e possivel acessar o Fabricamos e os ambientes conectados da Abiquifi usando o e-mail <strong>%2$s</strong>.</p>' .
			'<p style="margin:0 0 24px;font-size:16px;line-height:1.6;">Se voce nao reconhece este cadastro, basta ignorar este e-mail.</p>' .
			'<p style="margin:0 0 12px;"><a href="%3$s" style="display:inline-block;background:#0d2236;color:#ffffff;text-decoration:none;padding:14px 20px;border-radius:999px;font-weight:700;">Entrar no Fabricamos</a></p>' .
			'<p style="margin:0 0 24px;"><a href="%4$s" style="display:inline-block;color:#0d2236;text-decoration:underline;">Abrir o Dicionario</a></p>' .
			'<p style="margin:0;font-size:13px;line-height:1.6;color:#6c8195;">Mensagem automatica enviada por %5$s.</p>' .
			'</div></div></body></html>',
			esc_html( $name ),
			esc_html( $to ),
			esc_url( $login_url ),
			esc_url( $dictionary_url ),
			esc_html( $this->mail_from_name() )
		);

		return (bool) wp_mail( $to, $subject, $message, $headers );
	}

	protected function public_frontend_url( $path, $redirect_to = '' ) {
		$url = trailingslashit( $this->authority_url() ) . trim( $path, '/' ) . '/';

		if ( '' !== $redirect_to ) {
			$url = add_query_arg( 'redirect_to', $redirect_to, $url );
		}

		return $url;
	}

	protected function request_path_matches( $path ) {
		$request_path = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) : '';
		$target_path  = wp_parse_url( home_url( '/' . trim( $path, '/' ) . '/' ), PHP_URL_PATH );

		return untrailingslashit( (string) $request_path ) === untrailingslashit( (string) $target_path );
	}

	protected function to_bool( $value ) {
		if ( is_bool( $value ) ) {
			return $value;
		}

		$value = strtolower( trim( (string) $value ) );
		return in_array( $value, array( '1', 'true', 'yes', 'on', 'forever' ), true );
	}
}
