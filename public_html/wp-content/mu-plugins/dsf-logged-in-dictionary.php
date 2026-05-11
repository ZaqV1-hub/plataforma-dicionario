<?php
/**
 * Full dictionary view with gated access modal for DSF page.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action( 'init', 'dsf_dictionary_bootstrap_guest_access', 5 );
add_action( 'admin_post_nopriv_dsf_dictionary_guest_access', 'dsf_dictionary_handle_guest_access_form' );
add_action( 'admin_post_dsf_dictionary_guest_access', 'dsf_dictionary_handle_guest_access_form' );
add_filter( 'posts_where', 'dsf_dictionary_posts_where', 10, 2 );
add_filter( 'the_content', 'dsf_dictionary_replace_content_for_dsf_page', 999 );

function dsf_dictionary_bootstrap_guest_access() {
	dsf_dictionary_maybe_create_guest_access_table();

	if ( 0 === wp_rand( 0, 25 ) ) {
		dsf_dictionary_prune_expired_guest_access();
	}
}

function dsf_dictionary_guest_cookie_name() {
	return 'dsf_dictionary_guest_access';
}

function dsf_dictionary_shared_guest_cookie_name() {
	return 'abiquifi_guest_access_until';
}

function dsf_dictionary_shared_guest_cookie_domain() {
	return '.abiquifi.questione.ai';
}

function dsf_dictionary_guest_ttl() {
	return DAY_IN_SECONDS;
}

function dsf_dictionary_guest_access_table_name() {
	global $wpdb;

	return $wpdb->prefix . 'dsf_dictionary_guest_access';
}

function dsf_dictionary_job_title_options() {
	return array(
		'Diretor',
		'Vice-diretor',
		'Presidente',
		'Vice-presidente',
		'Gerente',
		'Outros',
	);
}

function dsf_dictionary_guest_access_error_message( $error_code ) {
	switch ( $error_code ) {
		case 'nonce':
			return 'Não foi possível validar o formulário. Tente novamente.';
		case 'required':
			return 'Preencha todos os campos obrigatórios.';
		case 'email':
			return 'Informe um e-mail válido.';
		case 'phone':
			return 'Informe um telefone válido.';
		case 'job_title':
			return 'Selecione um cargo válido.';
		default:
			return '';
	}
}

function dsf_dictionary_maybe_create_guest_access_table() {
	if ( get_option( 'dsf_dictionary_guest_access_table_v1' ) ) {
		return;
	}

	global $wpdb;

	$table_name      = dsf_dictionary_guest_access_table_name();
	$charset_collate = $wpdb->get_charset_collate();
	$sql             = "CREATE TABLE {$table_name} (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		session_id varchar(64) NOT NULL,
		full_name varchar(191) NOT NULL,
		phone varchar(60) NOT NULL,
		email varchar(191) NOT NULL,
		company varchar(191) NOT NULL,
		job_title varchar(100) NOT NULL,
		expires_at datetime NOT NULL,
		created_at datetime NOT NULL,
		updated_at datetime NOT NULL,
		PRIMARY KEY  (id),
		UNIQUE KEY session_id (session_id),
		KEY email (email),
		KEY expires_at (expires_at)
	) {$charset_collate};";

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	dbDelta( $sql );

	update_option( 'dsf_dictionary_guest_access_table_v1', 1, false );
}

function dsf_dictionary_prune_expired_guest_access() {
	global $wpdb;

	$wpdb->query(
		$wpdb->prepare(
			'DELETE FROM ' . dsf_dictionary_guest_access_table_name() . ' WHERE expires_at < %s',
			gmdate( 'Y-m-d H:i:s' )
		)
	);
}

function dsf_dictionary_set_guest_cookie( $token, $expires_at ) {
	$params = array(
		'expires'  => (int) $expires_at,
		'path'     => '/',
		'secure'   => is_ssl(),
		'httponly' => true,
		'samesite' => 'Lax',
	);

	if ( PHP_VERSION_ID >= 70300 ) {
		setcookie( dsf_dictionary_guest_cookie_name(), $token, $params );
	} else {
		setcookie( dsf_dictionary_guest_cookie_name(), $token, (int) $expires_at, '/; samesite=Lax', '', is_ssl(), true );
	}

	$_COOKIE[ dsf_dictionary_guest_cookie_name() ] = $token;
}

function dsf_dictionary_set_shared_guest_cookie( $expires_at ) {
	$params = array(
		'expires'  => (int) $expires_at,
		'path'     => '/',
		'domain'   => dsf_dictionary_shared_guest_cookie_domain(),
		'secure'   => is_ssl(),
		'httponly' => false,
		'samesite' => 'Lax',
	);

	if ( PHP_VERSION_ID >= 70300 ) {
		setcookie( dsf_dictionary_shared_guest_cookie_name(), (string) (int) $expires_at, $params );
	} else {
		setcookie( dsf_dictionary_shared_guest_cookie_name(), (string) (int) $expires_at, (int) $expires_at, '/; samesite=Lax', dsf_dictionary_shared_guest_cookie_domain(), is_ssl(), false );
	}

	$_COOKIE[ dsf_dictionary_shared_guest_cookie_name() ] = (string) (int) $expires_at;
}

function dsf_dictionary_clear_guest_cookie() {
	if ( PHP_VERSION_ID >= 70300 ) {
		setcookie(
			dsf_dictionary_guest_cookie_name(),
			'',
			array(
				'expires'  => time() - HOUR_IN_SECONDS,
				'path'     => '/',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	} else {
		setcookie( dsf_dictionary_guest_cookie_name(), '', time() - HOUR_IN_SECONDS, '/; samesite=Lax', '', is_ssl(), true );
	}

	unset( $_COOKIE[ dsf_dictionary_guest_cookie_name() ] );
}

function dsf_dictionary_clear_shared_guest_cookie() {
	if ( PHP_VERSION_ID >= 70300 ) {
		setcookie(
			dsf_dictionary_shared_guest_cookie_name(),
			'',
			array(
				'expires'  => time() - HOUR_IN_SECONDS,
				'path'     => '/',
				'domain'   => dsf_dictionary_shared_guest_cookie_domain(),
				'secure'   => is_ssl(),
				'httponly' => false,
				'samesite' => 'Lax',
			)
		);
	} else {
		setcookie( dsf_dictionary_shared_guest_cookie_name(), '', time() - HOUR_IN_SECONDS, '/; samesite=Lax', dsf_dictionary_shared_guest_cookie_domain(), is_ssl(), false );
	}

	unset( $_COOKIE[ dsf_dictionary_shared_guest_cookie_name() ] );
}

function dsf_dictionary_has_shared_guest_access() {
	$expires_at = isset( $_COOKIE[ dsf_dictionary_shared_guest_cookie_name() ] )
		? (int) sanitize_text_field( wp_unslash( $_COOKIE[ dsf_dictionary_shared_guest_cookie_name() ] ) )
		: 0;

	if ( $expires_at <= time() ) {
		if ( $expires_at > 0 ) {
			dsf_dictionary_clear_shared_guest_cookie();
		}

		return false;
	}

	return true;
}

function dsf_dictionary_guest_access_entry() {
	global $wpdb;

	$token = isset( $_COOKIE[ dsf_dictionary_guest_cookie_name() ] )
		? sanitize_text_field( wp_unslash( $_COOKIE[ dsf_dictionary_guest_cookie_name() ] ) )
		: '';

	if ( '' === $token ) {
		return null;
	}

	$row = $wpdb->get_row(
		$wpdb->prepare(
			'SELECT * FROM ' . dsf_dictionary_guest_access_table_name() . ' WHERE session_id = %s LIMIT 1',
			wp_hash( $token )
		),
		ARRAY_A
	);

	if ( empty( $row ) || empty( $row['expires_at'] ) ) {
		dsf_dictionary_clear_guest_cookie();
		return null;
	}

	if ( strtotime( (string) $row['expires_at'] ) <= time() ) {
		dsf_dictionary_clear_guest_cookie();
		return null;
	}

	return $row;
}

function dsf_dictionary_has_authenticated_account_access() {
	if ( is_user_logged_in() ) {
		return true;
	}

	if ( class_exists( 'Abiquifi_Public_SSO' ) ) {
		return Abiquifi_Public_SSO::instance()->is_public_authenticated();
	}

	return false;
}

function dsf_dictionary_has_access() {
	if ( dsf_dictionary_has_authenticated_account_access() ) {
		return true;
	}

	if ( dsf_dictionary_has_shared_guest_access() ) {
		return true;
	}

	return null !== dsf_dictionary_guest_access_entry();
}

function dsf_dictionary_handle_guest_access_form() {
	$redirect_to = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : home_url( '/dicionario-dsf/' );
	if ( '' === $redirect_to ) {
		$redirect_to = home_url( '/dicionario-dsf/' );
	}

	if ( ! isset( $_POST['dsf_dictionary_guest_access_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['dsf_dictionary_guest_access_nonce'] ) ), 'dsf_dictionary_guest_access' ) ) {
		wp_safe_redirect( add_query_arg( 'dsf_access_error', 'nonce', $redirect_to ) );
		exit;
	}

	$name      = sanitize_text_field( isset( $_POST['dsf_name'] ) ? wp_unslash( $_POST['dsf_name'] ) : '' );
	$phone     = sanitize_text_field( isset( $_POST['dsf_phone'] ) ? wp_unslash( $_POST['dsf_phone'] ) : '' );
	$email     = sanitize_email( isset( $_POST['dsf_email'] ) ? wp_unslash( $_POST['dsf_email'] ) : '' );
	$company   = sanitize_text_field( isset( $_POST['dsf_company'] ) ? wp_unslash( $_POST['dsf_company'] ) : '' );
	$job_title = sanitize_text_field( isset( $_POST['dsf_job_title'] ) ? wp_unslash( $_POST['dsf_job_title'] ) : '' );

	if ( '' === $name || '' === $phone || '' === $email || '' === $company || '' === $job_title ) {
		wp_safe_redirect( add_query_arg( 'dsf_access_error', 'required', $redirect_to ) );
		exit;
	}

	if ( ! is_email( $email ) ) {
		wp_safe_redirect( add_query_arg( 'dsf_access_error', 'email', $redirect_to ) );
		exit;
	}

	if ( strlen( preg_replace( '/\D+/', '', $phone ) ) < 10 ) {
		wp_safe_redirect( add_query_arg( 'dsf_access_error', 'phone', $redirect_to ) );
		exit;
	}

	if ( ! in_array( $job_title, dsf_dictionary_job_title_options(), true ) ) {
		wp_safe_redirect( add_query_arg( 'dsf_access_error', 'job_title', $redirect_to ) );
		exit;
	}

	global $wpdb;

	$token      = wp_generate_password( 48, false, false ) . wp_generate_password( 16, false, false );
	$expires_at = time() + dsf_dictionary_guest_ttl();
	$now        = current_time( 'mysql', true );

	$wpdb->insert(
		dsf_dictionary_guest_access_table_name(),
		array(
			'session_id' => wp_hash( $token ),
			'full_name'  => $name,
			'phone'      => $phone,
			'email'      => $email,
			'company'    => $company,
			'job_title'  => $job_title,
			'expires_at' => gmdate( 'Y-m-d H:i:s', $expires_at ),
			'created_at' => $now,
			'updated_at' => $now,
		),
		array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
	);

	dsf_dictionary_set_guest_cookie( $token, $expires_at );
	dsf_dictionary_set_shared_guest_cookie( $expires_at );

	wp_safe_redirect( remove_query_arg( 'dsf_access_error', $redirect_to ) );
	exit;
}

/**
 * Restrict letter filter to A-Z.
 *
 * @param string $letter Raw input.
 * @return string
 */
function dsf_dictionary_normalize_letter( $letter ) {
	$letter = strtoupper( substr( sanitize_text_field( wp_unslash( (string) $letter ) ), 0, 1 ) );
	return preg_match( '/^[A-Z]$/', $letter ) ? $letter : '';
}

/**
 * Add title initial filter to DSF dictionary query.
 *
 * @param string   $where SQL WHERE.
 * @param WP_Query $query Query object.
 * @return string
 */
function dsf_dictionary_posts_where( $where, $query ) {
	global $wpdb;

	if ( ! $query->get( 'dsf_logged_dictionary' ) ) {
		return $where;
	}

	$letter = $query->get( 'dsf_logged_dictionary_letter' );
	if ( ! $letter ) {
		return $where;
	}

	$like   = $wpdb->esc_like( $letter ) . '%';
	$where .= $wpdb->prepare( " AND {$wpdb->posts}.post_title LIKE %s", $like );
	return $where;
}

/**
 * Build the full dictionary page with optional access overlay.
 *
 * @return string
 */
function dsf_dictionary_render_view() {
	$search_term = '';
	if ( isset( $_GET['dsf_q'] ) ) {
		$search_term = sanitize_text_field( wp_unslash( (string) $_GET['dsf_q'] ) );
	}

	$letter = '';
	if ( isset( $_GET['dsf_letter'] ) ) {
		$letter = dsf_dictionary_normalize_letter( $_GET['dsf_letter'] );
	}

	$page = 1;
	if ( isset( $_GET['dsf_page'] ) ) {
		$page = max( 1, absint( $_GET['dsf_page'] ) );
	}

	$query_args = array(
		'post_type'                    => 'post',
		'post_status'                  => 'publish',
		'orderby'                      => 'title',
		'order'                        => 'ASC',
		'posts_per_page'               => 40,
		'paged'                        => $page,
		'dsf_logged_dictionary'        => true,
		'dsf_logged_dictionary_letter' => $letter,
	);

	if ( '' !== $search_term ) {
		$query_args['s'] = $search_term;
	}

	$query = new WP_Query( $query_args );

	$current_url = get_permalink();
	if ( ! $current_url ) {
		$current_url = home_url( '/dicionario-dsf/' );
	}

	$has_access         = dsf_dictionary_has_access();
	$guest_access_entry = dsf_dictionary_guest_access_entry();
	$is_account_access  = dsf_dictionary_has_authenticated_account_access();
	$register_url       = add_query_arg( 'redirect_to', $current_url, home_url( '/cadastro/' ) );
	$login_url          = add_query_arg( 'redirect_to', $current_url, home_url( '/log-in/' ) );
	$form_error         = isset( $_GET['dsf_access_error'] ) ? sanitize_text_field( wp_unslash( $_GET['dsf_access_error'] ) ) : '';
	$form_error_message = dsf_dictionary_guest_access_error_message( $form_error );

	$alphabet_links = array();
	foreach ( range( 'A', 'Z' ) as $char ) {
		$url = add_query_arg(
			array(
				'dsf_letter' => $char,
				'dsf_q'      => $search_term,
			),
			$current_url
		);

		$class            = ( $letter === $char ) ? ' class="is-active"' : '';
		$alphabet_links[] = '<a' . $class . ' href="' . esc_url( $url ) . '">' . esc_html( $char ) . '</a>';
	}

	$clear_url = remove_query_arg( array( 'dsf_q', 'dsf_letter', 'dsf_page', 'dsf_access_error' ), $current_url );

	ob_start();
	?>
	<section class="dsf-full-dictionary<?php echo $has_access ? ' is-unlocked' : ' is-locked'; ?>">
		<style>
			.dsf-full-dictionary { position: relative; max-width: 1160px; margin: 0 auto; padding: 170px 20px 40px; }
			.dsf-full-dictionary__viewport { position: relative; z-index: 1; transition: filter .25s ease, transform .25s ease; }
			.dsf-full-dictionary.is-locked .dsf-full-dictionary__viewport { filter: blur(16px); transform: scale(.992); pointer-events: none; user-select: none; }
			.dsf-full-dictionary h2 { margin: 0 0 10px; font-size: 42px; line-height: 1.15; color: #112f66; }
			.dsf-full-dictionary p { margin: 0 0 18px; color: #3d4d68; font-size: 18px; }
			.dsf-full-dictionary .dsf-search { display: flex; gap: 10px; flex-wrap: wrap; margin: 14px 0 18px; }
			.dsf-full-dictionary .dsf-search input[type="search"] { flex: 1 1 420px; min-height: 50px; border: 1px solid #bac5d9; border-radius: 10px; padding: 10px 14px; font-size: 16px; }
			.dsf-full-dictionary .dsf-search button,
			.dsf-full-dictionary .dsf-search a { min-height: 50px; border-radius: 10px; padding: 12px 18px; border: 1px solid #1d4b9f; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; }
			.dsf-full-dictionary .dsf-search button { background: #1d4b9f; color: #fff; cursor: pointer; }
			.dsf-full-dictionary .dsf-search a { background: #fff; color: #1d4b9f; }
			.dsf-full-dictionary .dsf-alphabet { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 20px; }
			.dsf-full-dictionary .dsf-alphabet a { width: 34px; height: 34px; border: 1px solid #c2cde0; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; text-decoration: none; color: #173b7a; font-weight: 700; font-size: 14px; }
			.dsf-full-dictionary .dsf-alphabet a.is-active { background: #173b7a; border-color: #173b7a; color: #fff; }
			.dsf-full-dictionary .dsf-meta { margin: 0 0 16px; font-size: 14px; color: #5a6982; }
			.dsf-full-dictionary ul { list-style: none; margin: 0; padding: 0; border: 1px solid #d3dbe9; border-radius: 14px; overflow: hidden; }
			.dsf-full-dictionary li { margin: 0; border-bottom: 1px solid #e6ecf5; background: #fff; }
			.dsf-full-dictionary li:last-child { border-bottom: 0; }
			.dsf-full-dictionary li a { display: block; padding: 13px 16px; color: #173b7a; text-decoration: none; font-weight: 600; }
			.dsf-full-dictionary li a:hover { background: #f5f8ff; }
			.dsf-full-dictionary .dsf-empty { border: 1px solid #d3dbe9; border-radius: 12px; background: #fff; padding: 18px; color: #3d4d68; }
			.dsf-full-dictionary .dsf-pagination { margin-top: 16px; display: flex; flex-wrap: wrap; gap: 6px; }
			.dsf-full-dictionary .dsf-pagination .page-numbers { display: inline-flex; min-width: 34px; height: 34px; align-items: center; justify-content: center; padding: 0 10px; border-radius: 8px; border: 1px solid #c2cde0; text-decoration: none; color: #173b7a; }
			.dsf-full-dictionary .dsf-pagination .page-numbers.current { background: #173b7a; border-color: #173b7a; color: #fff; }
			.dsf-full-dictionary .dsf-access-pill { display: inline-flex; margin: 0 0 18px; padding: 9px 14px; border-radius: 999px; background: #edf3ff; color: #173b7a; font-size: 13px; font-weight: 700; }
			.dsf-full-dictionary .dsf-access-overlay { position: absolute; inset: 0; z-index: 3; display: flex; align-items: flex-start; justify-content: center; padding: 150px 20px 40px; background: rgba(238, 244, 255, 0.32); }
			.dsf-full-dictionary .dsf-access-modal { width: min(100%, 560px); padding: 28px; border-radius: 22px; background: rgba(255, 255, 255, 0.96); border: 1px solid rgba(184, 198, 225, 0.9); box-shadow: 0 24px 60px rgba(13, 42, 96, 0.18); backdrop-filter: blur(10px); }
			.dsf-full-dictionary .dsf-access-modal h3 { margin: 0 0 18px; color: #102e63; font-size: 28px; line-height: 1.2; }
			.dsf-full-dictionary .dsf-access-modal p { margin-bottom: 14px; font-size: 15px; color: #51627f; }
			.dsf-full-dictionary .dsf-access-alert { margin: 0 0 16px; padding: 12px 14px; border-radius: 12px; background: #fff2f2; color: #9a2531; font-size: 14px; font-weight: 600; }
			.dsf-full-dictionary .dsf-access-form { display: grid; gap: 14px; }
			.dsf-full-dictionary .dsf-access-field label { display: block; margin: 0 0 6px; color: #173b7a; font-size: 14px; font-weight: 700; }
			.dsf-full-dictionary .dsf-access-field input,
			.dsf-full-dictionary .dsf-access-field select { width: 100%; min-height: 48px; border: 1px solid #c7d3e6; border-radius: 12px; padding: 11px 14px; background: #fff; color: #173b7a; font-size: 15px; }
			.dsf-full-dictionary .dsf-access-submit { min-height: 50px; border: 0; border-radius: 12px; background: #173b7a; color: #fff; font-size: 15px; font-weight: 700; cursor: pointer; }
			.dsf-full-dictionary .dsf-access-links { margin-top: 6px; font-size: 14px; line-height: 1.5; }
			.dsf-full-dictionary .dsf-access-links a { color: #173b7a; font-weight: 700; text-decoration: none; }
			.dsf-full-dictionary .dsf-access-links a:hover { text-decoration: underline; }

			@media (max-width: 767px) {
				.dsf-full-dictionary { padding-top: 140px; }
				.dsf-full-dictionary h2 { font-size: 32px; }
				.dsf-full-dictionary .dsf-access-overlay { padding-top: 128px; }
				.dsf-full-dictionary .dsf-access-modal { padding: 22px 18px; border-radius: 18px; }
				.dsf-full-dictionary .dsf-access-modal h3 { font-size: 24px; }
			}
		</style>

		<div class="dsf-full-dictionary__viewport">
			<h2>Dicionário Completo (DSF)</h2>
			<?php if ( $has_access && $is_account_access ) : ?>
				<div class="dsf-access-pill">Acesso por conta ativa por 7 dias.</div>
			<?php elseif ( $has_access && $guest_access_entry ) : ?>
				<div class="dsf-access-pill">Acesso temporário liberado por 24 horas.</div>
			<?php else : ?>
				<p>Pesquise qualquer substância e abra a ficha completa.</p>
			<?php endif; ?>

			<form class="dsf-search" method="get" action="<?php echo esc_url( $current_url ); ?>">
				<input type="search" name="dsf_q" value="<?php echo esc_attr( $search_term ); ?>" placeholder="Pesquise por nome, DCB, INN, CAS ou NCM" />
				<?php if ( '' !== $letter ) : ?>
					<input type="hidden" name="dsf_letter" value="<?php echo esc_attr( $letter ); ?>" />
				<?php endif; ?>
				<button type="submit">Buscar</button>
				<a href="<?php echo esc_url( $clear_url ); ?>">Limpar filtros</a>
			</form>

			<div class="dsf-alphabet"><?php echo wp_kses_post( implode( '', $alphabet_links ) ); ?></div>

			<div class="dsf-meta">
				<?php
				printf(
					/* translators: %d = number of records found */
					esc_html__( '%d resultados encontrados.', 'default' ),
					(int) $query->found_posts
				);
				?>
			</div>

			<?php if ( $query->have_posts() ) : ?>
				<ul>
					<?php
					while ( $query->have_posts() ) :
						$query->the_post();
						?>
						<li>
							<a href="<?php the_permalink(); ?>"><?php the_title(); ?></a>
						</li>
					<?php endwhile; ?>
				</ul>

				<?php
				$pagination = paginate_links(
					array(
						'base'      => add_query_arg( 'dsf_page', '%#%', remove_query_arg( 'dsf_page', $current_url ) ),
						'format'    => '',
						'current'   => $page,
						'total'     => max( 1, (int) $query->max_num_pages ),
						'type'      => 'array',
						'prev_text' => '&laquo;',
						'next_text' => '&raquo;',
						'add_args'  => array(
							'dsf_q'      => $search_term,
							'dsf_letter' => $letter,
						),
					)
				);

				if ( ! empty( $pagination ) ) :
					?>
					<nav class="dsf-pagination" aria-label="Paginação do dicionário">
						<?php
						foreach ( $pagination as $page_link ) {
							echo wp_kses_post( $page_link );
						}
						?>
					</nav>
				<?php endif; ?>

			<?php else : ?>
				<div class="dsf-empty">Nenhuma substância encontrada com os filtros atuais.</div>
			<?php endif; ?>
		</div>

		<?php if ( ! $has_access ) : ?>
			<div class="dsf-access-overlay">
				<div class="dsf-access-modal">
					<h3>Para continuar, é necessário preencher os dados</h3>
					<?php if ( '' !== $form_error_message ) : ?>
						<div class="dsf-access-alert"><?php echo esc_html( $form_error_message ); ?></div>
					<?php endif; ?>

					<form class="dsf-access-form" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post">
						<input type="hidden" name="action" value="dsf_dictionary_guest_access" />
						<input type="hidden" name="redirect_to" value="<?php echo esc_url( $current_url ); ?>" />
						<?php wp_nonce_field( 'dsf_dictionary_guest_access', 'dsf_dictionary_guest_access_nonce' ); ?>

						<div class="dsf-access-field">
							<label for="dsf-access-name">Nome:</label>
							<input id="dsf-access-name" name="dsf_name" type="text" required />
						</div>

						<div class="dsf-access-field">
							<label for="dsf-access-phone">Telefone:</label>
							<input id="dsf-access-phone" name="dsf_phone" type="text" required />
						</div>

						<div class="dsf-access-field">
							<label for="dsf-access-email">Email:</label>
							<input id="dsf-access-email" name="dsf_email" type="email" required />
						</div>

						<div class="dsf-access-field">
							<label for="dsf-access-company">Empresa:</label>
							<input id="dsf-access-company" name="dsf_company" type="text" required />
						</div>

						<div class="dsf-access-field">
							<label for="dsf-access-job-title">Cargo:</label>
							<select id="dsf-access-job-title" name="dsf_job_title" required>
								<option value="">Escolha uma opção</option>
								<?php foreach ( dsf_dictionary_job_title_options() as $option ) : ?>
									<option value="<?php echo esc_attr( $option ); ?>"><?php echo esc_html( $option ); ?></option>
								<?php endforeach; ?>
							</select>
						</div>

						<button type="submit" class="dsf-access-submit">Continuar</button>
					</form>

					<p class="dsf-access-links">Ou crie uma conta para não precisar preencher novamente - <a href="<?php echo esc_url( $register_url ); ?>">Criar uma conta&gt;&gt;</a></p>
					<p class="dsf-access-links">Já tem uma conta? <a href="<?php echo esc_url( $login_url ); ?>">Entrar&gt;&gt;</a></p>
				</div>
			</div>
		<?php endif; ?>
	</section>
	<?php
	wp_reset_postdata();
	return (string) ob_get_clean();
}

/**
 * Swap the DSF page content with the full dictionary view.
 *
 * @param string $content Original content.
 * @return string
 */
function dsf_dictionary_replace_content_for_dsf_page( $content ) {
	if ( is_admin() || ! in_the_loop() || ! is_main_query() ) {
		return $content;
	}

	if ( ! is_page( 'dicionario-dsf' ) ) {
		return $content;
	}

	return dsf_dictionary_render_view();
}
