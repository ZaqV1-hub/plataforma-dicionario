<?php
/**
 * DSF registration flow customizations for WP User Manager.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Add PT-BR registration fields and restore the richer signup form.
 *
 * @param array $fields
 * @return array
 */
function dsf_wpum_extend_registration_fields( $fields ) {
	$fields['user_firstname'] = array(
		'label'       => 'Nome',
		'type'        => 'text',
		'required'    => true,
		'placeholder' => 'Digite seu nome',
		'description' => '',
		'priority'    => 1,
		'primary_id'  => 'user_firstname',
		'options'     => array(),
	);

	$fields['user_lastname'] = array(
		'label'       => 'Sobrenome',
		'type'        => 'text',
		'required'    => true,
		'placeholder' => 'Digite seu sobrenome',
		'description' => '',
		'priority'    => 2,
		'primary_id'  => 'user_lastname',
		'options'     => array(),
	);

	if ( isset( $fields['user_email'] ) ) {
		$fields['user_email']['label']       = 'E-mail';
		$fields['user_email']['placeholder'] = 'Digite seu e-mail';
		$fields['user_email']['priority']    = 3;
	}

	if ( isset( $fields['user_password'] ) ) {
		$fields['user_password']['label']       = 'Senha';
		$fields['user_password']['placeholder'] = 'Digite sua senha';
		$fields['user_password']['priority']    = 4;
	}

	$fields['wpum_instituicao'] = array(
		'label'       => 'Nome da Instituição',
		'type'        => 'text',
		'required'    => true,
		'placeholder' => 'Empresa ou instituicao',
		'description' => '',
		'priority'    => 5,
		'options'     => array(),
	);

	$fields['wpum_whatsapp'] = array(
		'label'       => 'Celular / WhatsApp',
		'type'        => 'telephone',
		'required'    => true,
		'placeholder' => '(00) 00000-0000',
		'description' => '',
		'priority'    => 6,
		'options'     => array(),
	);

	$fields['wpum_ramo_atividade'] = array(
		'label'       => 'Ramo de Atividade',
		'type'        => 'dropdown',
		'required'    => true,
		'description' => '',
		'priority'    => 7,
		'options'     => array(
			''                        => 'Escolha uma opção',
			'agencia_governamental'   => 'Agência Governamental',
			'consultorias'            => 'Consultorias',
			'distribuidor_importador' => 'Distribuidor / Importador',
			'entidade_classe'         => 'Entidade de Classe',
			'fabricante_ifa'          => 'Fabricante de IFA',
			'fabricante_medicamentos' => 'Fabricante de Medicamentos',
			'ict'                     => 'ICT - Instituto de Ciência e Tecnologia',
			'laboratorio_oficial'     => 'Laboratório Oficial',
			'universidades'           => 'Universidades',
			'orgao_publico'           => 'Órgãos de Administração Pública',
			'outros'                  => 'Outros',
		),
	);

	$fields['wpum_departamento'] = array(
		'label'       => 'Departamento',
		'type'        => 'dropdown',
		'required'    => true,
		'description' => '',
		'priority'    => 8,
		'options'     => array(
			''                    => 'Escolha uma opção',
			'suprimentos'         => 'Suprimentos',
			'importacao'          => 'Importação',
			'marketing'           => 'Marketing',
			'vendas'              => 'Vendas',
			'exportacao'          => 'Exportação',
			'pdi'                 => 'PD&I',
			'assuntos_regulatorios' => 'Assuntos Regulatórios',
			'novos_negocios'      => 'Novos Negócios',
			'outros'              => 'Outros',
		),
	);

	$fields['wpum_cargo'] = array(
		'label'       => 'Cargo',
		'type'        => 'dropdown',
		'required'    => true,
		'description' => '',
		'priority'    => 9,
		'options'     => array(
			''                   => 'Escolha uma opção',
			'analista'           => 'Analista',
			'pesquisador'        => 'Pesquisador',
			'coordenador'        => 'Coordenador',
			'gerente'            => 'Gerente',
			'especialista'       => 'Especialista',
			'consultor'          => 'Consultor',
			'diretor'            => 'Diretor',
			'presidente_ceo'     => 'Presidente / Vice-Presidente / CEO',
			'outros'             => 'Outros',
		),
	);

	return $fields;
}
add_filter( 'wpum_get_registration_fields', 'dsf_wpum_extend_registration_fields', 20 );

/**
 * Persist extra registration fields.
 *
 * @param int   $user_id
 * @param array $values
 * @return void
 */
function dsf_wpum_save_registration_fields( $user_id, $values ) {
	if ( empty( $user_id ) || empty( $values['register'] ) || ! is_array( $values['register'] ) ) {
		return;
	}

	$register = $values['register'];

	$text_map = array(
		'wpum_instituicao' => 'wpum_instituicao',
		'wpum_whatsapp'    => 'wpum_whatsapp',
	);

	foreach ( $text_map as $field_key => $meta_key ) {
		if ( ! isset( $register[ $field_key ] ) ) {
			continue;
		}

		$value = sanitize_text_field( wp_unslash( (string) $register[ $field_key ] ) );
		update_user_meta( $user_id, $meta_key, $value );
	}

	$dropdown_map = array(
		'wpum_ramo_atividade' => array(
			'agencia_governamental',
			'consultorias',
			'distribuidor_importador',
			'entidade_classe',
			'fabricante_ifa',
			'fabricante_medicamentos',
			'ict',
			'laboratorio_oficial',
			'universidades',
			'orgao_publico',
			'outros',
		),
		'wpum_departamento' => array(
			'suprimentos',
			'importacao',
			'marketing',
			'vendas',
			'exportacao',
			'pdi',
			'assuntos_regulatorios',
			'novos_negocios',
			'outros',
		),
		'wpum_cargo' => array(
			'analista',
			'pesquisador',
			'coordenador',
			'gerente',
			'especialista',
			'consultor',
			'diretor',
			'presidente_ceo',
			'outros',
		),
	);

	foreach ( $dropdown_map as $field_key => $allowed ) {
		if ( ! isset( $register[ $field_key ] ) ) {
			continue;
		}

		$value = sanitize_key( (string) $register[ $field_key ] );
		if ( in_array( $value, $allowed, true ) ) {
			update_user_meta( $user_id, $field_key, $value );
		}
	}
}
add_action( 'wpum_after_registration', 'dsf_wpum_save_registration_fields', 10, 2 );

/**
 * Translate action links/labels to PT-BR.
 */
function dsf_wpum_registration_link_label() {
	$url = esc_url( get_permalink( wpum_get_core_page_id( 'register' ) ) );
	return sprintf( 'Não tem conta? <a href="%s">Crie sua conta &raquo;</a>', $url );
}
add_filter( 'wpum_registration_link_label', 'dsf_wpum_registration_link_label' );

function dsf_wpum_login_link_label() {
	$url = esc_url( get_permalink( wpum_get_core_page_id( 'login' ) ) );
	return sprintf( 'Já tem conta? <a href="%s">Entrar &raquo;</a>', $url );
}
add_filter( 'wpum_login_link_label', 'dsf_wpum_login_link_label' );

add_filter(
	'wpum_registration_form_submit_label',
	function () {
		return 'Criar conta';
	}
);

add_filter(
	'wpum_password_link_label',
	function () {
		return 'Esqueceu sua senha?';
	}
);
