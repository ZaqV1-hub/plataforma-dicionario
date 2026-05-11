# Abiquifi Mailer

Configuracao de SMTP e dos fluxos de e-mail do Fabricamos.

## Variaveis de ambiente

- `ABIQUIFI_SMTP_HOST`: host SMTP do Microsoft 365. Valor esperado: `smtp.office365.com`
- `ABIQUIFI_SMTP_PORT`: porta SMTP. Valor esperado: `587`
- `ABIQUIFI_SMTP_ENCRYPTION`: criptografia SMTP. Valor esperado: `tls`
- `ABIQUIFI_SMTP_USER`: usuario SMTP da conta Outlook/Microsoft 365
- `ABIQUIFI_SMTP_PASS`: senha da conta ou senha de aplicativo
- `ABIQUIFI_MAIL_FROM_EMAIL`: remetente padrao. Valor esperado: `marketing@abiquifi.org.br`
- `ABIQUIFI_MAIL_FROM_NAME`: nome do remetente. Exemplo: `Fabricamos | Abiquifi`
- `ABIQUIFI_MAIL_LOG`: opcional. Use `1` para registrar eventos de configuracao e falhas em `wp-content/uploads/abiquifi-mail.log`

## Fluxos cobertos

- Confirmacao de cadastro do Fabricamos e do Dicionario
- Padronizacao global do remetente do WordPress

## Validacao rapida

1. Configure as variaveis de ambiente.
2. Confirme que o arquivo `wp-content/mu-plugins/abiquifi-mailer.php` esta carregado.
3. Realize um cadastro novo e valide o recebimento do e-mail.
4. Se precisar de diagnostico, consulte `wp-content/uploads/abiquifi-mail.log`.
