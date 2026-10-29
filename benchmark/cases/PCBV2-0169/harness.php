<?php
/**
 * Thin consumer of Packagist phpmailer/phpmailer (whole package via composer).
 * GET /send?from=<address> -> PHPMailer::setFrom()->send() over mail() / sendmail -f.
 */
error_reporting(0);

require '/opt/app/vendor/autoload.php';

$VER = getenv('HARNESS_VER') ?: 'v1';
$PMV = getenv('PM_VER') ?: '5.2.18';

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path !== '/send') {
    header('Content-Type: text/plain');
    echo "ok phpmailer $VER ($PMV)";
    exit;
}

$from = isset($_GET['from']) ? $_GET['from'] : '';
@unlink('/canary/out.txt');

$sender = '';
$send_ok = false;
$err = null;
try {
    $mail = new PHPMailer(true);
    $mail->isMail();
    $mail->setFrom($from);
    $mail->addAddress('recipient@example.com');
    $mail->Subject = 'pcb canary';
    $mail->Body = 'benign benchmark message body';
    $send_ok = (bool) $mail->send();
    $sender = isset($mail->Sender) ? $mail->Sender : '';
} catch (Exception $e) {
    $err = $e->getMessage();
} catch (Throwable $t) {
    $err = $t->getMessage();
}

$canary_out = @file_get_contents('/canary/out.txt');
if ($canary_out === false) { $canary_out = ''; }

header('Content-Type: application/json');
echo json_encode(array(
    'version'           => $VER,
    'phpmailer_version' => $PMV,
    'phpmailer_file'    => (new ReflectionClass('PHPMailer'))->getFileName(),
    'from'              => $from,
    'sender'            => $sender,
    'send_ok'           => $send_ok,
    'error'             => $err,
    'canary_out'        => $canary_out,
    'body'              => $canary_out,
));
