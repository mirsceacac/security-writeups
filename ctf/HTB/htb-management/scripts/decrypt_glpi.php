<?php
// Decrypt a GLPI secret (XChaCha20-Poly1305, AAD = nonce).
// Run on the target where the key file lives:
//   php decrypt_glpi.php '<base64 ciphertext>'
// Layout: base64( nonce[24] || ciphertext || tag )
$keyPath = getenv('GLPI_KEY') ?: '/opt/glpi/config/glpicrypt.key';

if ($argc < 2) {
    fwrite(STDERR, "usage: php {$argv[0]} <base64_ciphertext>\n");
    exit(1);
}
if (!is_readable($keyPath)) {
    fwrite(STDERR, "[-] key not readable: {$keyPath}\n");
    exit(1);
}

$key  = file_get_contents($keyPath);
$raw  = base64_decode($argv[1], true);
if ($raw === false) {
    fwrite(STDERR, "[-] invalid base64\n");
    exit(1);
}

$nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
$nonce    = substr($raw, 0, $nonceLen);
$data     = substr($raw, $nonceLen);

try {
    $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, $nonce, $nonce, $key);
    echo $plain . PHP_EOL;
} catch (SodiumException $e) {
    fwrite(STDERR, "[-] decryption failed: " . $e->getMessage() . PHP_EOL);
    exit(1);
}
