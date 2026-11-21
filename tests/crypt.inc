<?php
/*
 * Checks a value in Suhosin's encryption format, version 2, without decrypting it:
 *   0x02 | IV (16) | AES-256-CBC ciphertext (16*n) | HMAC-SHA256 tag (32)
 * $material is what suhosin_generate_key() hashes: cryptkey . user agent . document root . REMOTE_ADDR prefix.
 * The tag covers the version, the name the value is bound to, the IV and the ciphertext.
 */
function suhosin_crypt_check($name, $value, $material)
{
	$bin = base64_decode(strtr($value, '-._', '/=+'), true);
	if ($bin === false || strlen($bin) < 65 || (strlen($bin) - 49) % 16 != 0 || ord($bin[0]) != 2) {
		return "not encrypted";
	}
	$base = hash('sha256', $material, true);
	$mac_key = hash_hmac('sha256', 'suhosin-v2-mac', $base, true);
	$tag = hash_hmac('sha256', "\x02" . pack('V', strlen($name)) . $name . substr($bin, 1, -32), $mac_key, true);
	if ($tag !== substr($bin, -32)) {
		return "encrypted, tag does not verify";
	}
	return "encrypted, tag verifies, " . (strlen($bin) - 49) . " bytes ciphertext";
}

/* prints each Set-Cookie header, with encrypted values replaced by what suhosin_crypt_check() says */
function suhosin_show_set_cookies($material)
{
	foreach (headers_list() as $h) {
		if (!preg_match('/^Set-Cookie: ([^=]*)=([^;]*)(.*)$/', $h, $m)) {
			continue;
		}
		$r = suhosin_crypt_check(urldecode($m[1]), urldecode($m[2]), $material);
		if ($r == "not encrypted") {
			echo "$h\n";
		} else {
			echo "Set-Cookie: $m[1]=<$r>$m[3]\n";
		}
	}
}
