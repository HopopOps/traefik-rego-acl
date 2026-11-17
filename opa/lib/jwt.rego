package lib.jwt

# claims(token, aud) is the payload of a token signed by an issuer declared in
# data.lib.config.issuers and issued for aud; undefined otherwise.
#
# The JWKS URL comes from that configuration only, never from the token or the caller:
# this function is the one network path policies have.
claims(token, aud) := payload if {
	[_, unverified, _] := io.jwt.decode(token)
	issuer := data.lib.config.issuers[unverified.iss]
	response := http.send({
		"method": "GET",
		"url": issuer.jwks_uri,
		"force_cache": true,
		"force_cache_duration_seconds": 3600,
		"raise_error": false,
	})
	response.status_code == 200
	[valid, _, payload] := io.jwt.decode_verify(token, {
		"cert": response.raw_body,
		"iss": unverified.iss,
		"aud": aud,
	})
	valid
}
