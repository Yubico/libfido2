#ifndef _FIDO_OPENSSL_COMPAT_H
#define _FIDO_OPENSSL_COMPAT_H

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

static inline EVP_PKEY *
fido_ec_pk_to_pkey(int nid, const unsigned char *x, const unsigned char *y,
    size_t len, const BIGNUM *priv)
{
	unsigned char pub[97];
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY_CTX *check = NULL;
	EVP_PKEY *pkey = NULL;
	int ok = -1;

	if (len > (sizeof(pub) - 1) / 2)
		return (NULL);
	pub[0] = 0x04;
	memcpy(pub + 1, x, len);
	memcpy(pub + 1 + len, y, len);
	if ((bld = OSSL_PARAM_BLD_new()) == NULL ||
	    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
	    OBJ_nid2sn(nid), 0) != 1 ||
	    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
	    pub, 1 + 2 * len) != 1 ||
	    (priv != NULL && OSSL_PARAM_BLD_push_BN(bld,
	    OSSL_PKEY_PARAM_PRIV_KEY, priv) != 1) ||
	    (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
	    (ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL ||
	    EVP_PKEY_fromdata_init(ctx) != 1 ||
	    EVP_PKEY_fromdata(ctx, &pkey, priv == NULL ? EVP_PKEY_PUBLIC_KEY :
	    EVP_PKEY_KEYPAIR, params) != 1 ||
	    (check = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL)) == NULL ||
	    EVP_PKEY_public_check(check) != 1)
		goto fail;
	ok = 0;
fail:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_CTX_free(check);
	if (ok < 0) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	return (pkey);
}

static inline int
fido_ec_pk_from_pkey(const EVP_PKEY *pkey, int nid, unsigned char *x,
    unsigned char *y, size_t len)
{
	char group[80];
	BIGNUM *bnx = NULL;
	BIGNUM *bny = NULL;
	EVP_PKEY *check = NULL;
	int ok = FIDO_ERR_INVALID_ARGUMENT;

	if (EVP_PKEY_is_a(pkey, "EC") != 1 ||
	    EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
	    group, sizeof(group), NULL) != 1 || OBJ_txt2nid(group) != nid)
		goto fail;
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bnx) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &bny) != 1 ||
	    BN_bn2binpad(bnx, x, (int)len) != (int)len ||
	    BN_bn2binpad(bny, y, (int)len) != (int)len)
		goto fail;
	if ((check = fido_ec_pk_to_pkey(nid, x, y, len, NULL)) == NULL)
		goto fail;
	ok = FIDO_OK;
fail:
	BN_free(bnx);
	BN_free(bny);
	EVP_PKEY_free(check);
	return (ok);
}
#endif