# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

find_program(MANDOC_PATH mandoc)
find_program(GZIP_PATH gzip)

message(STATUS "MANDOC_PATH: ${MANDOC_PATH}")
message(STATUS "GZIP_PATH: ${GZIP_PATH}")

add_custom_target(man_copy
	COMMAND cp -f ${CMAKE_SOURCE_DIR}/man/*.[31] ${CMAKE_BINARY_DIR}/man)

macro(define_symlink_target NAME EXT)
	add_custom_target(${NAME}
		COMMAND ln -fs es256_pk.${EXT} es256_pk_new.${EXT}
		COMMAND ln -fs es256_pk.${EXT} es256_pk_free.${EXT}
		COMMAND ln -fs es256_pk.${EXT} es256_pk_from_EC_KEY.${EXT}
		COMMAND ln -fs es256_pk.${EXT} es256_pk_from_ptr.${EXT}
		COMMAND ln -fs es256_pk.${EXT} es256_pk_to_EVP_PKEY.${EXT}
		COMMAND ln -fs fido.${EXT} fido_init.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_new.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_free.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_count.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_hmac_secret_len.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_hmac_secret_ptr.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_user_display_name.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_user_icon.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_user_name.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_authdata_ptr.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_clientdata_hash_ptr.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_user_id_ptr.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_sig_ptr.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_authdata_len.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_clientdata_hash_len.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_user_id_len.${EXT}
		COMMAND ln -fs fido_assert.${EXT} fido_assert_sig_len.${EXT}
		COMMAND ln -fs fido_assert_set.${EXT} fido_assert_set_authdata.${EXT}
		COMMAND ln -fs fido_assert_set.${EXT} fido_assert_set_clientdata_hash.${EXT}
		COMMAND ln -fs fido_assert_set.${EXT} fido_assert_set_count.${EXT}
		COMMAND ln -fs fido_assert_set.${EXT} fido_assert_set_extensions.${EXT}
		COMMAND ln -fs fido_assert_set.${EXT} fido_assert_set_hmac_salt.${EXT}
		COMMAND ln -fs fido_assert_set.${EXT} fido_assert_set_options.${EXT}
		COMMAND ln -fs fido_assert_set.${EXT} fido_assert_set_rp.${EXT}
		COMMAND ln -fs fido_assert_set.${EXT} fido_assert_set_sig.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_new.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_free.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_fmt.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_authdata_ptr.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_clientdata_hash_ptr.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_id_ptr.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_pubkey_ptr.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_sig_ptr.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_x5c_ptr.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_authdata_len.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_clientdata_hash_len.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_id_len.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_pubkey_len.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_sig_len.${EXT}
		COMMAND ln -fs fido_cred.${EXT} fido_cred_x5c_len.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_authdata.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_x509.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_sig.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_clientdata_hash.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_rp.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_user.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_extensions.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_options.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_fmt.${EXT}
		COMMAND ln -fs fido_cred_set.${EXT} fido_cred_set_type.${EXT}
		COMMAND ln -fs fido_dev_info_manifest.${EXT} fido_dev_info_new.${EXT}
		COMMAND ln -fs fido_dev_info_manifest.${EXT} fido_dev_info_free.${EXT}
		COMMAND ln -fs fido_dev_info_manifest.${EXT} fido_dev_info_ptr.${EXT}
		COMMAND ln -fs fido_dev_info_manifest.${EXT} fido_dev_info_path.${EXT}
		COMMAND ln -fs fido_dev_info_manifest.${EXT} fido_dev_info_product.${EXT}
		COMMAND ln -fs fido_dev_info_manifest.${EXT} fido_dev_info_vendor.${EXT}
		COMMAND ln -fs fido_dev_info_manifest.${EXT} fido_dev_info_manufacturer_string.${EXT}
		COMMAND ln -fs fido_dev_info_manifest.${EXT} fido_dev_info_product_string.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_close.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_new.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_free.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_is_fido2.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_protocol.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_build.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_flags.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_major.${EXT}
		COMMAND ln -fs fido_dev_open.${EXT} fido_dev_minor.${EXT}
		COMMAND ln -fs fido_dev_set_pin.${EXT} fido_dev_get_retry_count.${EXT}
		COMMAND ln -fs fido_dev_set_pin.${EXT} fido_dev_reset.${EXT}
		COMMAND ln -fs rs256_pk.${EXT} rs256_pk_new.${EXT}
		COMMAND ln -fs rs256_pk.${EXT} rs256_pk_free.${EXT}
		COMMAND ln -fs rs256_pk.${EXT} rs256_pk_from_RSA.${EXT}
		COMMAND ln -fs rs256_pk.${EXT} rs256_pk_from_ptr.${EXT}
		COMMAND ln -fs rs256_pk.${EXT} rs256_pk_to_EVP_PKEY.${EXT}
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man)
endmacro()

define_symlink_target(man_symlink 3)

add_custom_target(man_lint
	COMMAND mandoc -T lint *.3 *.1
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man)

add_custom_target(man_html
	COMMAND cp -f ${CMAKE_SOURCE_DIR}/man/style.css .
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" es256_pk.3 > es256_pk.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido.3 > fido.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_assert.3 > fido_assert.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_assert_allow_cred.3 > fido_assert_allow_cred.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_assert_set.3 > fido_assert_set.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_assert_verify.3 > fido_assert_verify.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cbor_info.3 > fido_cbor_info.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cred.3 > fido_cred.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cred_exclude.3 > fido_cred_exclude.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cred_set.3 > fido_cred_set.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cred_verify.3 > fido_cred_verify.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_get_assert.3 > fido_dev_get_assert.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_info_manifest.3 > fido_dev_info_manifest.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_make_cred.3 > fido_dev_make_cred.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_open.3 > fido_dev_open.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_set_io_functions.3 > fido_dev_set_io_functions.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_set_pin.3 > fido_dev_set_pin.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_strerr.3 > fido_strerr.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" rs256_pk.3 > rs256_pk.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido2-assert.1 > fido2-assert.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido2-cred.1 > fido2-cred.html
	COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido2-token.1 > fido2-token.html
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man)

define_symlink_target(man_symlink_html html)

add_custom_target(man_html_partial
	COMMAND mandoc -T html -O man="%N.html",fragment es256_pk.3 > es256_pk.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido.3 > fido.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_assert.3 > fido_assert.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_assert_allow_cred.3 > fido_assert_allow_cred.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_assert_set.3 > fido_assert_set.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_assert_verify.3 > fido_assert_verify.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_cbor_info.3 > fido_cbor_info.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_cred.3 > fido_cred.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_cred_exclude.3 > fido_cred_exclude.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_cred_set.3 > fido_cred_set.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_cred_verify.3 > fido_cred_verify.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_dev_get_assert.3 > fido_dev_get_assert.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_dev_info_manifest.3 > fido_dev_info_manifest.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_dev_make_cred.3 > fido_dev_make_cred.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_dev_open.3 > fido_dev_open.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_dev_set_io_functions.3 > fido_dev_set_io_functions.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_dev_set_pin.3 > fido_dev_set_pin.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido_strerr.3 > fido_strerr.partial
	COMMAND mandoc -T html -O man="%N.html",fragment rs256_pk.3 > rs256_pk.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido2-assert.1 > fido2-assert.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido2-cred.1 > fido2-cred.partial
	COMMAND mandoc -T html -O man="%N.html",fragment fido2-token.1 > fido2-token.partial
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man)

define_symlink_target(man_symlink_html_partial partial)

add_custom_target(man_gzip
	COMMAND gzip -c es256_pk.3 > es256_pk.3.gz
	COMMAND gzip -c fido.3 > fido.3.gz
	COMMAND gzip -c fido_assert.3 > fido_assert.3.gz
	COMMAND gzip -c fido_assert_allow_cred.3 > fido_assert_allow_cred.3.gz
	COMMAND gzip -c fido_assert_set.3 > fido_assert_set.3.gz
	COMMAND gzip -c fido_assert_verify.3 > fido_assert_verify.3.gz
	COMMAND gzip -c fido_cbor_info.3 > fido_cbor_info.3.gz
	COMMAND gzip -c fido_cred.3 > fido_cred.3.gz
	COMMAND gzip -c fido_cred_exclude.3 > fido_cred_exclude.3.gz
	COMMAND gzip -c fido_cred_set.3 > fido_cred_set.3.gz
	COMMAND gzip -c fido_cred_verify.3 > fido_cred_verify.3.gz
	COMMAND gzip -c fido_dev_get_assert.3 > fido_dev_get_assert.3.gz
	COMMAND gzip -c fido_dev_info_manifest.3 > fido_dev_info_manifest.3.gz
	COMMAND gzip -c fido_dev_make_cred.3 > fido_dev_make_cred.3.gz
	COMMAND gzip -c fido_dev_open.3 > fido_dev_open.3.gz
	COMMAND gzip -c fido_dev_set_io_functions.3 > fido_dev_set_io_functions.3.gz
	COMMAND gzip -c fido_dev_set_pin.3 > fido_dev_set_pin.3.gz
	COMMAND gzip -c fido_strerr.3 > fido_strerr.3.gz
	COMMAND gzip -c rs256_pk.3 > rs256_pk.3.gz
	COMMAND gzip -c fido2-assert.1 > fido2-assert.1.gz
	COMMAND gzip -c fido2-cred.1 > fido2-cred.1.gz
	COMMAND gzip -c fido2-token.1 > fido2-token.1.gz
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man)

define_symlink_target(man_symlink_gzip 3.gz)

add_dependencies(man_symlink man_copy)
add_dependencies(man_lint man_symlink)
add_dependencies(man_html man_lint)
add_dependencies(man_symlink_html man_html)
add_dependencies(man_html_partial man_lint)
add_dependencies(man_symlink_html_partial man_html_partial)
add_custom_target(man ALL)

if(MANDOC_PATH)
	add_dependencies(man man_symlink_html)
	add_dependencies(man_gzip man_lint)
	install(FILES ${CMAKE_BINARY_DIR}/man/es256_pk.html
		${CMAKE_BINARY_DIR}/man/es256_pk_free.html
		${CMAKE_BINARY_DIR}/man/es256_pk_from_EC_KEY.html
		${CMAKE_BINARY_DIR}/man/es256_pk_from_ptr.html
		${CMAKE_BINARY_DIR}/man/es256_pk_new.html
		${CMAKE_BINARY_DIR}/man/es256_pk_to_EVP_PKEY.html
		${CMAKE_BINARY_DIR}/man/fido.html
		${CMAKE_BINARY_DIR}/man/fido_assert.html
		${CMAKE_BINARY_DIR}/man/fido_assert_allow_cred.html
		${CMAKE_BINARY_DIR}/man/fido_assert_authdata_len.html
		${CMAKE_BINARY_DIR}/man/fido_assert_authdata_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_assert_clientdata_hash_len.html
		${CMAKE_BINARY_DIR}/man/fido_assert_clientdata_hash_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_assert_count.html
		${CMAKE_BINARY_DIR}/man/fido_assert_free.html
		${CMAKE_BINARY_DIR}/man/fido_assert_new.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set_authdata.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set_clientdata_hash.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set_count.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set_extensions.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set_hmac_salt.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set_options.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set_rp.html
		${CMAKE_BINARY_DIR}/man/fido_assert_set_sig.html
		${CMAKE_BINARY_DIR}/man/fido_assert_sig_len.html
		${CMAKE_BINARY_DIR}/man/fido_assert_sig_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_assert_hmac_secret_len.html
		${CMAKE_BINARY_DIR}/man/fido_assert_hmac_secret_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_assert_user_display_name.html
		${CMAKE_BINARY_DIR}/man/fido_assert_user_icon.html
		${CMAKE_BINARY_DIR}/man/fido_assert_user_id_len.html
		${CMAKE_BINARY_DIR}/man/fido_assert_user_id_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_assert_user_name.html
		${CMAKE_BINARY_DIR}/man/fido_assert_verify.html
		${CMAKE_BINARY_DIR}/man/fido_cbor_info.html
		${CMAKE_BINARY_DIR}/man/fido_cred.html
		${CMAKE_BINARY_DIR}/man/fido_cred_authdata_len.html
		${CMAKE_BINARY_DIR}/man/fido_cred_authdata_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_cred_clientdata_hash_len.html
		${CMAKE_BINARY_DIR}/man/fido_cred_clientdata_hash_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_cred_exclude.html
		${CMAKE_BINARY_DIR}/man/fido_cred_fmt.html
		${CMAKE_BINARY_DIR}/man/fido_cred_free.html
		${CMAKE_BINARY_DIR}/man/fido_cred_id_len.html
		${CMAKE_BINARY_DIR}/man/fido_cred_id_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_cred_new.html
		${CMAKE_BINARY_DIR}/man/fido_cred_pubkey_len.html
		${CMAKE_BINARY_DIR}/man/fido_cred_pubkey_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_authdata.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_clientdata_hash.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_fmt.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_extensions.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_options.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_rp.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_sig.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_type.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_user.html
		${CMAKE_BINARY_DIR}/man/fido_cred_set_x509.html
		${CMAKE_BINARY_DIR}/man/fido_cred_sig_len.html
		${CMAKE_BINARY_DIR}/man/fido_cred_sig_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_cred_verify.html
		${CMAKE_BINARY_DIR}/man/fido_cred_x5c_len.html
		${CMAKE_BINARY_DIR}/man/fido_cred_x5c_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_dev_build.html
		${CMAKE_BINARY_DIR}/man/fido_dev_close.html
		${CMAKE_BINARY_DIR}/man/fido_dev_flags.html
		${CMAKE_BINARY_DIR}/man/fido_dev_free.html
		${CMAKE_BINARY_DIR}/man/fido_dev_get_assert.html
		${CMAKE_BINARY_DIR}/man/fido_dev_get_retry_count.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_free.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_manifest.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_manufacturer_string.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_new.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_path.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_product.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_product_string.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_ptr.html
		${CMAKE_BINARY_DIR}/man/fido_dev_info_vendor.html
		${CMAKE_BINARY_DIR}/man/fido_dev_is_fido2.html
		${CMAKE_BINARY_DIR}/man/fido_dev_major.html
		${CMAKE_BINARY_DIR}/man/fido_dev_make_cred.html
		${CMAKE_BINARY_DIR}/man/fido_dev_minor.html
		${CMAKE_BINARY_DIR}/man/fido_dev_new.html
		${CMAKE_BINARY_DIR}/man/fido_dev_open.html
		${CMAKE_BINARY_DIR}/man/fido_dev_protocol.html
		${CMAKE_BINARY_DIR}/man/fido_dev_reset.html
		${CMAKE_BINARY_DIR}/man/fido_dev_set_io_functions.html
		${CMAKE_BINARY_DIR}/man/fido_dev_set_pin.html
		${CMAKE_BINARY_DIR}/man/fido_init.html
		${CMAKE_BINARY_DIR}/man/fido_strerr.html
		${CMAKE_BINARY_DIR}/man/rs256_pk.html
		${CMAKE_BINARY_DIR}/man/rs256_pk_free.html
		${CMAKE_BINARY_DIR}/man/rs256_pk_from_ptr.html
		${CMAKE_BINARY_DIR}/man/rs256_pk_from_RSA.html
		${CMAKE_BINARY_DIR}/man/rs256_pk_new.html
		${CMAKE_BINARY_DIR}/man/rs256_pk_to_EVP_PKEY.html
		${CMAKE_BINARY_DIR}/man/fido2-assert.html
		${CMAKE_BINARY_DIR}/man/fido2-cred.html
		${CMAKE_BINARY_DIR}/man/fido2-token.html
		${CMAKE_BINARY_DIR}/man/style.css
		DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/libfido2")
endif()

if(GZIP_PATH)
	add_dependencies(man_gzip man_copy)
	add_dependencies(man_symlink_gzip man_gzip)
	add_dependencies(man man_symlink_gzip)
	install(FILES ${CMAKE_BINARY_DIR}/man/es256_pk.3.gz
		${CMAKE_BINARY_DIR}/man/es256_pk_free.3.gz
		${CMAKE_BINARY_DIR}/man/es256_pk_from_EC_KEY.3.gz
		${CMAKE_BINARY_DIR}/man/es256_pk_from_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/es256_pk_new.3.gz
		${CMAKE_BINARY_DIR}/man/es256_pk_to_EVP_PKEY.3.gz
		${CMAKE_BINARY_DIR}/man/fido.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_allow_cred.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_authdata_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_authdata_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_clientdata_hash_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_clientdata_hash_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_count.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_free.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_new.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set_authdata.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set_clientdata_hash.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set_count.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set_extensions.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set_hmac_salt.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set_options.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set_rp.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_set_sig.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_sig_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_sig_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_hmac_secret_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_hmac_secret_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_user_display_name.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_user_icon.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_user_id_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_user_id_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_user_name.3.gz
		${CMAKE_BINARY_DIR}/man/fido_assert_verify.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cbor_info.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_authdata_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_authdata_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_clientdata_hash_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_clientdata_hash_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_exclude.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_fmt.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_free.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_id_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_id_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_new.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_pubkey_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_pubkey_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_authdata.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_clientdata_hash.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_fmt.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_extensions.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_options.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_rp.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_sig.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_type.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_user.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_set_x509.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_sig_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_sig_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_verify.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_x5c_len.3.gz
		${CMAKE_BINARY_DIR}/man/fido_cred_x5c_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_build.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_close.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_flags.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_free.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_get_assert.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_get_retry_count.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_free.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_manifest.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_manufacturer_string.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_new.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_path.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_product.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_product_string.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_info_vendor.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_is_fido2.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_major.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_make_cred.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_minor.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_new.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_open.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_protocol.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_reset.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_set_io_functions.3.gz
		${CMAKE_BINARY_DIR}/man/fido_dev_set_pin.3.gz
		${CMAKE_BINARY_DIR}/man/fido_init.3.gz
		${CMAKE_BINARY_DIR}/man/fido_strerr.3.gz
		${CMAKE_BINARY_DIR}/man/rs256_pk.3.gz
		${CMAKE_BINARY_DIR}/man/rs256_pk_free.3.gz
		${CMAKE_BINARY_DIR}/man/rs256_pk_from_ptr.3.gz
		${CMAKE_BINARY_DIR}/man/rs256_pk_from_RSA.3.gz
		${CMAKE_BINARY_DIR}/man/rs256_pk_new.3.gz
		${CMAKE_BINARY_DIR}/man/rs256_pk_to_EVP_PKEY.3.gz
		DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man3")
	install(FILES ${CMAKE_BINARY_DIR}/man/fido2-assert.1.gz
		${CMAKE_BINARY_DIR}/man/fido2-cred.1.gz
		${CMAKE_BINARY_DIR}/man/fido2-token.1.gz
		DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man1")
endif()
