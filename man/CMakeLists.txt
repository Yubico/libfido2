# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

if(MANDOC_PATH)
	add_custom_target(man_symlink ALL
		COMMAND cp ${CMAKE_SOURCE_DIR}/man/*.3 ${CMAKE_BINARY_DIR}/man
		COMMAND ln -fs es256_pk.3 es256_pk_new.3
		COMMAND ln -fs es256_pk.3 es256_pk_free.3
		COMMAND ln -fs es256_pk.3 es256_pk_from_EC_KEY.3
		COMMAND ln -fs es256_pk.3 es256_pk_from_ptr.3
		COMMAND ln -fs es256_pk.3 es256_pk_to_EVP_PKEY.3
		COMMAND ln -fs fido.3 fido_init.3
		COMMAND ln -fs fido_assert.3 fido_assert_new.3
		COMMAND ln -fs fido_assert.3 fido_assert_free.3
		COMMAND ln -fs fido_assert.3 fido_assert_count.3
		COMMAND ln -fs fido_assert.3 fido_assert_user_display_name.3
		COMMAND ln -fs fido_assert.3 fido_assert_user_icon.3
		COMMAND ln -fs fido_assert.3 fido_assert_user_name.3
		COMMAND ln -fs fido_assert.3 fido_assert_authdata_ptr.3
		COMMAND ln -fs fido_assert.3 fido_assert_clientdata_hash_ptr.3
		COMMAND ln -fs fido_assert.3 fido_assert_user_id_ptr.3
		COMMAND ln -fs fido_assert.3 fido_assert_sig_ptr.3
		COMMAND ln -fs fido_assert.3 fido_assert_authdata_len.3
		COMMAND ln -fs fido_assert.3 fido_assert_clientdata_hash_len.3
		COMMAND ln -fs fido_assert.3 fido_assert_user_id_len.3
		COMMAND ln -fs fido_assert.3 fido_assert_sig_len.3
		COMMAND ln -fs fido_assert_set.3 fido_assert_set_authdata.3
		COMMAND ln -fs fido_assert_set.3 fido_assert_set_clientdata_hash.3
		COMMAND ln -fs fido_assert_set.3 fido_assert_set_count.3
		COMMAND ln -fs fido_assert_set.3 fido_assert_set_options.3
		COMMAND ln -fs fido_assert_set.3 fido_assert_set_rp.3
		COMMAND ln -fs fido_assert_set.3 fido_assert_set_sig.3
		COMMAND ln -fs fido_cred.3 fido_cred_new.3
		COMMAND ln -fs fido_cred.3 fido_cred_free.3
		COMMAND ln -fs fido_cred.3 fido_cred_fmt.3
		COMMAND ln -fs fido_cred.3 fido_cred_authdata_ptr.3
		COMMAND ln -fs fido_cred.3 fido_cred_clientdata_hash_ptr.3
		COMMAND ln -fs fido_cred.3 fido_cred_id_ptr.3
		COMMAND ln -fs fido_cred.3 fido_cred_pubkey_ptr.3
		COMMAND ln -fs fido_cred.3 fido_cred_sig_ptr.3
		COMMAND ln -fs fido_cred.3 fido_cred_x5c_ptr.3
		COMMAND ln -fs fido_cred.3 fido_cred_authdata_len.3
		COMMAND ln -fs fido_cred.3 fido_cred_clientdata_hash_len.3
		COMMAND ln -fs fido_cred.3 fido_cred_id_len.3
		COMMAND ln -fs fido_cred.3 fido_cred_pubkey_len.3
		COMMAND ln -fs fido_cred.3 fido_cred_sig_len.3
		COMMAND ln -fs fido_cred.3 fido_cred_x5c_len.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_authdata.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_x509.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_sig.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_clientdata_hash.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_rp.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_user.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_options.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_fmt.3
		COMMAND ln -fs fido_cred_set.3 fido_cred_set_type.3
		COMMAND ln -fs fido_dev_info_manifest.3 fido_dev_info_new.3
		COMMAND ln -fs fido_dev_info_manifest.3 fido_dev_info_free.3
		COMMAND ln -fs fido_dev_info_manifest.3 fido_dev_info_ptr.3
		COMMAND ln -fs fido_dev_info_manifest.3 fido_dev_info_path.3
		COMMAND ln -fs fido_dev_info_manifest.3 fido_dev_info_product.3
		COMMAND ln -fs fido_dev_info_manifest.3 fido_dev_info_vendor.3
		COMMAND ln -fs fido_dev_info_manifest.3 fido_dev_info_manufacturer_string.3
		COMMAND ln -fs fido_dev_info_manifest.3 fido_dev_info_product_string.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_close.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_new.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_free.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_is_fido2.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_protocol.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_build.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_flags.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_major.3
		COMMAND ln -fs fido_dev_open.3 fido_dev_minor.3
		COMMAND ln -fs fido_dev_set_pin.3 fido_dev_get_retry_count.3
		COMMAND ln -fs fido_dev_set_pin.3 fido_dev_reset.3
		COMMAND ln -fs rs256_pk.3 rs256_pk_new.3
		COMMAND ln -fs rs256_pk.3 rs256_pk_free.3
		COMMAND ln -fs rs256_pk.3 rs256_pk_from_RSA.3
		COMMAND ln -fs rs256_pk.3 rs256_pk_from_ptr.3
		COMMAND ln -fs rs256_pk.3 rs256_pk_to_EVP_PKEY.3
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man)
	add_custom_target(man_lint ALL
		COMMAND mandoc -T lint *.3
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man)
	add_custom_target(man_html ALL
		COMMAND mkdir html
		COMMAND cp ${CMAKE_SOURCE_DIR}/man/style.css html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" es256_pk.3 > html/es256_pk.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido.3 > html/fido.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_assert.3 > html/fido_assert.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_assert_allow_cred.3 > html/fido_assert_allow_cred.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_assert_set.3 > html/fido_assert_set.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_assert_verify.3 > html/fido_assert_verify.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cbor_info.3 > html/fido_cbor_info.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cred.3 > html/fido_cred.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cred_exclude.3 > html/fido_cred_exclude.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cred_set.3 > html/fido_cred_set.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_cred_verify.3 > html/fido_cred_verify.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_get_assert.3 > html/fido_dev_get_assert.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_info_manifest.3 > html/fido_dev_info_manifest.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_make_cred.3 > html/fido_dev_make_cred.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_open.3 > html/fido_dev_open.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_set_io_functions.3 > html/fido_dev_set_io_functions.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_dev_set_pin.3 > html/fido_dev_set_pin.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" fido_strerr.3 > html/fido_strerr.html
		COMMAND mandoc -T html -O man="%N.html",style=style.css -I os="Yubico AB" rs256_pk.3 > html/rs256_pk.html
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man)
	add_custom_target(man_symlink_html ALL
		COMMAND ln -fs es256_pk.html es256_pk_new.html
		COMMAND ln -fs es256_pk.html es256_pk_free.html
		COMMAND ln -fs es256_pk.html es256_pk_from_EC_KEY.html
		COMMAND ln -fs es256_pk.html es256_pk_from_ptr.html
		COMMAND ln -fs es256_pk.html es256_pk_to_EVP_PKEY.html
		COMMAND ln -fs fido.html fido_init.html
		COMMAND ln -fs fido_assert.html fido_assert_new.html
		COMMAND ln -fs fido_assert.html fido_assert_free.html
		COMMAND ln -fs fido_assert.html fido_assert_count.html
		COMMAND ln -fs fido_assert.html fido_assert_user_display_name.html
		COMMAND ln -fs fido_assert.html fido_assert_user_icon.html
		COMMAND ln -fs fido_assert.html fido_assert_user_name.html
		COMMAND ln -fs fido_assert.html fido_assert_authdata_ptr.html
		COMMAND ln -fs fido_assert.html fido_assert_clientdata_hash_ptr.html
		COMMAND ln -fs fido_assert.html fido_assert_user_id_ptr.html
		COMMAND ln -fs fido_assert.html fido_assert_sig_ptr.html
		COMMAND ln -fs fido_assert.html fido_assert_authdata_len.html
		COMMAND ln -fs fido_assert.html fido_assert_clientdata_hash_len.html
		COMMAND ln -fs fido_assert.html fido_assert_user_id_len.html
		COMMAND ln -fs fido_assert.html fido_assert_sig_len.html
		COMMAND ln -fs fido_assert_set.html fido_assert_set_authdata.html
		COMMAND ln -fs fido_assert_set.html fido_assert_set_clientdata_hash.html
		COMMAND ln -fs fido_assert_set.html fido_assert_set_count.html
		COMMAND ln -fs fido_assert_set.html fido_assert_set_options.html
		COMMAND ln -fs fido_assert_set.html fido_assert_set_rp.html
		COMMAND ln -fs fido_assert_set.html fido_assert_set_sig.html
		COMMAND ln -fs fido_cred.html fido_cred_new.html
		COMMAND ln -fs fido_cred.html fido_cred_free.html
		COMMAND ln -fs fido_cred.html fido_cred_fmt.html
		COMMAND ln -fs fido_cred.html fido_cred_authdata_ptr.html
		COMMAND ln -fs fido_cred.html fido_cred_clientdata_hash_ptr.html
		COMMAND ln -fs fido_cred.html fido_cred_id_ptr.html
		COMMAND ln -fs fido_cred.html fido_cred_pubkey_ptr.html
		COMMAND ln -fs fido_cred.html fido_cred_sig_ptr.html
		COMMAND ln -fs fido_cred.html fido_cred_x5c_ptr.html
		COMMAND ln -fs fido_cred.html fido_cred_authdata_len.html
		COMMAND ln -fs fido_cred.html fido_cred_clientdata_hash_len.html
		COMMAND ln -fs fido_cred.html fido_cred_id_len.html
		COMMAND ln -fs fido_cred.html fido_cred_pubkey_len.html
		COMMAND ln -fs fido_cred.html fido_cred_sig_len.html
		COMMAND ln -fs fido_cred.html fido_cred_x5c_len.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_authdata.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_x509.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_sig.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_clientdata_hash.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_rp.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_user.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_options.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_fmt.html
		COMMAND ln -fs fido_cred_set.html fido_cred_set_type.html
		COMMAND ln -fs fido_dev_info_manifest.html fido_dev_info_new.html
		COMMAND ln -fs fido_dev_info_manifest.html fido_dev_info_free.html
		COMMAND ln -fs fido_dev_info_manifest.html fido_dev_info_ptr.html
		COMMAND ln -fs fido_dev_info_manifest.html fido_dev_info_path.html
		COMMAND ln -fs fido_dev_info_manifest.html fido_dev_info_product.html
		COMMAND ln -fs fido_dev_info_manifest.html fido_dev_info_vendor.html
		COMMAND ln -fs fido_dev_info_manifest.html fido_dev_info_manufacturer_string.html
		COMMAND ln -fs fido_dev_info_manifest.html fido_dev_info_product_string.html
		COMMAND ln -fs fido_dev_open.html fido_dev_close.html
		COMMAND ln -fs fido_dev_open.html fido_dev_new.html
		COMMAND ln -fs fido_dev_open.html fido_dev_free.html
		COMMAND ln -fs fido_dev_open.html fido_dev_is_fido2.html
		COMMAND ln -fs fido_dev_open.html fido_dev_protocol.html
		COMMAND ln -fs fido_dev_open.html fido_dev_build.html
		COMMAND ln -fs fido_dev_open.html fido_dev_flags.html
		COMMAND ln -fs fido_dev_open.html fido_dev_major.html
		COMMAND ln -fs fido_dev_open.html fido_dev_minor.html
		COMMAND ln -fs fido_dev_set_pin.html fido_dev_get_retry_count.html
		COMMAND ln -fs fido_dev_set_pin.html fido_dev_reset.html
		COMMAND ln -fs rs256_pk.html rs256_pk_new.html
		COMMAND ln -fs rs256_pk.html rs256_pk_free.html
		COMMAND ln -fs rs256_pk.html rs256_pk_from_RSA.html
		COMMAND ln -fs rs256_pk.html rs256_pk_from_ptr.html
		COMMAND ln -fs rs256_pk.html rs256_pk_to_EVP_PKEY.html
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/man/html)
	add_dependencies(man_lint man_symlink)
	add_dependencies(man_html man_lint)
	add_dependencies(man_symlink_html man_html)
endif()
