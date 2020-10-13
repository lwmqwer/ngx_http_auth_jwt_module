
/*
 * Copyright (C) Wuming Liu (lwmqwer@163.com)
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>


#define NGX_HTTP_AUTH_BUF_SIZE  2048


typedef struct {
    ngx_flag_t     enable;
    const EVP_MD  *hash_algorithm;
    EVP_PKEY      *pkey;
    ngx_str_t      key;
    ngx_str_t      type;
} ngx_http_auth_jwt_loc_conf_t;


static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_key_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_auth_jwt_commands[] = {

    { ngx_string("auth_jwt"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, enable),
      NULL },

    { ngx_string("auth_jwt_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_auth_jwt_key_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_jwt_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_auth_jwt_init,             /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_auth_jwt_create_loc_conf,  /* create location configuration */
    ngx_http_auth_jwt_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_auth_jwt_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_jwt_module_ctx,       /* module context */
    ngx_http_auth_jwt_commands,          /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_jwt_verify(ngx_http_auth_jwt_loc_conf_t *alcf,
    ngx_str_t *encoded)
{
    u_int        n;
    ngx_str_t    token;
    ngx_str_t    input, output;
    BIGNUM      *r = NULL;
    BIGNUM      *s = NULL;
    ECDSA_SIG   *ec_sig = NULL;
    EVP_MD_CTX  *mdctx = NULL;
    u_char       buf[2][NGX_HTTP_AUTH_BUF_SIZE];

    input.data = buf[0];
    output.data = buf[1];

    token.data = encoded->data + encoded->len - 1;
    while (token.data > encoded->data) {
        if (*(token.data) == '.') {
            break;
        }
        token.data--;
    }
    token.len = encoded->len - (token.data - encoded->data) - 1;
    encoded->len = token.data - encoded->data;
    token.data++;

    if (encoded->len == 0 || token.len == 0) {
        return NGX_ERROR;
    }

    if (alcf->type.data[0] == 'H' ||  alcf->type.data[0] == 'h') {
        if (NGX_HTTP_AUTH_BUF_SIZE < EVP_MAX_MD_SIZE) {
            return NGX_ERROR;
        }
        HMAC(alcf->hash_algorithm, alcf->key.data, alcf->key.len,
             encoded->data, encoded->len, input.data, &n);
        input.len = n;
        if (ngx_base64_encoded_length(input.len) > NGX_HTTP_AUTH_BUF_SIZE) {
            return NGX_ERROR;
        }
        ngx_encode_base64url(&output, &input);
        if (ngx_strncmp(token.data, output.data, token.len) != 0) {
            return NGX_ERROR;
        }
    } else {
        output.len = ngx_base64_decoded_length(token.len);
        if (output.len > NGX_HTTP_AUTH_BUF_SIZE) {
            return NGX_ERROR;
        }
        ngx_decode_base64url(&output, &token);
        if (alcf->type.data[0] == 'E' || alcf->type.data[0] == 'e') {
            r = BN_bin2bn(output.data, output.len >> 1, NULL);
            s = BN_bin2bn(output.data + (output.len >> 1), output.len >> 1,
                          NULL);
            ec_sig = ECDSA_SIG_new();
            if (ec_sig == NULL) {
                return NGX_ERROR;
            }
            ECDSA_SIG_set0(ec_sig, r, s);
            if (i2d_ECDSA_SIG(ec_sig, NULL) > NGX_HTTP_AUTH_BUF_SIZE) {
                ECDSA_SIG_free(ec_sig);
                return NGX_ERROR;
            }
            output.len = i2d_ECDSA_SIG(ec_sig, &output.data);
            output.data = buf[1];
            ECDSA_SIG_free(ec_sig);
        }

        mdctx = EVP_MD_CTX_create();
        if (mdctx == NULL) {
            return NGX_ERROR;
        }

        if (EVP_DigestVerifyInit(mdctx, NULL, alcf->hash_algorithm, NULL,
                                 alcf->pkey)
            != 1) {
            EVP_MD_CTX_destroy(mdctx);
            return NGX_ERROR;
        }
        if (EVP_DigestVerify(mdctx, output.data, output.len, encoded->data,
                             encoded->len)
            != 1) {
            EVP_MD_CTX_destroy(mdctx);
            return NGX_ERROR;
        }
        EVP_MD_CTX_destroy(mdctx);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_str_t                      encoded;
    ngx_http_auth_jwt_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

    if (!alcf->enable) {
        return NGX_DECLINED;
    }

    if (r->headers_in.authorization == NULL) {
        return NGX_HTTP_FORBIDDEN;
    }

    encoded = r->headers_in.authorization->value;

    if (encoded.len < sizeof("Bearer ") - 1
        || ngx_strncasecmp(encoded.data, (u_char *) "Bearer ",
                           sizeof("Bearer ") - 1)
           != 0)
    {
        r->headers_in.user.data = (u_char *) "";
        return NGX_HTTP_FORBIDDEN;
    }

    encoded.len -= sizeof("Bearer ") - 1;
    encoded.data += sizeof("Bearer ") - 1;

    while (encoded.len && encoded.data[0] == ' ') {
        encoded.len--;
        encoded.data++;
    }

    if (encoded.len == 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    rc = ngx_http_auth_jwt_verify(alcf, &encoded);

    if (rc == NGX_ERROR) {
        return NGX_HTTP_FORBIDDEN;
    }

    return rc;
}


static void *
ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_jwt_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->hash_algorithm = NGX_CONF_UNSET_PTR;
    conf->pkey = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_jwt_loc_conf_t  *prev = parent;
    ngx_http_auth_jwt_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->hash_algorithm, prev->hash_algorithm, NULL);
    ngx_conf_merge_ptr_value(conf->pkey, prev->pkey, NULL);
    ngx_conf_merge_str_value(conf->type, prev->type, "");
    ngx_conf_merge_str_value(conf->key, prev->key, "");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_jwt_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_jwt_handler;

    return NGX_OK;
}


static void
ngx_http_auth_jwt_cleanup(void *data)
{
    EVP_PKEY_free((EVP_PKEY *)data);
}


static char *
ngx_http_auth_jwt_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                        n;
    ngx_fd_t                       fd;
    ngx_str_t                     *value;
    ngx_pool_cleanup_t            *cln;
    ngx_http_auth_jwt_loc_conf_t  *alcf = conf;

    if (alcf->type.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    alcf->type = value[1];

    if (alcf->type.data[2] == '2') {
        alcf->hash_algorithm = EVP_sha256();
    } else if (alcf->type.data[2] == '3') {
        alcf->hash_algorithm = EVP_sha384();
    } else if (alcf->type.data[2] == '5') {
        alcf->hash_algorithm = EVP_sha512();
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "unsupport algorithem %s", value[1].data);
        return NGX_CONF_ERROR;
    }

    fd = ngx_open_file(value[2].data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%s\" failed", value[2].data);
        return NGX_CONF_ERROR;
    }

    if (alcf->type.data[0] == 'H' ||  alcf->type.data[0] == 'h') {
        alcf->key.data = ngx_palloc(cf->pool, NGX_HTTP_AUTH_BUF_SIZE);
        if (alcf->key.data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "jwt module alloc key buffer fail");
            goto cleanup;
        }

        n = ngx_read_fd(fd, alcf->key.data, NGX_HTTP_AUTH_BUF_SIZE);

        if (n == -1 || n > NGX_HTTP_AUTH_BUF_SIZE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               ngx_read_fd_n " \"%s\" failed", value[2].data);
            goto cleanup;
        }
        alcf->key.len = n-1;
    } else {
        alcf->pkey = PEM_read_PUBKEY(fdopen(fd, "r"), NULL, NULL, NULL);
        if (alcf->pkey == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "Read public key from \"%s\" failed",
                               value[2].data);
            goto cleanup;
        }

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            EVP_PKEY_free(alcf->pkey);
            goto cleanup;
        }
        cln->handler = ngx_http_auth_jwt_cleanup;
        cln->data = alcf->pkey;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%s\" failed", value[2].data);
    }

    return NGX_CONF_OK;
cleanup:
    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%s\" failed", value[2].data);
    }

    return NGX_CONF_ERROR;
}
