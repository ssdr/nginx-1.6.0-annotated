
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

/*
 * Request URL : http://ip:port/md5sum?f=xxxx
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#define NGX_HTTP_FORBIDDEN_NO_ARGS 10000
#define NGX_HTTP_FORBIDDEN_INVALID_ARGS 10001

#define BUFSZ (1024*8)

static char *ngx_http_file_md5(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_file_md5_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_add_error_to_header(ngx_http_request_t *r, ngx_int_t error_code);
static ngx_int_t ngx_http_to_string(ngx_pool_t *pool, ngx_int_t n, ngx_str_t *str);

static ngx_int_t ngx_http_file_md5sum_compute( ngx_http_request_t *r, ngx_str_t filename, ngx_str_t *md5sum);

static ngx_command_t ngx_http_file_md5_commands[] = {
    { ngx_string("md5sum"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_file_md5,
      0,
      0,
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_file_md5_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_file_md5_module = {
    NGX_MODULE_V1,
    &ngx_http_file_md5_module_ctx,        /* module context */
    ngx_http_file_md5_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_file_md5(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    // 按需挂载handler
    clcf->handler = ngx_http_file_md5_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_file_md5_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_int_t                  error_n;
    ngx_str_t                  value;
    ngx_log_t                 *log;
    ngx_chain_t                out;
    ngx_buf_t                 *buf;
    ngx_str_t                  md5sum;
    
    // 请求的有效性判断
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }
    
    // 丢弃请求体
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    
    //必须包含filename参数，否则禁止请求
    if (r->args.len <= 0) {
        error_n = NGX_HTTP_FORBIDDEN_NO_ARGS;
        goto FORBIDDEN;
    }

    //必须包含filename参数且值为数字，否则禁止请求
    rc = ngx_http_arg(r, (u_char *)"f", 1, &value);
    if (NGX_OK != rc) {
        error_n = NGX_HTTP_FORBIDDEN_INVALID_ARGS;
        goto FORBIDDEN;
    }

    log = r->connection->log;

    ngx_log_error(NGX_LOG_INFO, log, 0,
                   "IP: %V, REQUEST URL: \"%V?%V\"", 
                   &r->connection->addr_text, &r->uri, &r->args);//

	log->action = "commputing file md5sum";
	if( ngx_http_file_md5sum_compute( r, value, &md5sum ) != NGX_OK) {
    	ngx_log_error(NGX_LOG_ALERT, log, 0,
                   "File md5sum compute failed. IP: %V, REQUEST URL: \"%V?%V\"", 
                   &r->connection->addr_text, &r->uri, &r->args);//
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	//设置响应的头信息
	ngx_str_t type = ngx_string("text/plain");
    r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = md5sum.len;
	r->headers_out.content_type = type;
	// 发送头
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
	
    buf = ngx_create_temp_buf(r->pool, md5sum.len);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "Failed to allocate response buffer in chain.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(buf->pos, md5sum.data, md5sum.len);
    buf->last = buf->pos + md5sum.len;
    buf->last_buf = 1;
	
    out.buf = buf;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);


FORBIDDEN:

    rc = ngx_http_add_error_to_header(r, error_n);
    if (NGX_ERROR == rc) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_HTTP_FORBIDDEN;
}

ngx_int_t
ngx_http_add_error_to_header(ngx_http_request_t *r, ngx_int_t error_code)
{
    ngx_table_elt_t           *table;
    ngx_int_t                  rc;

    table = (ngx_table_elt_t *)ngx_list_push(&r->headers_out.headers);
    if(NULL == table) {
        return NGX_ERROR;
    }
    table->hash = 1;
    ngx_str_set(&table->key, "Error-Type");
    rc = ngx_http_to_string(r->pool, error_code, &table->value);
    if(NGX_ERROR == rc) {
        return NGX_ERROR;
    }

	ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
			   "ERROR CODE in header: \"%V:%V\"", &table->key, &table->value);
    return NGX_OK;
}

static ngx_int_t
ngx_http_to_string(ngx_pool_t *pool, ngx_int_t n, ngx_str_t *str)
{
    u_char              *c;
    u_char               ch[10]; // error code like xxxx, 5 is enough, here is 10 :)
    ngx_uint_t           len;

    len = sizeof(ch);
    ngx_memzero(ch, len);
    ngx_snprintf(ch, len, "%d", n);

    len = strlen((char*)ch);
    c = ngx_pcalloc(pool, sizeof(u_char)*len);
    if(NULL == c) {
        return NGX_ERROR;
    }

    str->len = len;
    ngx_memcpy(c, ch, len);
    str->data = c;

    return NGX_OK;
}

static ngx_int_t
ngx_http_file_md5sum_compute( ngx_http_request_t *r, ngx_str_t filename, ngx_str_t *md5sum)
{
    off_t                      size, n, i;
    u_char                    *last, buf[BUFSZ], md5[16];
    size_t                     len;
    ngx_log_t                 *log;
	ngx_str_t				   abspath;
    ngx_md5_t                  ctx;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    log = r->connection->log;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_memzero(&of, sizeof(ngx_open_file_info_t));
    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;
    
	abspath.len = clcf->root.len + 1 + filename.len;
	abspath.data = ngx_pcalloc(r->pool, abspath.len);
	if( abspath.data == NULL ) {
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "abspath data ngx_pcalloc failed");
		return NGX_ERROR;
	}
	last = ngx_copy(abspath.data, clcf->root.data, clcf->root.len);
    last = ngx_cpystrn(last, (u_char*)"/", 2);
    last = ngx_cpystrn(last, filename.data, filename.len+1);
	
	//ngx_log_error(NGX_LOG_INFO, log, 0, " root: %V filename: %V abspath: %V ", &clcf->root, &filename, &abspath);

    if (ngx_open_cached_file(clcf->open_file_cache, &abspath, &of, r->pool) != NGX_OK)
    {
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno, 
			" %V failed to open cached file", &abspath);
        return NGX_ERROR;
    }
	if (!of.is_file) {
		if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, log, ngx_errno, 
				ngx_close_file_n " %V failed to close", &abspath);
		}

		ngx_log_error(NGX_LOG_ERR, log, ngx_errno, " %V is not file", &abspath);
        return NGX_ERROR;
	}

    size = of.size;
    len = BUFSZ;

    ngx_md5_init(&ctx);
    while (size > 0) {

        if ((off_t) len > size) {
            len = (size_t) size;
        }

        n = ngx_read_fd(of.fd, buf, len);

        if (n == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          ngx_read_fd_n "failed");
            return NGX_ERROR;
        }

        if ((size_t) n != len) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          ngx_read_fd_n " has read only %z of %uz",
                          n, size);
            return NGX_ERROR;
        }

        ngx_md5_update(&ctx, buf, len);

        size -= n;
    }
    ngx_md5_final(md5, &ctx);

    md5sum->data = last = ngx_pcalloc(r->pool, 32);
    if (last == NULL) {
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "md5sum data ngx_pcalloc failed");
        return NGX_ERROR;
    }

    for (i = 0; i < 16; i++) {
        last = ngx_sprintf(last, "%02xi", md5[i]);
    }
	md5sum->len = last - md5sum->data;

    return NGX_OK;
}
