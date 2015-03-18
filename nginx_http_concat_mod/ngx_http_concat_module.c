
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* 
 * 请求模式：
 * http://172.30.204.122:7211/ssi/file?a.html&a.shtml
 */

static char *ngx_http_concat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_concat_handler(ngx_http_request_t *r);


static ngx_command_t ngx_http_concat_commands[] = {
    { ngx_string("concat"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_concat,
      0,
      0,
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_concat_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_concat_module = {
    NGX_MODULE_V1,
    &ngx_http_concat_module_ctx,        /* module context */
    ngx_http_concat_commands,           /* module directives */
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
ngx_http_concat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    // 按需挂载handler
    clcf->handler = ngx_http_concat_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_concat_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
	size_t 					   root;
	u_char					  *s, *t, *last;
	u_char					   fullpath[1024];
	off_t					   totalSz;
    ngx_str_t                  name;
	ngx_str_t				   path;
    ngx_log_t                 *log;
    ngx_chain_t                out, *ch, **last_out;
    ngx_buf_t                 *buf;
    ngx_file_t                *file;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_open_file_info_t       of;
    
    // 请求的有效性判断
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }
    
    // 必须包含参数
    if (r->args.len <= 0) {
    	return NGX_HTTP_FORBIDDEN;
    }


    log = r->connection->log;
    ngx_log_error(NGX_LOG_INFO, log, 0,
                   "IP: %V, REQUEST URL: \"%V?%V\" ", 
                   &r->connection->addr_text, &r->uri, &r->args);//
    r->root_tested = !r->error_page;
    log->action = "sending files to client";


	// 映射目录路径
    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    path.len = last - path.data;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	buf = NULL;
	ch = NULL;
	last_out = NULL;
	totalSz = 0;
	// 解析url获取文件名 
	s = r->args.data; 
	while(s < r->args.data + r->args.len) {
		t = ngx_strlchr(s, s+r->args.len, '&');
		if(t == NULL) {
			t = r->args.data + r->args.len; 
		}

		name.data = s;
		name.len = t - s;
		ngx_memzero(fullpath, 1024);
		ngx_snprintf(fullpath, 1024, "%V%V", &path, &name);
		name.data = fullpath;
		name.len += path.len;
		
		ngx_memzero(&of, sizeof(ngx_open_file_info_t));
		of.read_ahead = clcf->read_ahead;
		of.directio = clcf->directio;
		of.valid = clcf->open_file_cache_valid;
		of.min_uses = clcf->open_file_cache_min_uses;
		of.errors = clcf->open_file_cache_errors;
		of.events = clcf->open_file_cache_events;
		if (ngx_http_set_disable_symlinks(r, clcf, &name, &of) != NGX_OK) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "ngx_http_set_disable_symlinks() failed [%V}.", &name);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		if (ngx_open_cached_file(clcf->open_file_cache, &name, &of, r->pool) != NGX_OK) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "ngx_open_cached_file() failed [%V].", &name);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		if (!of.is_file) {
			if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
				ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "\"%V\" close failed.", &name);
			}
			ngx_log_error(NGX_LOG_ALERT, log, 0, "\"%V\" is not a regular file.", &name);
			return NGX_HTTP_NOT_FOUND;
		}
		
		if(of.size <= 0) {
			continue;
		}
		// 更新totalSz
		totalSz += of.size;

		buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
		if (buf == NULL) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "Failed to allocate buffer.");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
		if(file == NULL) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "Failed to allocate file.");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		
		buf->file_pos = 0;
		buf->file_last = of.size;
		buf->in_file = buf->file_last ? 1 : 0;
		buf->file = file;
		
		file->fd = of.fd;
		file->name = name;
		file->log = log;
		file->directio = of.is_directio;


		if(last_out == NULL) {
			out.buf = buf;
			last_out = &out.next;
			out.next = NULL;
		} else {
			ch = ngx_alloc_chain_link(r->pool);
			if (ch == NULL) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "Failed to allocate chain.");
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			ch->buf = buf;
			*last_out = ch;
			last_out = &ch->next;
			ch->next = NULL;
		}
		
		// here we can write some delimiter data between files

		s = t + 1;
	}

    //设置响应的头信息
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = totalSz;
    r->headers_out.last_modified_time = time(NULL);

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

	if(buf) {
		buf->last_buf = 1;
		buf->last_in_chain = 1;
	}

    return ngx_http_output_filter(r, &out);
}
