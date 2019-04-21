/*内部函数以ipslab_开头
 * 模块相关函数以ngx_开头
 * */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
//#include <openssl/err.h>
//#include <malloc.h>

# include <openssl/md5.h>
# include "duktape.h"
# include "gumbo.h"


#define ID_POS_MIN 6
#define ID_LEN_IN_TEXT sizeof(ngx_int_t)
//ID 的长度
#define ENCRPT_ID_SIZE 32
#define ENCRPT_IDNUM_SIZE 32
//“href"以null结尾字符串长度
#define HREF_SIZE_WITH_NL 5
#define SRC_SIZE_WITH_NL 4

//"?hxID="和"&hxID="的长度
#define CHRCTR_HXID_EQ_NUM 6
#define APPEND_NUM (CHRCTR_HXID_EQ_NUM + ENCRPT_ID_SIZE+1)

enum Append_flag{
	pure_chrctr,    //添加“hxID=xxxx” 0
	ampersand_chrctr,//添加“&hxID=xxxx” 1
	question_chrctr//添加“?hxID=xxxx” 2

};
typedef struct{
	GumboSourcePosition value_end_of_attr;//具体使用
	enum Append_flag chrctr_flag;
}packed_position;
//#define CURVE_I 8
typedef struct {
	ngx_chain_t *out_ctx;
	ngx_str_t hxID;
} ngx_http_ipslab_ctx_t;

typedef struct {
	ngx_int_t pass_count;//如果请求返回一个HTML页面，将会根据HTML解析结果保留请求相关资源的机会。
	u_char rbtree_node_data;
	ngx_queue_t queue;
	u_char slab_ID[ENCRPT_ID_SIZE+1];//node中保留的均是给浏览器下发的ID，浏览器端在请求时会进行MD5，而本模块会在强求到达时访问slab的look up操作中进行MD5
	u_char last_slab_ID[ENCRPT_ID_SIZE+1];


} ngx_http_ipslab_node_t;

//ngx_http_ipslab_shm_t 保存在共享内存中
typedef struct {
	//红黑树用于快速检索
	ngx_rbtree_t rbtree;
	//使用红黑树必须定义的哨兵节点
	ngx_rbtree_node_t sentinel;
	//淘汰链表
	ngx_queue_t queue;
} ngx_http_ipslab_shm_t;

typedef struct {
	//ssize_t shmsize;共享内存大小，配置项适合ngx_int_t,内存适合使用ssize_t
	ngx_int_t shmsize_int;
	ngx_slab_pool_t *shpool;//操作共享内存一定需要的结构体，这个结构体也在共享内存中
	ngx_http_ipslab_shm_t *sh;
// ngx_int_t uri_ID;
} ngx_http_ipslab_conf_t;
static ngx_int_t ngx_http_ipslab_handler(ngx_http_request_t *r);
static char * ngx_http_ipslab_createmem(ngx_conf_t *cf, ngx_command_t *cmd,
		void *conf);
static ngx_int_t ngx_http_ipslab_init(ngx_conf_t *cf);
static void *ngx_http_ipslab_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ipslab_subrequest_post_handler(ngx_http_request_t *r,
		void *data, ngx_int_t rc);
static void
ipslab_post_handler(ngx_http_request_t * r);
//8888static ngx_int_t ngx_http_ipslab_input_filter(void *data, ssize_t bytes);


//一些原本可以隐式声明的
//static ngx_int_t push_one_packed_position_to_array(GumboSourcePosition* pos,enum Append_flag flag,ngx_array_t* link_vector);
static GumboNode* find_body_node(const GumboNode* root);
ngx_buf_t* build_content_response(ngx_http_request_t *r,const char* ID_frm_srvr);
static ngx_uint_t ipslab_ip_atoui(ngx_str_t str_ip);
static ngx_command_t ngx_http_ipslab_commands[] = { {
ngx_string("ip_slab"),
NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ngx_http_ipslab_createmem, //ngx_conf_set_num_slot,
		NGX_HTTP_MAIN_CONF_OFFSET, offsetof(ngx_http_ipslab_conf_t,
				shmsize_int),
		NULL },

ngx_null_command };

static ngx_http_module_t ngx_http_ipslab_module_ctx = {
NULL, /* preconfiguration */
ngx_http_ipslab_init, /* postconfiguration */

ngx_http_ipslab_create_main_conf, /* create main configuration */
NULL, /* init main configuration */

NULL, /* create server configuration */
NULL, /* merge server configuration */

NULL, // create location configuration */
		NULL /* merge location configuration */
};

ngx_module_t ngx_http_ipslab_module = {
NGX_MODULE_V1, &ngx_http_ipslab_module_ctx, /* module context */
ngx_http_ipslab_commands, /* module directives */
NGX_HTTP_MODULE, /* module type */
NULL, /* init master */
NULL, /* init module */
NULL, /* init process */
NULL, /* init thread */
NULL, /* exit thread */
NULL, /* exit process */
NULL, /* exit master */
NGX_MODULE_V1_PADDING };

static void *ngx_http_ipslab_create_main_conf(ngx_conf_t *cf) {

	ngx_http_ipslab_conf_t *conf;
	ngx_log_error(NGX_LOG_DEBUG, cf->log, 0,
			"sxx-ngx_http_ipslab_create_main_conf");
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipslab_conf_t));

	if (NULL == conf) {
		return NULL;
	}

	conf->shmsize_int = NGX_CONF_UNSET;
	return conf;
}

static ngx_int_t ngx_http_ipslab_shm_init(ngx_shm_zone_t *shm_zone, void *data) {
	ngx_http_ipslab_conf_t *conf;

	ngx_http_ipslab_conf_t *oconf = data;
	size_t len;
	fprintf(stderr, "%s", "ngx_http_ipslab_shm_init");
	conf = (ngx_http_ipslab_conf_t *) shm_zone->data;

	if (oconf) {
		conf->sh = oconf->sh;
		conf->shpool = oconf->shpool;

		return NGX_OK;
	}

	conf->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	fprintf(stderr, "ngx_http_ipslab_shm_init:%s\r\n", (char *) conf->shpool);
	if (NULL != conf->shpool) {

	}
	// fprintf(stderr, "ngx_http_ipslab_shm_init:%s\r\n",conf->shpool,sizeof(ngx_slab_pool_t));
	len = sizeof(ngx_http_ipslab_shm_t);
	fprintf(stderr, "alloc:%uz", (unsigned int) len);
	conf->sh = ngx_slab_alloc(conf->shpool, 1);
	// conf->sh = ngx_slab_alloc(conf->shpool, sizeof(ngx_http_ipslab_shm_t));
	fprintf(stderr, "alloc:%uz", (unsigned int) len);
	if (conf->sh == NULL) {
		fprintf(stderr, "%s", "conf->sh == NULL");
		return NGX_ERROR;
	}
	fprintf(stderr, "%s", "before conf->shpool->data");
	conf->shpool->data = conf->sh;
	fprintf(stderr, "%s", "before ngx_rbtree_init");
	ngx_rbtree_init(&conf->sh->rbtree, &conf->sh->sentinel,
			ngx_rbtree_insert_value);

	fprintf(stderr, "%s", "before ngx_queue_init");
	ngx_queue_init(&conf->sh->queue);

	len = sizeof(" in ipslab \"\"") + shm_zone->shm.name.len;

	conf->shpool->log_ctx = ngx_slab_alloc(conf->shpool, len);
	if (conf->shpool->log_ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_sprintf(conf->shpool->log_ctx, " in ipslab \"%V\"%z",
			&shm_zone->shm.name);
	fprintf(stderr, "alloc:%uz", (unsigned int) len);

	return NGX_OK;
}

static char * ngx_http_ipslab_createmem(ngx_conf_t *cf, ngx_command_t *cmd,
		void *conf) {
	ngx_str_t *value;
	ngx_http_ipslab_conf_t *mconf;

	ngx_shm_zone_t *shm_zone;
	ngx_str_t slabname = ngx_string("ip_slab_shm");

	value = cf->args->elts;
	mconf = (ngx_http_ipslab_conf_t *) conf;
	if (cf->args->nelts > 1) {
		//将字符串转为整形
		mconf->shmsize_int = ngx_atoi(value[1].data, value[1].len);
		if (mconf->shmsize_int == NGX_ERROR) {
			return "transform from str to int fail";
		}
	}

	shm_zone = ngx_shared_memory_add(cf, &slabname,
			mconf->shmsize_int * ngx_pagesize, &ngx_http_ipslab_module);
	fprintf(stderr, "ngx_pagesize:%d\r\n", (int) ngx_pagesize);
	fprintf(stderr, "ngx_http_ipslab_shm_init:%s\r\n", (char *) shm_zone);
	fprintf(stderr, "203\r\n");

	if (NULL == shm_zone) {
		fprintf(stderr, "%s", "(NULL == shm_zone)");
		return NGX_CONF_ERROR ;
	}
	//fprintf(stderr, "ngx_http_ipslab_createmem:%d\r\n",(uint)&shm_zone);
	shm_zone->init = ngx_http_ipslab_shm_init;
	shm_zone->data = mconf;
	ngx_log_error(NGX_LOG_DEBUG, cf->log, 0,
				"sxx-log-ngx_http_ipslab_createmem:]");
		fprintf(stderr, "sxx-fpf-ngx_http_ipslab_createmem:]");
	fprintf(stderr, "221\r\n");

	return NGX_CONF_OK;

}

/**/
static ngx_int_t ngx_http_ipslab_init(ngx_conf_t *cf)
//static ngx_int_t ngx_http_ipslab_init(ngx_conf_t *cf, EC_KEY* key, u_char* retID)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf; //只有main级别的

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (NULL == h) {
		return NGX_ERROR;
	}
	*h = ngx_http_ipslab_handler;
	return NGX_OK;
}
/*ngx_int_t ipslab_print_EC_KEY(EC_KEY* key)
{
	//if(key->meth == NULL) fprintf(stderr,"key->meth == NULL");
	return 1;

}*/
ngx_int_t ipslab_encrypt_mssg(u_char* mssg,u_char* encrptMssg){
	//参数：要加密的原信息messg，用来存放加密后信息的encrptMssg
	//

	 unsigned char md[16];
	 int i;

	 char tmp[3];
	 ngx_memset(tmp,'\0',3);
	 MD5(mssg,strlen((char*)mssg),md);
	 for (i = 0; i < 16; i++){
	         sprintf(tmp,"%2.2x",md[i]);

	         strcat((char*)encrptMssg,tmp);
	     }
	 fprintf(stderr,"ipslab_encrypt_mssg:encrptMssg:%s]\r\n",encrptMssg);
	 fprintf(stderr,"ipslab_encrypt_mssg:mssg:%s]\r\n",mssg);

	      return 1;
}
ngx_int_t ipslab_func_ID_getnext_update_slab(u_char* slab_ID,u_char* next_ID) {

	//利用slab_ID生成next_ID
	ipslab_encrypt_mssg(slab_ID,next_ID);
	//更新slab_ID。从next_ID 拷贝n个到slab_ID
	ngx_memcpy(slab_ID,next_ID,ENCRPT_ID_SIZE);
	return 1;
}

ngx_int_t ipslab_func_IDnew(u_char* encryptedID) {
	//参数： 经过加密的encryptedID。
	//1.以时间作为原始信息mssg，2.加密得到encryptedID

	u_char tmpID[ENCRPT_ID_SIZE+1];
	//1.以时间作为原始信息mssg
	ngx_time_t *tp;
	ngx_msec_t now;	  //本质是ngx_uint_t;
	tp = ngx_timeofday();
	now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
	fprintf(stderr, "mesc-now:%d", (int) now);
	//itoa并不是一个标准的C函数，它是Windows特有的，如果要写跨平台的程序，请用sprintf
	sprintf((char *)tmpID,"%d",(int)now);
fprintf(stderr,"sxx-fpf-ipslab_func_IDnew: tmpID: %s]",tmpID);
	//2.加密得到encryptedID


ipslab_func_ID_getnext_update_slab(tmpID, encryptedID);
	fprintf(stderr,"sxx-fpf-ipslab_func_IDnew: encryptedID: %s]",encryptedID);

	return 1;
}

static ngx_int_t ngx_abstract_hxID(ngx_http_request_t *r, ngx_int_t* begin_pos,ngx_int_t* end_pos)
{
	//find_pos是hxID=xxxx中xxxx开始的位置
	ngx_int_t isAuth = -1;
	ngx_str_t match = ngx_string("hxID=");
	ngx_str_t hxID_str;

	//ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-ngx_abstract_hxID r->args:%V\r\n",r->args);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-ngx_abstract_hxID &r->args:%V\r\n", &(r->args));

	//对args的每个字段进行比较
	ngx_uint_t i = 0;
	if (r->args.len >= match.len) {
		for (; i <= r->args.len - match.len; i++) {
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-i:%ui\r\n",
					i);
			if (0 == ngx_strncasecmp(r->args.data + i, match.data, match.len)) {
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
						"0 == ngx_strncasecmp\r\n,i:%ui\r\n", i);
				if (i != 0 && *(r->args.data + i - 1) != '&') {
					continue;
				}
				isAuth = i + match.len;
				break;
			}
		}
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-Auth:%ui\r\n",
				isAuth);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-r->args.len:%ui\r\n", r->args.len);

		if (-1 != isAuth) {
			for (i = isAuth; i < r->args.len; i++) {

				if (*(r->args.data + i) == '&') {
					break;
				}
			}
			hxID_str.len = i - isAuth;
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"sxx-hxID_str.len:%ui\r\n", hxID_str.len);
			/*ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"sxx-*(r->args.data+r->args.len):%s]\r\n",
					*(r->args.data));*/
			hxID_str.data = ngx_palloc(r->pool, hxID_str.len);
			ngx_memcpy(hxID_str.data, r->args.data + isAuth, i - isAuth);
			*begin_pos = isAuth;
			*end_pos = i;

			fprintf(stderr, "ngx_abstract_hxID data:try");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
								"sxx-ngx_abstract_hxID data str:%V\r\n", &hxID_str);
			/*
			//fprintf(stderr, "ngx_abstract_hxID.len:%d\r\n",len);
			hxID_tmp = ngx_atoi(hxID_str.data, hxID_str.len);
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"sxx-ngx_abstract_hxID data int:%i\r\n", hxID_tmp);*/
			return 1;//hxID_tmp;
		}
	}

	return -1;
}
/* 删除最后一个节点*/
static void ngx_http_ipslab_delete_one(ngx_http_request_t *r,
		ngx_http_ipslab_conf_t *conf) {

	ngx_queue_t *q;
	ngx_rbtree_node_t *node;
	ngx_http_ipslab_node_t *lr;

	if (ngx_queue_empty(&conf->sh->queue)) {
		return;
	}

	q = ngx_queue_last(&conf->sh->queue);

	lr = ngx_queue_data(q, ngx_http_ipslab_node_t, queue);

	node = (ngx_rbtree_node_t *) ((u_char *) lr
			- offsetof(ngx_rbtree_node_t, data));

	ngx_queue_remove(q);

	ngx_rbtree_delete(&conf->sh->rbtree, node);

	ngx_slab_free_locked(conf->shpool, node);

}
static ngx_int_t ngx_http_ipslab_lookup_no_update(ngx_http_request_t *r,
		ngx_http_ipslab_conf_t *conf, ngx_uint_t ip_int,u_char* slab_ID_out,u_char* last_slab_ID_out)
//执行查找功能，找到的结果使用参数slab_ID_out和old_slab_ID_out向外传递
//slab_ID和old_slab_ID 都是下发给浏览器的ID，鉴于浏览器端ID经过md5算法后在请求中携带的hxID，向外传递的slab_ID_out=md5(slab_ID_out);
//old_slab_ID_out = md5(slab_ID_out).
//成功返回1，失败返回0
{


	ngx_rbtree_node_t *node, *sentinel;
	ngx_http_ipslab_node_t *lr;

	node = conf->sh->rbtree.root;
	sentinel = conf->sh->rbtree.sentinel;

	while (node != sentinel) {
		if (ip_int < node->key) {
			node = node->left;
			continue;
		}

		if (ip_int > node->key) {
			node = node->right;
			continue;
		}
		if (ip_int == node->key)	  //找到节点
			{
			lr = (ngx_http_ipslab_node_t *) &node->data;
			ipslab_encrypt_mssg(lr->slab_ID,slab_ID_out);
			ipslab_encrypt_mssg(lr->last_slab_ID,last_slab_ID_out);
			return 1;
		}
	}
	//没有找到该节点
	return 0;

}
static ngx_int_t ngx_http_ipslab_lookup_ID_update_forward(ngx_http_request_t *r,
		ngx_http_ipslab_conf_t *conf, ngx_uint_t ip_int,
		u_char* server_ID)
//--hash是ip的hash
//用server_ID 向外传出找到slab_ID经过MD5的new_ID
{

	size_t size;
	ngx_rbtree_node_t *node, *sentinel;
	ngx_http_ipslab_node_t *lr;


	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_lookup_ID_update_forward:now I am here L414\r\n");
	//ngx_atoi(r->args->data,sizeof(ngx_int_t));
	node = conf->sh->rbtree.root;
	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_lookup_ID_update_forward:now I am here L417\r\n");
	sentinel = conf->sh->rbtree.sentinel;
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
						"sxx-log-ngx_http_ipslab_lookup_ID_update_forward:now I am here");

	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_lookup_ID_update_forward:now I am here L422\r\n");
	while (node != sentinel) {
		if (ip_int < node->key) {
			node = node->left;
			continue;
		}

		if (ip_int > node->key) {
			node = node->right;
			continue;
		}
		if (ip_int == node->key)	  //只要IP存在，不管ID是否匹配都要更新ID
			{
			lr = (ngx_http_ipslab_node_t *) &node->data;
			ngx_queue_remove(&lr->queue);
			ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
			//即时更新并返回更新后ID

			ngx_log_error(8, r->connection->log, 0,	"sxxx-ip_int == node->key,lr->slab_ID before IDnext():%s", lr->slab_ID);
			//lr->slab_ID=ngx_func_IDnext(id_tmp);
			//先把上一次下发的slab_ID保存到last_slab_ID，在ipslab_func_ID_getnext_update_slab
			//中更新slab中的slab_ID，这将是这次请求应该匹配的ID，也是响应中要下发给浏览器的ID，为方便这次比较，
			//用server_ID从slab中传出来。
			ngx_memcpy(lr->last_slab_ID,lr->slab_ID,strlen((char*)lr->slab_ID));//保存
			ipslab_func_ID_getnext_update_slab(lr->slab_ID,server_ID);//更新

			ngx_log_error(8, r->connection->log, 0,	"sxxx-ip_int == node->key,lr->slab_ID after IDnext():%s", lr->slab_ID);


			return 1;
		}

		//测试
		// if(lr==NULL) printf("printf:%s","OK");

	}

	size = offsetof(ngx_rbtree_node_t,
			data) + sizeof(ngx_http_ipslab_node_t)+ENCRPT_ID_SIZE+1;

	node = ngx_slab_alloc_locked(conf->shpool, size);

	while (node == NULL) {
		//删除最后一个,留出一点分配空间
		ngx_http_ipslab_delete_one(r, conf);
		node = ngx_slab_alloc_locked(conf->shpool, size);
	}

	node->key = ip_int;


	lr = (ngx_http_ipslab_node_t *) &node->data;

	// retNewID = (u_char *)malloc(ENCRPT_ID_SIZE);free(retNewID);
	fprintf(stderr,"in func lookup,before IDnew, server_ID:%s]",server_ID);
	ipslab_func_IDnew(server_ID);
	fprintf(stderr,"sxx-fpf-ngx_http_ipslab_lookup_ID_update_forward:after IDnew, server_ID:%s]",server_ID);

	//在第一次分配出(IP,ID)的node时，last_slab_ID就置为null
	memset(lr->last_slab_ID,'\0',sizeof(lr->last_slab_ID));//保存
	ngx_memcpy(lr->last_slab_ID,server_ID,ENCRPT_ID_SIZE);
	ngx_memcpy(lr->slab_ID,server_ID,ENCRPT_ID_SIZE);//
	lr->pass_count = 0;
//ngx_memcpy(lr->slab_ID,retNewID,ENCRPT_ID_SIZE);

	//ngx_log_error(8, r->connection->log, 0, "sxxx-IDnew-in lookup:%i",(int )lr->slab_ID);

	// lr->ip_int=ngx_http_variable_binary_remote_addr();
	// r->connection->addr_text;
	//ngx_memcpy(lr->data, ip, len);

	ngx_rbtree_insert(&conf->sh->rbtree, node);

	ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
	//memcpy(server_ID, lr->slab_ID, ENCRPT_ID_SIZE);
	return 1;
}/**/
static void ipslab_post_handler(ngx_http_request_t * r) {

	fprintf(stderr, "%s", "sxx-fpf-mytest_post_handler");
	//如果没有返回200则直接把错误码发回用户
	if (r->headers_out.status != NGX_HTTP_OK) {
		fprintf(stderr, "%s", "ipslab_post_handler r->headers_out.status != NGX_HTTP_OK");
		ngx_http_finalize_request(r, r->headers_out.status);
		return ;
	}
	//当前请求是父请求，直接取其上下文
	ngx_http_ipslab_ctx_t* myctx = ngx_http_get_module_ctx(r,
			ngx_http_ipslab_module);

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-log-mytest_post_handlerctx %s", myctx->out_ctx->buf->pos);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-log-mytest_post_handlerctx %d", myctx->out_ctx->buf->last-myctx->out_ctx->buf->pos);
	fprintf(stderr, "%s", "sxx-fpf-mytest_post_handler");
	 r->headers_out.status = NGX_HTTP_OK;
	ngx_int_t ret = ngx_http_send_header(r);
	ret = ngx_http_output_filter(r, myctx->out_ctx);

	//注意，这里发送完响应后必须手动调用ngx_http_finalize_request
	//结束请求，因为这时http框架不会再帮忙调用它
	ngx_http_finalize_request(r, ret);
	return ;

}
/*static void ipslab_post_handler_for_nonhtml(ngx_http_request_t * r) {

	fprintf(stderr, "%s", "sxx-fpf-mytest_post_handler");
	//如果没有返回200则直接把错误码发回用户
	if (r->headers_out.status != NGX_HTTP_OK) {
		fprintf(stderr, "%s", "ipslab_post_handler r->headers_out.status != NGX_HTTP_OK");
		ngx_http_finalize_request(r, r->headers_out.status);
		return ;
	}
	//当前请求是父请求，直接取其上下文
	ngx_http_ipslab_ctx_t* myctx = ngx_http_get_module_ctx(r,
			ngx_http_ipslab_module);

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-log-mytest_post_handlerctx %s", myctx->out_ctx->buf->pos);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-log-mytest_post_handlerctx %d", myctx->out_ctx->buf->last-myctx->out_ctx->buf->pos);
	fprintf(stderr, "%s", "sxx-fpf-mytest_post_handler");
	// system("C:\\Users\\shao\\Desktop\\JsPTest\\run.bat");
	// system("C:/Users/shao/Desktop/JsPTest/run.bat");
	// system("C://Users//shao//Desktop//JsPTest//run.bat");
	//设置Content-Type，注意汉字编码新浪服务器使用了GBK
	// 	static ngx_str_t type = ngx_string("text/plain; charset=GBK");
	// r->headers_out.content_type = type;
	// r->headers_out.status = NGX_HTTP_OK;
	 //sssssss
	// r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
	ngx_int_t ret = ngx_http_send_header(r);
	// = ngx_http_output_filter(r, &out);
	ret = ngx_http_output_filter(r, myctx->out_ctx);

	//注意，这里发送完响应后必须手动调用ngx_http_finalize_request
	//结束请求，因为这时http框架不会再帮忙调用它
	ngx_http_finalize_request(r, ret);
	return ;

}*/

/*ngx_int_t copy_a_node_element(const GumboElement* srcnode,GumboElement* dstnode){
	dstnode->tag = srcnode->tag;

	dstnode->end_pos->column = srcnode->end_pos->column;
	dstnode->end_pos->line = srcnode->end_pos->line;
	dstnode->end_pos->offset = srcnode->end_pos->offset;


	dstnode->

}*/


static GumboNode* find_body_node(const GumboNode* root) {
//

  const GumboVector* root_children = &root->v.element.children;
  GumboNode* body = NULL;
  for (unsigned int i = 0; i < root_children->length; ++i) {
    GumboNode* child = root_children->data[i];
    if (child->type == GUMBO_NODE_ELEMENT &&
        child->v.element.tag == GUMBO_TAG_BODY) {
      body = child;
      break;
    }
  }
return body;
}
static GumboSourcePosition* find_end_pos(GumboNode* node){
	return &(node->v.element.end_pos);

}
static ngx_int_t insert_str(ngx_buf_t* buf,ngx_uint_t offset,ngx_str_t str){
	//u_char* p_oldpos = buf->pos;
	u_char* p_oldlast = buf->last;
	ngx_uint_t remain_len = buf->last -buf->pos-offset;
	char* p_tmp = malloc(remain_len);
	memcpy(p_tmp,buf->pos+offset,remain_len);//将后半段保留下来

	buf->last = p_oldlast+str.len;
	ngx_memcpy(buf->pos+offset,str.data,str.len);//
	ngx_memcpy(buf->pos+offset+str.len,p_tmp,remain_len);
	return 1;

}
//可迭代的检测某个节点并其子节点是否有链接ngx_array_t<packed_position>* link_vector
ngx_uint_t find_links(const GumboNode* node,ngx_uint_t* count)
{
	ngx_uint_t* p_count=count;

	if (node->type != GUMBO_NODE_ELEMENT) {
	    return 0;
	  }
	//char href_str[]="href";
	fprintf(stderr, "%s","sxx-fpf-in find links");

	 if( node->v.element.tag == GUMBO_TAG_LINK || node->v.element.tag == GUMBO_TAG_IMG ||node->v.element.tag == GUMBO_TAG_SCRIPT){
		 fprintf(stderr, "%s",
			   		"sxx-fpf-find links a and link");
		*p_count = (*p_count)+1;
		 fprintf(stderr, "%s",
				   		"sxx-fpf-find links a and link after 1for");
	}


	 fprintf(stderr, "%s",	"sxx-fpf-find links after 2if");
	if(node->v.element.children.length>0){
	const GumboVector* children = &(node->v.element.children);
		fprintf(stderr, "%s",
							   		"sxx-fpf-find links have sub tree");
		for(unsigned int i=0;i<children->length;i++)
		{
			find_links(children->data[i],p_count);
		}
	}else{
		fprintf(stderr, "%s","sxx-fpf-find links no sub tree");
	}
	return 1;
}
//子请求结束时的回调方法
//1.计算总size; 2.分配大块内;3.调用gumbo或duktape进行处理。
static ngx_int_t ipslab_subrequest_post_handler(ngx_http_request_t *r,
		void *data, ngx_int_t rc) {



	//当前请求r是子请求，它的parent成员就指向父请求
	ngx_http_request_t *pr = r->parent;
	pr->headers_out.status = r->headers_out.status;
	pr->headers_out.content_type = r->headers_out.content_type;


	GumboOutput* output;
	const char* content;	//int length;
	 //  int duktape_temp;
	//如果返回NGX_HTTP_OK（也就是200）意味着访问第三方服务器成功，接着将开始解析http包体
	fprintf(stderr, "%s",
				"sxx-fpf-mytest_subrequest_post_handler have include gumbo");
	if (r->headers_out.status == NGX_HTTP_OK) {
		fprintf(stderr, "%s","sxx-fpfsubrequest_postNGX_HTTP_OK");
		//在不转发响应时，buffer中会保存着上游服务器的响应。特别是在使用
		//反向代理模块访问上游服务器时，如果它使用upstream机制时没有重定义
		//input_filter方法，upstream机制默认的input_filter方法会试图
		//把所有的上游响应全部保存到buffer缓冲区中
		ngx_buf_t* pRecvBuf = &r->upstream->buffer;
		ngx_http_ipslab_ctx_t* out = (ngx_http_ipslab_ctx_t *) data;
		size_t len = pRecvBuf->last - pRecvBuf->pos;
		pRecvBuf->last = pRecvBuf->pos + len;
		pRecvBuf->last_buf = 1;
		out->out_ctx->buf = pRecvBuf;
		out->out_ctx->next = NULL;
		ngx_str_t html_rspnd = ngx_string("text/html");
		//ngx_str_t js_rspnd = ngx_string("text/javascript");
		if(0 == ngx_strcmp(&(r->headers_out.content_type), &html_rspnd)){
			fprintf(stderr, "%s",
							"sxx-fpf-mytest_subrequest_post_handler ngx_strcmp(type)");
			content = (char *)pRecvBuf->pos;
		   output = gumbo_parse_with_options(&kGumboDefaultOptions,content, len);
			   ngx_uint_t tmp_count;//留出请求资源（js,css,png等）的次数。
			   	find_links(output->root,&tmp_count);
				 ngx_str_t insrt_str_part1= ngx_string("<input id='hxID' style='display:none;' value='");
				 ngx_str_t insrt_str_part3= ngx_string("'></input>");

				 ngx_str_t insrt_str_part2 = ngx_string(out->hxID.data);
				// ngx_buf_t* new_buf = ngx_create_temp_buf(pr->pool,insrt_str_part1.len+insrt_str_part2.len+insrt_str_part3.len);
				 ngx_str_t new_block;
				 new_block.len= insrt_str_part1.len+ENCRPT_ID_SIZE+insrt_str_part3.len;
				 new_block.data = ngx_palloc(r->pool, new_block.len);
				 ngx_snprintf(new_block.data,new_block.len,"%V%s%V",&insrt_str_part1,insrt_str_part2.data,&insrt_str_part3);
				 GumboSourcePosition* body_end = (GumboSourcePosition*)find_end_pos((GumboNode*)find_body_node(output->root));
				 insert_str(pRecvBuf,body_end->offset,new_block);
				 gumbo_destroy_output(&kGumboDefaultOptions, output);
		}else {//非HTML响应
			fprintf(stderr, "%s","sxx-response not HTML");

	    pr->headers_out.content_length_n = r->headers_out.content_length_n;
	    pr->headers_out.content_offset = r->headers_out.content_offset;
	    fprintf(stderr, "sxx-NOHTML length %ld",pr->headers_out.content_length_n);


		}
	}else{//
		fprintf(stderr, "%s","sxx-fpf-mytest_subrequest_post_handler  r->headers_notOK");

	}

		//这一步很重要，设置接下来父请求的回调方法
		pr->write_event_handler = ipslab_post_handler;

		return NGX_OK;

}

static ngx_uint_t ipslab_ip_atoui(ngx_str_t str_ip)
{
	ngx_uint_t uint_ip=0;
	struct in_addr addr;

 char* char_ip = malloc((str_ip.len+1)*sizeof(char));
 ngx_memcpy(char_ip,str_ip.data,str_ip.len);
 *(char_ip+str_ip.len) ='\0' ;
	    if(inet_aton(char_ip,&addr))
	    {
	        uint_ip = ntohl(addr.s_addr);
	    }
	    return uint_ip;

}
/*static ngx_int_t ngx_http_ipslab_input_filter(void *data, ssize_t bytes){

	return
}*/
//handle方法，
ngx_buf_t* build_content_response(ngx_http_request_t *r,const char* ID_frm_srvr){
	//构造一个页面，含有原请求的url，同时 注入ID
	//r:1.在r->pool 中分配buf，2.使用r->uri
	ngx_buf_t *b;
	ngx_int_t maxlen;
	ngx_str_t str0 = ngx_string("<html>\r\n<body>\r\n<h1>A Fail page</h1><div>a page to revisit visit this website,please click 'TRY AGAIN' to start</div>\r\n");
	ngx_str_t str1 = ngx_string("<script src=\"https://cdnjs.cloudflare.com/ajax/libs/blueimp-md5/2.10.0/js/md5.min.js\"></script>");
	ngx_str_t str2 = ngx_string("<a id = 'OneHref' href= '");
	//ngx_str_t tmp_host = ngx_string("127.0.0.1:80");
	ngx_str_t str4 = ngx_string("'>TRY AGAIN</a>\r\n<input id='hxID' style='display:none;' value='");
	ngx_str_t str5;
		str5.len = ngx_strlen(ID_frm_srvr);
		str5.data = ngx_palloc(r->pool,str5.len);
		ngx_memcpy(str5.data,ID_frm_srvr,str5.len);
	ngx_str_t str6 =ngx_string("'></input>\r\n</body>\r\n</html>");
	maxlen = str0.len + str1.len + str2.len+r->uri.len + str4.len +str5.len +str6.len;
	b = ngx_create_temp_buf(r->pool, maxlen);
	if (b == NULL) {
				return NULL;
	}
	ngx_snprintf(b->pos, maxlen, "%V%V%V%V%V%V%V", &str0,&str1,&str2, &r->uri,&str4,
			&str5, &str6);
	 //注意，一定要设置好last指针
	b->last = b->pos + maxlen;
	//声明这是最后一块缓冲区
	b->last_buf = 1;
	//构造发送时的ngx_chain_t结构体
	return b;
}
static bool is_html_request(ngx_str_t uri){
	fprintf(stderr, "sxx-func is_html_request");
	fprintf(stderr, "sxx-args:[%s]\n",uri.data);
	ngx_str_t match = ngx_string("html");
	u_char* p=ngx_strlcasestrn(uri.data,uri.data+uri.len,match.data,match.len-1);
	if(p){
		fprintf(stderr, "sxx-%s is_html_request",uri.data);
		return true;
	}
	fprintf(stderr, "sxx-%s is not html_request",uri.data);
	return false;
}
static ngx_int_t ngx_http_ipslab_handler(ngx_http_request_t *r) {
	//1.从uri中提取出ID；2.用ip为关键字访问一次共享内存，节点存在则更新或者节点不存在则分配，无论如何子函数返回最新的ID。
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-ngx_http_ipslab_handler:before ngx_abstract_hxID");
	fprintf(stderr, "sxx-ngx_http_ipslab_handler:before ngx_abstract_hxID");
	u_char* client_ID;
	u_char* server_ID_now_used;
	ngx_int_t id_begin_pos=0;
	ngx_int_t id_end_pos=0;
	ngx_int_t clientid_now_len;
	ngx_uint_t ip_int;
	// ngx_str_t tmpstr = ngx_string("?hxID=");
	// ngx_int_t ID_POS_MIN=tmpstr.len;
	ngx_int_t id_pos = ID_POS_MIN - 1;   //url中hxID=号后面开始的位置，初始值为-1.
	ngx_http_ipslab_conf_t *conf;
	ngx_http_ipslab_ctx_t* myctx;
	ngx_int_t rc;
	//给client_ID 分配内存并填充内容
	client_ID = ngx_palloc(r->pool, ENCRPT_ID_SIZE+1);
	server_ID_now_used = ngx_palloc(r->pool, ENCRPT_ID_SIZE+1);
	ngx_memset(server_ID_now_used,'\0',ENCRPT_ID_SIZE+1);
	server_ID_now_used[ENCRPT_ID_SIZE] = '\0';
	ngx_abstract_hxID(r, &id_begin_pos,&id_end_pos);
	clientid_now_len =  id_end_pos-id_begin_pos;
	ngx_memcpy(client_ID, r->args.data + id_begin_pos,clientid_now_len);
	client_ID[clientid_now_len] ='\0' ;


	ip_int = ipslab_ip_atoui(r->connection->addr_text);

	conf = ngx_http_get_module_main_conf(r, ngx_http_ipslab_module);
	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_handler: 667");
	fprintf(stderr, "sxx-bool is_html_R-r->uri:[%s]\r\n",r->uri.data);
	bool is_html_R = is_html_request(r->uri);


	if(is_html_R){//使用
		fprintf(stderr, "sxx-is html request");
			ngx_shmtx_lock(&conf->shpool->mutex);
			fprintf(stderr, "sxx-fpf-ngx_http_ipslab_handler: lock shmtx");

			ngx_http_ipslab_lookup_ID_update_forward(r, conf, ip_int, server_ID_now_used); //遍历查找，有ip的产生nextID，并返回用于比较。没有ID的添加新纪录，并返回ID
			fprintf(stderr, "sxx-fpf-ngx_http_ipslab_handler: after lookup serverID:%s]",server_ID_now_used);
			ngx_shmtx_unlock(&conf->shpool->mutex);

	}else{
		fprintf(stderr, "sxx-is not html request");
		//如果是非HTML文件请求。则与last_slab_ID的md5比较。额外预备了server_another_slab_ID是供后面迭代开发使用
			u_char* server_another_slab_ID = ngx_palloc(r->pool, ENCRPT_ID_SIZE+1);
			ngx_memset(server_another_slab_ID,'\0',ENCRPT_ID_SIZE+1);

			ngx_shmtx_lock(&conf->shpool->mutex);
			ngx_http_ipslab_lookup_no_update(r, conf, ip_int, server_another_slab_ID,server_ID_now_used);
			fprintf(stderr, "sxx-after no update,server_another_slab_ID:%s,server_ID_now_used:%s.",server_another_slab_ID,server_ID_now_used);
			ngx_shmtx_unlock(&conf->shpool->mutex);
	}


	if (0 == ngx_memcmp(server_ID_now_used, client_ID,ENCRPT_ID_SIZE)) {
		fprintf(stderr, "sxx-client_ID == server_ID\r\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-sxx-client_ID:%s, == server_ID:%s\r\n", client_ID,
				server_ID_now_used);
		//创建http上下文

		myctx = ngx_http_get_module_ctx(r, ngx_http_ipslab_module);
		// ngx_buf_t *b ;
		if (myctx == NULL) {
			myctx = ngx_palloc(r->pool, sizeof(ngx_http_ipslab_ctx_t));
			if (myctx == NULL) {
				return NGX_ERROR;
			}
			// b = ngx_create_temp_buf(r->pool,50);
			fprintf(stderr, "%s", "I am here");
			myctx->out_ctx = ngx_palloc(r->pool, sizeof(ngx_chain_t));
			//= ngx_string(server_ID);
			ngx_str_set(&myctx->hxID,server_ID_now_used);
			/*    myctx->out_ctx->buf=b;
			 myctx->out_ctx->next=NULL;*/
			//将上下文设置到原始请求r中
			fprintf(stderr, "%s", "I am here");
			ngx_http_set_ctx(r, myctx, ngx_http_ipslab_module);
		}

		// ngx_http_post_subrequest_t结构体会决定子请求的回调方法，参见5.4.1节
		ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool,
				sizeof(ngx_http_post_subrequest_t));
		if (psr == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		//设置子请求回调方法为mytest_subrequest_post_handler
		psr->handler = ipslab_subrequest_post_handler;

		//data设为myctx上下文，这样回调mytest_subrequest_post_handler
		//时传入的data参数就是myctx
		psr->data = myctx;

		//子请求的URI前缀是/list，这是因为访问新浪服务器的请求必须是类
		//似/list=s_sh000001这样的URI，这与5.6.1节在nginx.conf中
		//配置的子请求location中的URI是一致的
		ngx_str_t sub_prefix = ngx_string("/tmpdir");
		ngx_str_t sub_location;

		if (r->args.data == NULL) {
			sub_location.len = sub_prefix.len + r->uri.len;/*******/
			sub_location.data = ngx_palloc(r->pool, sub_location.len);
			ngx_snprintf(sub_location.data, sub_location.len, "%V%V",
					&sub_prefix, &r->uri);
		} else {
			ngx_str_t tmp_args;
			tmp_args.len = id_pos - 5;
			tmp_args.data = ngx_palloc(r->pool, tmp_args.len);
			ngx_memcpy(tmp_args.data, r->args.data, tmp_args.len);

			sub_location.len = sub_prefix.len + r->uri.len + tmp_args.len;/*******/
			sub_location.data = ngx_palloc(r->pool, sub_location.len);
			ngx_snprintf(sub_location.data, sub_location.len, "%V%V%V",
					&sub_prefix, &r->uri, &tmp_args);

		}

		/* ngx_str_t sub_location;
		 sub_location.len =  r->args.len;
		 sub_location.data = ngx_palloc(r->pool, sub_location.len);
		 ngx_snprintf(sub_location.data, sub_location.len,
		 "%V", &r->args);*/

		//sr就是子请求
		ngx_http_request_t *sr;
		//调用ngx_http_subrequest创建子请求，它只会返回NGX_OK
		//或者NGX_ERROR。返回NGX_OK时，sr就已经是合法的子请求。注意，这里
		//的NGX_HTTP_SUBREQUEST_IN_MEMORY参数将告诉upstream模块把上
		//游服务器的响应全部保存在子请求的sr->upstream->buffer内存缓冲区中
		fprintf(stderr, "sxx-fpf-ngx_http_mytest_handler sub_location: %s\r\n",
				sub_location.data);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-log-ngx_http_mytest_handler sub_location:%V\r\n",
				sub_location);
		if(is_html_R){
			rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr,
				NGX_HTTP_SUBREQUEST_IN_MEMORY);
		}else{
			rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr,0);
		}
		if (rc != NGX_OK) {
					return NGX_ERROR;
				}
        //sr->upstream->process_header =
		// 当为1时，根据上游服务器返回的响应头部，动态决定是以上游网速优先，还是下游网速优先
		//sr->upstream->conf->change_buffering=1;
		//sr->
		//8888 sr->upstream->input_filter =ngx_http_ipslab_input_filter;
		//sr->upstream->buffering = 1;
		//sr->upstream->input_filter
		//sr->upstream->bufs.size = ngx_pagesize;


		if (r->out == NULL) {
			/*r->out->buf = ngx_create_temp_buf(r->pool,200);
			 r->out->next = NULL;*/
			fprintf(stderr, "%s",
					"sxx-fpf-ngx_http_mytest_handler r->out->buf== NULL");
		} else {
			fprintf(stderr, "%s",
					"sxx-fpf-ngx_http_mytest_handler  out->buf != null");
		}
		//必须返回NGX_DONE，理由同upstream
		return NGX_DONE;

		//return NGX_DECLINED;
	} else {//当ID不匹配就直接返回构造的响应
		fprintf(stderr, "%s",
							"sxx-ID not match,build a fail page");
		ngx_int_t lclrc;//供局部使用的rc
		//必须是GET或者HEAD方法，否则返回405 Not Allowed
		if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
		{
			return NGX_HTTP_NOT_ALLOWED;
		}

	    //构造好响应内容
	    ngx_buf_t* b = build_content_response(r,(char*)server_ID_now_used);
	    if(b==NULL){
	    	return NGX_HTTP_INTERNAL_SERVER_ERROR;
	    }
	    //丢弃请求中的包体
	    lclrc = ngx_http_discard_request_body(r);
		if (lclrc != NGX_OK)
		{
			return lclrc;
		}

	    //设置返回的Content-Type。注意，ngx_str_t有一个很方便的初始化宏
	    ngx_str_t type = ngx_string("text/html");
	    //设置返回状态码
	    r->headers_out.status = NGX_HTTP_OK;
	    //响应包是有包体内容的，所以需要设置Content-Length长度
	    off_t response_len = b->last-b->pos;
	    r->headers_out.content_length_n = response_len;
	    //设置Content-Type
	    r->headers_out.content_type = type;

	    //发送http头部
	    lclrc = ngx_http_send_header(r);
	    if (lclrc == NGX_ERROR || lclrc > NGX_OK || r->header_only)
	    {
	        return lclrc;
	    }

		ngx_chain_t out;
		out.buf = b;
		out.next = NULL;
		return ngx_http_output_filter(r, &out);
	}
	return NGX_OK;
}

