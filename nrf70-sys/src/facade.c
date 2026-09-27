/* SPDX-License-Identifier: BSD-3-Clause */
#include "nrf70_facade.h"
#include "supplicant.h"
#include "osal_ops.h"
#include "common/nrf70_bm_core.h"
#include "system/fmac_api.h"
#include "system/fmac_rx.h"
#include "common/fmac_util.h"
#include "util.h"
#include "coex.h"
#include <stdarg.h>

#define TASKLET_SLOTS 16u
#define TIMER_SLOTS 16u
#define LOCK_SLOTS 16u
#define EVENT_SLOTS 68u
#define RX_SLOTS 4u
#define TX_HEADROOM 128u
#define EAPOL_SLOTS 4u
#define EAPOL_MAX 640u
#define CONN_IE_MAX 128u

/* Connect state machine. Steps advance only in nrf70_facade_process; FMAC
 * event callbacks merely set flags. Open networks skip DERIVE/SCAN/HANDSHAKE.
 * EAPOL TX/RX use the normal FMAC data path as 0x888E Ethernet frames: this
 * nrf_wifi revision has no control-port TX command (deviation from the plan
 * text, see README). */
enum conn_state {
    CONN_IDLE = 0,
    CONN_DERIVE,      /* sliced PBKDF2 passphrase -> PMK */
    CONN_SCAN_START,  /* issue SCAN_CONNECT filtered to the target */
    CONN_SCAN_WAIT,   /* waiting for scan done + RSN IE capture */
    CONN_AUTH_START,  /* issue open-system authenticate */
    CONN_AUTH_WAIT,
    CONN_SUPP_SETUP,  /* wpa_sm setup + associate */
    CONN_ASSOC_WAIT,
    CONN_HANDSHAKE,   /* EAPOL 4-way/group handshake via wpa_sm */
    CONN_AUTHORIZED   /* controlled port authorized (or open link up) */
};

struct tasklet_slot { uint8_t used, pending; void (*fn)(unsigned long); unsigned long data; };
struct timer_slot { uint8_t used, armed; uint32_t deadline; void (*fn)(unsigned long); unsigned long data; };
struct lock_slot { uint8_t used, held; };
struct list_node { struct list_node *next, *prev; void *data; };
struct list { struct list_node *head, *tail; uint32_t len; };
struct nbuf { uint8_t *base, *data; uint32_t capacity, len, tx_token; uint8_t priority, checksum, facade_tx; };
struct rx_slot { uint16_t length; int8_t rssi; uint8_t frame[NRF70_FACADE_MAX_FRAME_LEN]; };
struct eapol_slot { uint16_t length; uint8_t src[6]; uint8_t frame[EAPOL_MAX]; };
struct conn_ctx {
    uint8_t state, security, mfp, secured, ssid_len, have_bssid;
    uint8_t bssid[6], found_bssid[6];
    uint8_t ssid[NRF70_FACADE_MAX_SSID_LEN];
    uint16_t frequency;
    uint8_t pmk[NRF70_SUPP_PMK_LEN], pmk_ready;
    uint16_t rsn_ie_len, rsnxe_len, assoc_ie_len;
    uint8_t rsn_ie[CONN_IE_MAX], rsnxe[CONN_IE_MAX];
    uint8_t assoc_ie[NRF70_SUPP_ASSOC_IE_MAX];
    uint8_t scan_fetch, scan_done, auth_ok, auth_fail, assoc_ok, assoc_fail;
    uint8_t port_authorized, teardown;
};

static const struct nrf70_facade_platform_ops *platform;
static struct tasklet_slot tasklets[TASKLET_SLOTS];
static struct timer_slot timers[TIMER_SLOTS];
static struct lock_slot locks[LOCK_SLOTS];
static struct nrf70_facade_event events[EVENT_SLOTS];
static struct rx_slot rx_slots[RX_SLOTS];
static uint8_t event_read, event_write, event_count, rx_read, rx_write, rx_count;
static uint8_t initialized, scan_active, scan_suppress, irq_pending, faulted;
static uint8_t callbacks_enabled, linked, scan_fetch_pending, scan_command_active;
static struct nbuf *tx_in_call;
static uint8_t tx_freed_in_call;
static uint16_t associated_frequency, scan_result_count, scan_max_results;
static int8_t current_rssi;
static uint32_t generation;
static struct nrf70_facade_stats counters;
static struct nrf_wifi_fmac_priv *fmac_priv;
static struct nrf_wifi_fmac_dev_ctx *fmac_dev;
static unsigned char sta_vif_idx;
static uint8_t sta_mac[6];
static struct conn_ctx conn;
static struct eapol_slot eapol_slots[EAPOL_SLOTS];
static uint8_t eapol_read, eapol_write, eapol_count;
INCBIN(_bin, nrf70_facade_fw, STR(CONFIG_NRF_WIFI_SYS_FW_BIN));
static void *irq_data;
static int (*irq_callback)(void *);
void *nrf70_os_memset(void *d, int v, size_t n);
static void conn_teardown_now(void);

static uint32_t now_us(void) { return platform && platform->now_us ? platform->now_us(platform->context) : 0; }
/* Zeroization that the optimizer must not elide; used for every buffer that
 * ever held credential, PMK, or key material. Key material is never logged. */
static void secure_zero(void *p, size_t n) { volatile uint8_t *d = p; while (n--) *d++ = 0; }
static void reset_runtime(void) { nrf70_os_memset(tasklets,0,sizeof(tasklets)); nrf70_os_memset(timers,0,sizeof(timers)); nrf70_os_memset(locks,0,sizeof(locks)); event_read=event_write=event_count=0; rx_read=rx_write=rx_count=0; irq_pending=0; faulted=0; irq_data=0; irq_callback=0; scan_active=scan_suppress=0; linked=0; callbacks_enabled=0; tx_in_call=0;tx_freed_in_call=0;scan_fetch_pending=scan_command_active=0; associated_frequency=0; scan_result_count=scan_max_results=0; current_rssi=0; fmac_priv=0; fmac_dev=0; sta_vif_idx=MAX_NUM_VIFS; secure_zero(&conn,sizeof(conn)); secure_zero(eapol_slots,sizeof(eapol_slots)); eapol_read=eapol_write=eapol_count=0; }
static void account_call(uint32_t start) { uint32_t d = now_us() - start; if (d > counters.max_c_call_us) counters.max_c_call_us = d; }
static void enqueue_event(const struct nrf70_facade_event *event, uint8_t terminal) {
    if (event_count == EVENT_SLOTS && terminal) { event_read = (uint8_t)((event_read + 1u) % EVENT_SLOTS); event_count--; counters.dropped_events++; }
    if (event_count == EVENT_SLOTS) { counters.dropped_events++; return; }
    events[event_write] = *event; event_write = (uint8_t)((event_write + 1u) % EVENT_SLOTS); event_count++;
}
/* Diagnostic text to the host (level: 0 dbg, 1 info, 2 warn, 3 err). Never
 * called with secret material. */
static void log_msg(uint8_t level, const char *msg) { if (platform && platform->log) platform->log(platform->context, level, msg); }
static void fatal(int32_t reason, const char *msg) {
    counters.fatal_errors++;
    faulted=1;
    /* May be nested inside a wpa_sm call, so only the static secret staging is
     * cleared here; wpa_sm teardown (which frees and zeroizes its own keys)
     * happens on the reset/deinit that follows every fatal. */
    nrf70_supp_clear_secrets();
    secure_zero(conn.pmk, sizeof(conn.pmk));
    if (platform && platform->fatal) platform->fatal(platform->context, reason, msg);
    struct nrf70_facade_event e = { .generation = generation, .status = reason, .kind = NRF70_FACADE_EVENT_FATAL };
    enqueue_event(&e, 1);
}

void *nrf70_os_malloc(size_t n) { void *p = platform && platform->alloc ? platform->alloc(platform->context, (uint32_t)n, 8, 0) : 0; if (!p) { counters.allocation_failures++; fatal(NRF70_FACADE_NO_MEMORY,"Wi-Fi control arena exhausted"); } return p; }
void *nrf70_os_calloc(size_t count, size_t n) { if (n && count > ((size_t)-1) / n) { counters.allocation_failures++; fatal(NRF70_FACADE_NO_MEMORY,"Wi-Fi allocation overflow"); return 0; } size_t total = count * n; void *p = platform && platform->alloc ? platform->alloc(platform->context, (uint32_t)total, 8, 1) : 0; if (!p) { counters.allocation_failures++; fatal(NRF70_FACADE_NO_MEMORY,"Wi-Fi control arena exhausted"); } return p; }
void nrf70_os_free(void *p) { if (p && platform && platform->free) platform->free(platform->context, p); }
void *nrf70_os_memcpy(void *d, const void *s, size_t n) { uint8_t *dd=d; const uint8_t *ss=s; while(n--) *dd++=*ss++; return d; }
void *nrf70_os_memset(void *d, int v, size_t n) { uint8_t *dd=d; while(n--) *dd++=(uint8_t)v; return d; }
int nrf70_os_memcmp(const void *a,const void *b,size_t n){const uint8_t*x=a,*y=b;while(n--){if(*x!=*y)return *x<*y?-1:1;x++;y++;}return 0;}
size_t nrf70_os_strlen(const char *s){size_t n=0;if(s)while(s[n])n++;return n;}
int nrf70_os_strcmp(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return (uint8_t)*a-(uint8_t)*b;}
int nrf70_os_printf(const char *fmt, ...){(void)fmt;return 0;}
static char hex(uint8_t v){return v<10?(char)('0'+v):(char)('A'+v-10);}
int nrf70_os_snprintf(char *dst,size_t n,const char *fmt,...){
    (void)fmt; va_list ap; va_start(ap,fmt); unsigned int v[6]; for(int i=0;i<6;i++)v[i]=va_arg(ap,unsigned int); va_end(ap);
    if(n<18)return -1; for(int i=0;i<6;i++){dst[i*3]=hex((uint8_t)(v[i]>>4));dst[i*3+1]=hex((uint8_t)v[i]);if(i<5)dst[i*3+2]=':';}dst[17]=0;return 17;
}

static void *mem_alloc(size_t n){return nrf70_os_malloc(n);} static void *mem_zalloc(size_t n){return nrf70_os_calloc(1,n);} static void mem_free(void*p){nrf70_os_free(p);}
static int log_drop(const char *f,va_list a){(void)f;(void)a;return 0;}
/* Minimal printf-style formatter for the nrf_wifi diagnostic logs. Covers the
 * specifiers those logs actually use (%s, %c, %d, %u, %x/%X, %p, with z/l
 * modifiers); anything else prints as '?'. Bounded output, no libc. */
static void log_fmt_put(char*buf,size_t cap,size_t*w,char c){if(*w+1<cap)buf[*w]=c;(*w)++;}
static void log_fmt_num(char*buf,size_t cap,size_t*w,unsigned long v,unsigned base,int upper){
    char tmp[2*sizeof(v)+3];unsigned i=0;
    do{unsigned d=(unsigned)(v%base);tmp[i++]=(char)(d<10?'0'+d:(upper?'A':'a')+d-10);v/=base;}while(v&&i<sizeof(tmp));
    while(i)log_fmt_put(buf,cap,w,tmp[--i]);
}
static int log_fmt(uint8_t level,const char *f,va_list a){
    char buf[160];size_t w=0;
    for(const char*p=f;*p;p++){
        if(*p!='%'){log_fmt_put(buf,sizeof(buf),&w,*p);continue;}
        p++;
        int lmod=0;
        while(*p=='l'||*p=='z'||*p=='h'||('0'<=*p&&*p<='9')||*p=='.'||*p=='-'||*p=='+'||*p==' '||*p=='#'){if(*p=='l'||*p=='z')lmod=1;p++;}
        switch(*p){
        case's':{const char*s=va_arg(a,const char*);if(!s)s="<null>";while(*s)log_fmt_put(buf,sizeof(buf),&w,*s++);break;}
        case'c':log_fmt_put(buf,sizeof(buf),&w,(char)va_arg(a,int));break;
        case'd':case'i':{long v=lmod?va_arg(a,long):va_arg(a,int);unsigned long u=(unsigned long)v;if(v<0){log_fmt_put(buf,sizeof(buf),&w,'-');u=(unsigned long)-v;}log_fmt_num(buf,sizeof(buf),&w,u,10,0);break;}
        case'u':log_fmt_num(buf,sizeof(buf),&w,lmod?va_arg(a,unsigned long):va_arg(a,unsigned int),10,0);break;
        case'x':log_fmt_num(buf,sizeof(buf),&w,lmod?va_arg(a,unsigned long):va_arg(a,unsigned int),16,0);break;
        case'X':log_fmt_num(buf,sizeof(buf),&w,lmod?va_arg(a,unsigned long):va_arg(a,unsigned int),16,1);break;
        case'p':log_fmt_num(buf,sizeof(buf),&w,(unsigned long)(uintptr_t)va_arg(a,void*),16,0);break;
        case'%':log_fmt_put(buf,sizeof(buf),&w,'%');break;
        case 0:p--;break;
        default:log_fmt_put(buf,sizeof(buf),&w,'?');break;
        }
    }
    /* Strip one trailing newline; the host log adds its own framing. */
    if(w&&w<=sizeof(buf)&&buf[w-1]=='\n')w--;
    buf[w<sizeof(buf)?w:sizeof(buf)-1]=0;
    log_msg(level,buf);
    return 0;
}
static int log_fmt_err(const char *f,va_list a){return log_fmt(3,f,a);}
static void log_diag(const char *f,...){va_list a;va_start(a,f);log_fmt(0,f,a);va_end(a);}
static unsigned int os_strlen(const void*s){return (unsigned int)nrf70_os_strlen((const char*)s);} static unsigned char rand8(void){return platform&&platform->random_u8?platform->random_u8(platform->context):0;}

static void *lock_alloc(void){for(unsigned i=0;i<LOCK_SLOTS;i++)if(!locks[i].used){locks[i].used=1;locks[i].held=0;return &locks[i];}counters.allocation_failures++;fatal(NRF70_FACADE_NO_MEMORY,"Wi-Fi lock slots exhausted");return 0;}
static void lock_free(void*p){if(p)((struct lock_slot*)p)->used=0;} static void lock_init(void*p){if(p)((struct lock_slot*)p)->held=0;}
static void lock_take(void*p){if(p)((struct lock_slot*)p)->held=1;} static void lock_rel(void*p){if(p)((struct lock_slot*)p)->held=0;}
static void lock_irq_take(void*p,unsigned long*f){if(f)*f=0;lock_take(p);} static void lock_irq_rel(void*p,unsigned long*f){(void)f;lock_rel(p);}

static void *node_alloc(void){return mem_zalloc(sizeof(struct list_node));} static void node_free(void*p){mem_free(p);} static void *node_data(void*p){return p?((struct list_node*)p)->data:0;} static void node_set(void*p,void*d){if(p)((struct list_node*)p)->data=d;}
static void *list_alloc(void){return mem_zalloc(sizeof(struct list));} static void list_free(void*p){mem_free(p);} static void list_init(void*p){if(p)nrf70_os_memset(p,0,sizeof(struct list));}
static void list_tail(void*l,void*n){struct list*x=l;struct list_node*y=n;y->next=0;y->prev=x->tail;if(x->tail)x->tail->next=y;else x->head=y;x->tail=y;x->len++;}
static void list_head(void*l,void*n){struct list*x=l;struct list_node*y=n;y->prev=0;y->next=x->head;if(x->head)x->head->prev=y;else x->tail=y;x->head=y;x->len++;}
static void *list_get_head(void*l){return l?((struct list*)l)->head:0;} static void *list_next(void*l,void*n){(void)l;return n?((struct list_node*)n)->next:0;}
static void list_del(void*l,void*n){struct list*x=l;struct list_node*y=n;if(y->prev)y->prev->next=y->next;else x->head=y->next;if(y->next)y->next->prev=y->prev;else x->tail=y->prev;y->next=y->prev=0;if(x->len)x->len--;}
static unsigned int list_len(void*l){return l?((struct list*)l)->len:0;}

static void *nbuf_alloc(unsigned int size){struct nbuf*n=mem_zalloc(sizeof(*n));if(!n)return 0;n->base=mem_alloc(size);if(!n->base){mem_free(n);return 0;}n->data=n->base;n->capacity=size;counters.nbuf_in_use++;if(counters.nbuf_in_use>counters.nbuf_high_water)counters.nbuf_high_water=counters.nbuf_in_use;return n;}
/* TX_COMPLETE describes host-buffer release, not an over-the-air ACK. FMAC
 * can release a successfully copied packet synchronously inside start_xmit.
 * Defer that packet's event until its submission result is known. */
static void tx_complete(uint32_t token, int32_t status) {
    if (!callbacks_enabled) return;
    struct nrf70_facade_event e = {
        .generation = generation, .kind = NRF70_FACADE_EVENT_TX_COMPLETE,
        .token = token, .status = status,
    };
    if (status) counters.tx_failed++;
    else counters.tx_completed++;
    enqueue_event(&e, 0);
}
static void nbuf_free(void *p) {
    struct nbuf *n = p;
    if (!n) return;
    uint8_t is_tx = n->facade_tx;
    uint32_t token = n->tx_token;
    uint8_t defer = is_tx && n == tx_in_call;
    mem_free(n->base);
    mem_free(n);
    if (counters.nbuf_in_use) counters.nbuf_in_use--;
    if (defer) tx_freed_in_call = 1;
    else if (is_tx) tx_complete(token, NRF70_FACADE_OK);
}
static void nbuf_res(void*p,unsigned int s){struct nbuf*n=p;if(n&&s<=n->capacity){n->data=n->base+s;n->len=0;}}
static unsigned int nbuf_headroom(void*p){struct nbuf*n=p;return n?(unsigned int)(n->data-n->base):0;} static unsigned int nbuf_size(void*p){return p?((struct nbuf*)p)->len:0;} static void *nbuf_data(void*p){return p?((struct nbuf*)p)->data:0;}
static void *nbuf_put(void*p,unsigned int s){struct nbuf*n=p;if(!n||n->data-n->base+n->len+s>n->capacity)return 0;void*r=n->data+n->len;n->len+=s;return r;}
static void *nbuf_push(void*p,unsigned int s){struct nbuf*n=p;if(!n||s>(unsigned)(n->data-n->base))return 0;n->data-=s;n->len+=s;return n->data;} static void *nbuf_pull(void*p,unsigned int s){struct nbuf*n=p;if(!n||s>n->len)return 0;n->data+=s;n->len-=s;return n->data;}
static unsigned char nbuf_prio(void*p){return p?((struct nbuf*)p)->priority:0;} static unsigned char nbuf_sum(void*p){return p?((struct nbuf*)p)->checksum:0;} static void nbuf_set_sum(void*p,unsigned char v){if(p)((struct nbuf*)p)->checksum=v;}

static void *tasklet_alloc(int type){(void)type;for(unsigned i=0;i<TASKLET_SLOTS;i++)if(!tasklets[i].used){tasklets[i].used=1;tasklets[i].pending=0;return &tasklets[i];}counters.allocation_failures++;fatal(NRF70_FACADE_NO_MEMORY,"Wi-Fi tasklet slots exhausted");return 0;}
static void tasklet_free(void*p){if(p)nrf70_os_memset(p,0,sizeof(struct tasklet_slot));} static void tasklet_init(void*p,void(*fn)(unsigned long),unsigned long d){struct tasklet_slot*t=p;t->fn=fn;t->data=d;t->pending=0;} static void tasklet_schedule(void*p){if(p)((struct tasklet_slot*)p)->pending=1;} static void tasklet_kill(void*p){if(p)((struct tasklet_slot*)p)->pending=0;}
static void *timer_alloc(void){for(unsigned i=0;i<TIMER_SLOTS;i++)if(!timers[i].used){timers[i].used=1;return &timers[i];}counters.allocation_failures++;fatal(NRF70_FACADE_NO_MEMORY,"Wi-Fi timer slots exhausted");return 0;} static void timer_free(void*p){if(p)nrf70_os_memset(p,0,sizeof(struct timer_slot));}
static void timer_init(void*p,void(*fn)(unsigned long),unsigned long d){struct timer_slot*t=p;t->fn=fn;t->data=d;t->armed=0;} static void timer_schedule(void*p,unsigned long ms){struct timer_slot*t=p;t->deadline=now_us()+(uint32_t)ms*1000u;t->armed=1;} static void timer_kill(void*p){if(p)((struct timer_slot*)p)->armed=0;}

static int sleep_ms(int ms){uint32_t start=now_us();for(int i=0;i<ms;i++){if(platform&&platform->delay_us)platform->delay_us(platform->context,1000u);if(platform&&platform->host_irq_active&&platform->host_irq_active(platform->context))irq_pending=1;/* Synchronous BM APIs wait for firmware events. Pump only internal deferred C work here; Rust-facing callbacks merely enqueue. */nrf70_facade_process(8);}uint32_t d=now_us()-start;if(d>counters.max_osal_delay_us)counters.max_osal_delay_us=d;return 0;} static int delay_us(int us){uint32_t start=now_us();if(platform&&platform->delay_us)platform->delay_us(platform->context,(uint32_t)us);uint32_t d=now_us()-start;if(d>counters.max_osal_delay_us)counters.max_osal_delay_us=d;return 0;}
static unsigned long time_us(void){return now_us();} static unsigned int elapsed_us(unsigned long s){return now_us()-(uint32_t)s;} static unsigned long time_ms(void){return now_us()/1000u;} static unsigned int elapsed_ms(unsigned long s){return now_us()/1000u-(uint32_t)s;}

static void *bus_init(void){if(!platform||platform->power_on(platform->context))return 0;if(platform->bus_init(platform->context)){platform->bus_deinit(platform->context);platform->power_off(platform->context);return 0;}return (void*)platform;} static void bus_deinit(void*p){(void)p;if(platform){platform->bus_deinit(platform->context);platform->power_off(platform->context);}}
static void *dev_add(void*b,void*c){(void)b;return c?c:(void*)platform;} static void dev_rem(void*p){(void)p;} static enum nrf_wifi_status dev_init(void*p){(void)p;return NRF_WIFI_STATUS_SUCCESS;} static void dev_deinit(void*p){(void)p;}
static enum nrf_wifi_status irq_reg(void*d,void*c,int(*fn)(void*)){(void)d;irq_data=c;irq_callback=fn;return NRF_WIFI_STATUS_SUCCESS;} static void irq_unreg(void*d){(void)d;irq_callback=0;irq_data=0;}
static void host_map(void*d,struct nrf_wifi_osal_host_map*m){(void)d;m->addr=0;m->size=0xFFFFFFFFu;}
static unsigned int read32(void*p,unsigned long a){(void)p;uint32_t v=0,s=now_us();if(!platform||platform->read_reg32(platform->context,(uint32_t)a,&v)){v=0;counters.spi_errors++;fatal(NRF70_FACADE_IO,"SPI register read");}uint32_t d=now_us()-s;if(d>counters.max_spi_transfer_us)counters.max_spi_transfer_us=d;return v;}
static void write32(void*p,unsigned long a,unsigned int v){(void)p;uint32_t s=now_us();if(!platform||platform->write_reg32(platform->context,(uint32_t)a,v)){counters.spi_errors++;fatal(NRF70_FACADE_IO,"SPI register write");}uint32_t d=now_us()-s;if(d>counters.max_spi_transfer_us)counters.max_spi_transfer_us=d;}
/* The RPU bus moves whole 32-bit words, but the driver's commands and events
 * have arbitrary byte sizes (e.g. sizeof(struct nrf_wifi_cmd_sys_init) ==
 * 341), so transfers with an unaligned buffer or length bounce through a
 * zero-padded aligned copy, as Nordic's Zephyr shim does. The RPU-side
 * address must stay word-aligned. Bounce buffers may carry key material and
 * are zeroed before release. */
static void read_mem(void*p,void*d,unsigned long a,size_t n){
    (void)p;uint32_t s=now_us();int err;
    if((a&3u)||!platform){err=1;}
    else if(((((uintptr_t)d)|n)&3u)==0){err=platform->read(platform->context,(uint32_t)a,d,(uint32_t)n)!=0;}
    else{
        size_t pad=(n+3u)&~(size_t)3u;
        void*tmp=nrf70_os_malloc(pad); /* fatals itself when exhausted */
        if(!tmp){err=1;}
        else{
            err=platform->read(platform->context,(uint32_t)a,tmp,(uint32_t)pad)!=0;
            if(!err)nrf70_os_memcpy(d,tmp,n);
            secure_zero(tmp,pad);nrf70_os_free(tmp);
        }
    }
    if(err){nrf70_os_memset(d,0,n);counters.spi_errors++;fatal(NRF70_FACADE_IO,"SPI bulk read");}
    uint32_t x=now_us()-s;if(x>counters.max_spi_transfer_us)counters.max_spi_transfer_us=x;
}
static void write_mem(void*p,unsigned long a,const void*s,size_t n){
    (void)p;uint32_t t=now_us();int err;
    if((a&3u)||!platform){err=1;}
    else if(((((uintptr_t)s)|n)&3u)==0){err=platform->write(platform->context,(uint32_t)a,s,(uint32_t)n)!=0;}
    else{
        size_t pad=(n+3u)&~(size_t)3u;
        void*tmp=nrf70_os_malloc(pad); /* fatals itself when exhausted */
        if(!tmp){err=1;}
        else{
            nrf70_os_memset(tmp,0,pad);nrf70_os_memcpy(tmp,s,n);
            err=platform->write(platform->context,(uint32_t)a,tmp,(uint32_t)pad)!=0;
            secure_zero(tmp,pad);nrf70_os_free(tmp);
        }
    }
    if(err){counters.spi_errors++;fatal(NRF70_FACADE_IO,"SPI bulk write");}
    uint32_t x=now_us()-t;if(x>counters.max_spi_transfer_us)counters.max_spi_transfer_us=x;
}
static int ps_sleep(void*p){(void)p;return platform?platform->sleep(platform->context):-1;}static int ps_wake(void*p){(void)p;return platform?platform->wake(platform->context):-1;}static int ps_status(void*p){(void)p;return platform?platform->power_status(platform->context):-1;}
static void os_assert(int t,int v,enum nrf_wifi_assert_op_type op,char*m){int ok=0;switch(op){case NRF_WIFI_ASSERT_EQUAL_TO:ok=t==v;break;case NRF_WIFI_ASSERT_NOT_EQUAL_TO:ok=t!=v;break;case NRF_WIFI_ASSERT_LESS_THAN:ok=t<v;break;case NRF_WIFI_ASSERT_LESS_THAN_EQUAL_TO:ok=t<=v;break;case NRF_WIFI_ASSERT_GREATER_THAN:ok=t>v;break;case NRF_WIFI_ASSERT_GREATER_THAN_EQUAL_TO:ok=t>=v;break;default:ok=0;}if(!ok)fatal(NRF70_FACADE_FATAL,m?m:"nrf_wifi assert");}

/* Control lists and data-memory metadata use the same arena-backed helpers
 * as ordinary lists and allocations. The vendor OSAL calls these separate
 * hooks unconditionally; leaving them unset branches to NULL at startup. */
const struct nrf_wifi_osal_ops nrf_wifi_os_bm_ops = {
 .mem_alloc=mem_alloc,.mem_zalloc=mem_zalloc,.mem_free=mem_free,.mem_cpy=nrf70_os_memcpy,.mem_set=nrf70_os_memset,.mem_cmp=nrf70_os_memcmp,
 .data_mem_zalloc=mem_zalloc,.data_mem_free=mem_free,
 .ctrl_llist_alloc=list_alloc,.ctrl_llist_free=list_free,.ctrl_llist_node_alloc=node_alloc,.ctrl_llist_node_free=node_free,
 .qspi_read_reg32=read32,.qspi_write_reg32=write32,.qspi_cpy_from=read_mem,.qspi_cpy_to=write_mem,
 .spinlock_alloc=lock_alloc,.spinlock_free=lock_free,.spinlock_init=lock_init,.spinlock_take=lock_take,.spinlock_rel=lock_rel,.spinlock_irq_take=lock_irq_take,.spinlock_irq_rel=lock_irq_rel,
 .log_dbg=log_drop,.log_info=log_drop,.log_err=log_fmt_err,
 .llist_node_alloc=node_alloc,.llist_node_free=node_free,.llist_node_data_get=node_data,.llist_node_data_set=node_set,.llist_alloc=list_alloc,.llist_free=list_free,.llist_init=list_init,.llist_add_node_tail=list_tail,.llist_add_node_head=list_head,.llist_get_node_head=list_get_head,.llist_get_node_nxt=list_next,.llist_del_node=list_del,.llist_len=list_len,
 .nbuf_alloc=nbuf_alloc,.nbuf_free=nbuf_free,.nbuf_headroom_res=nbuf_res,.nbuf_headroom_get=nbuf_headroom,.nbuf_data_size=nbuf_size,.nbuf_data_get=nbuf_data,.nbuf_data_put=nbuf_put,.nbuf_data_push=nbuf_push,.nbuf_data_pull=nbuf_pull,.nbuf_get_priority=nbuf_prio,.nbuf_get_chksum_done=nbuf_sum,.nbuf_set_chksum_done=nbuf_set_sum,
 .tasklet_alloc=tasklet_alloc,.tasklet_free=tasklet_free,.tasklet_init=tasklet_init,.tasklet_schedule=tasklet_schedule,.tasklet_kill=tasklet_kill,
 .sleep_ms=sleep_ms,.delay_us=delay_us,.time_get_curr_us=time_us,.time_elapsed_us=elapsed_us,.time_get_curr_ms=time_ms,.time_elapsed_ms=elapsed_ms,
 .bus_qspi_init=bus_init,.bus_qspi_deinit=bus_deinit,.bus_qspi_dev_add=dev_add,.bus_qspi_dev_rem=dev_rem,.bus_qspi_dev_init=dev_init,.bus_qspi_dev_deinit=dev_deinit,.bus_qspi_dev_intr_reg=irq_reg,.bus_qspi_dev_intr_unreg=irq_unreg,.bus_qspi_dev_host_map_get=host_map,
 .timer_alloc=timer_alloc,.timer_free=timer_free,.timer_init=timer_init,.timer_schedule=timer_schedule,.timer_kill=timer_kill,.bus_qspi_ps_sleep=ps_sleep,.bus_qspi_ps_wake=ps_wake,.bus_qspi_ps_status=ps_status,
 .assert=os_assert,.strlen=os_strlen,.rand8_get=rand8
};

static void *rpu_ctx(void){return fmac_dev;}
static unsigned char vif_idx(void){return sta_vif_idx;}
static void push_simple(uint8_t kind,int32_t status){struct nrf70_facade_event e={.generation=generation,.status=status,.kind=kind,.frequency_mhz=associated_frequency,.rssi_dbm=current_rssi};enqueue_event(&e,kind==NRF70_FACADE_EVENT_FATAL||kind==NRF70_FACADE_EVENT_DISCONNECTED);}
static void rx_frame_cb(void *vif,void *frm){(void)vif;struct nbuf*n=frm;if(!n)return;if(!callbacks_enabled){nbuf_free(n);return;}if(n->len<14||n->len>NRF70_FACADE_MAX_FRAME_LEN){counters.rx_invalid++;nbuf_free(n);return;}
    /* FMAC callback context: enqueue/copy only; wpa_sm and FMAC re-entry happen
     * later from nrf70_facade_process. */
    uint16_t ethertype=((uint16_t)n->data[12]<<8)|n->data[13];
    if(ethertype==0x888Eu){
        uint16_t body=(uint16_t)(n->len-14u);
        if(body>=7u)log_diag("EAPOL RX: len=%u type=%u key_info=%x state=%u",(unsigned)body,n->data[15],((unsigned)n->data[19]<<8)|n->data[20],conn.state);
        if(!conn.secured||body>EAPOL_MAX||eapol_count==EAPOL_SLOTS){counters.eapol_rx_dropped++;nbuf_free(n);return;}
        struct eapol_slot*s=&eapol_slots[eapol_write];
        s->length=body;nrf70_os_memcpy(s->src,n->data+6,6);nrf70_os_memcpy(s->frame,n->data+14,body);
        eapol_write=(uint8_t)((eapol_write+1u)%EAPOL_SLOTS);eapol_count++;counters.eapol_rx++;
        nbuf_free(n);return;
    }
    if(conn.secured&&!conn.port_authorized){counters.rx_dropped_unauthorized++;nbuf_free(n);return;}
    counters.rx_received++;if(rx_count==RX_SLOTS){counters.rx_dropped++;nbuf_free(n);return;}struct rx_slot*s=&rx_slots[rx_write];s->length=(uint16_t)n->len;s->rssi=current_rssi;nrf70_os_memcpy(s->frame,n->data,n->len);counters.rx_copies++;rx_write=(uint8_t)((rx_write+1u)%RX_SLOTS);rx_count++;if(rx_count>counters.rx_queue_high_water)counters.rx_queue_high_water=rx_count;nbuf_free(n);push_simple(NRF70_FACADE_EVENT_RX_READY,NRF70_FACADE_OK);}
static enum nrf_wifi_status carrier_cb(void*vif,enum nrf_wifi_fmac_if_carr_state state){(void)vif;if(!callbacks_enabled)return NRF_WIFI_STATUS_SUCCESS;uint8_t up=state==NRF_WIFI_FMAC_IF_CARR_STATE_ON;if(up!=linked){linked=up;if(up)counters.link_ups++;else counters.link_downs++;struct nrf70_facade_event e={.generation=generation,.kind=NRF70_FACADE_EVENT_LINK,.link_up=up,.frequency_mhz=associated_frequency,.rssi_dbm=current_rssi};enqueue_event(&e,1);}return NRF_WIFI_STATUS_SUCCESS;}
/* MLME event buffers are allocated at exactly the RPU-declared length, so
 * every field read must be covered by `len`; a short event is treated as a
 * failure (auth/assoc) or reported with reason 0 (disconnect). */
#define MLME_FLAGS_LEN (offsetof(struct nrf_wifi_umac_event_mlme,nrf_wifi_flags)+sizeof(((struct nrf_wifi_umac_event_mlme*)0)->nrf_wifi_flags))
static uint16_t mlme_status(const struct nrf_wifi_umac_event_mlme *e, unsigned len, unsigned offset) {
    if (!e || len < MLME_FLAGS_LEN || (e->nrf_wifi_flags & NRF_WIFI_EVENT_MLME_TIMED_OUT) ||
        len < offsetof(struct nrf_wifi_umac_event_mlme, frame.frame) + offset + 2u ||
        e->frame.frame_len < offset + 2u) return UINT16_MAX;
    const uint8_t *frame = (const uint8_t *)e->frame.frame;
    return (uint16_t)frame[offset] | ((uint16_t)frame[offset + 1] << 8);
}
static void auth_cb(void*vif,struct nrf_wifi_umac_event_mlme*e,unsigned int len){
    (void)vif;
    uint16_t status=mlme_status(e,len,28); /* 24-byte header, algorithm, transaction, status */
    log_diag("auth response: status=%u",(unsigned)status);
    if(conn.state==CONN_AUTH_WAIT){if(status==0)conn.auth_ok=1;else conn.auth_fail=1;}
    push_simple(NRF70_FACADE_EVENT_AUTH,status==0?0:NRF70_FACADE_IO);
}
static void assoc_cb(void*vif,struct nrf_wifi_umac_event_mlme*e,unsigned int len){
    (void)vif;
    uint16_t status=mlme_status(e,len,26); /* 24-byte header, capabilities, status */
    log_diag("assoc response: status=%u",(unsigned)status);
    if(conn.state==CONN_ASSOC_WAIT){if(status==0)conn.assoc_ok=1;else conn.assoc_fail=1;}
    push_simple(NRF70_FACADE_EVENT_ASSOC,status==0?0:NRF70_FACADE_IO);
}
static void disconnected_cb(void*vif,struct nrf_wifi_umac_event_mlme*e,unsigned int len){(void)vif;if(!callbacks_enabled)return;uint16_t reason=0;if(e&&len>=offsetof(struct nrf_wifi_umac_event_mlme,frame.frame)+26u&&e->frame.frame_len>=26){const uint8_t*f=(const uint8_t*)e->frame.frame;reason=(uint16_t)f[24]|((uint16_t)f[25]<<8);}counters.disconnects++;linked=0;if(conn.state!=CONN_IDLE)conn.teardown=1;struct nrf70_facade_event x={.generation=generation,.kind=NRF70_FACADE_EVENT_DISCONNECTED,.frequency_mhz=associated_frequency,.reason_code=reason};enqueue_event(&x,1);}
static void rssi_cb(void*vif,signed short signal){(void)vif;if(signal<-128)current_rssi=-128;else if(signal>127)current_rssi=127;else current_rssi=(int8_t)signal;}
static void recovery_cb(void*vif,void*event,unsigned int len){(void)vif;(void)event;(void)len;if(callbacks_enabled){counters.firmware_restarts++;push_simple(NRF70_FACADE_EVENT_FATAL,NRF70_FACADE_FATAL);}}
static void reg_change_cb(void*vif,struct nrf_wifi_event_regulatory_change*e,unsigned int len){(void)vif;(void)len;if(!fmac_dev||!e||!fmac_dev->waiting_for_reg_event)return;fmac_dev->reg_change=nrf70_os_malloc(sizeof(*e));if(!fmac_dev->reg_change)return;nrf70_os_memcpy(fmac_dev->reg_change,e,sizeof(*e));fmac_dev->reg_set_status=true;}
static void get_reg_cb(void*vif,struct nrf_wifi_reg*e,unsigned int len){(void)vif;(void)len;if(!fmac_dev||!e||fmac_dev->alpha2_valid)return;nrf70_os_memcpy(fmac_dev->alpha2,e->nrf_wifi_alpha2,2);fmac_dev->reg_chan_count=e->num_channels;if(fmac_dev->reg_chan_count>MAX_NUM_REG_CHANELS)fmac_dev->reg_chan_count=MAX_NUM_REG_CHANELS;nrf70_os_memcpy(fmac_dev->reg_chan_info,e->chn_info,fmac_dev->reg_chan_count*sizeof(struct nrf_wifi_get_reg_chn_info));fmac_dev->alpha2_valid=true;}
static void fill_callbacks(struct nrf_wifi_fmac_callbk_fns*c);

static void scan_start_cb(void*vif,struct nrf_wifi_umac_event_trigger_scan*e,unsigned int len){(void)vif;(void)e;(void)len;}
static void scan_done_cb(void*vif,struct nrf_wifi_umac_event_trigger_scan*e,unsigned int len){(void)vif;(void)e;(void)len;if(scan_active)scan_fetch_pending=1;else if(conn.state==CONN_SCAN_WAIT)conn.scan_fetch=1;}
static void scan_abort_cb(void*vif,struct nrf_wifi_umac_event_trigger_scan*e,unsigned int len){(void)vif;(void)e;(void)len;if(scan_suppress){scan_suppress=0;return;}if(!scan_active){if(conn.state==CONN_SCAN_WAIT)conn.scan_done=1;/* aborted connect scan: no RSN IE captured -> HANDSHAKE_FAILED */return;}scan_active=0;struct nrf70_facade_event x={.generation=generation,.kind=NRF70_FACADE_EVENT_SCAN_COMPLETE,.status=NRF70_FACADE_CANCELLED};enqueue_event(&x,1);}
static void scan_results_cb(void*vif,struct nrf_wifi_umac_event_new_scan_display_results*results,unsigned int len,bool more){(void)vif;(void)len;if(!scan_active||!results)return;for(unsigned i=0;i<results->event_bss_count;i++){if(scan_suppress||(scan_max_results&&scan_result_count>=scan_max_results))break;struct umac_display_results*r=&results->display_results[i];struct nrf70_facade_event e={.generation=generation,.kind=NRF70_FACADE_EVENT_SCAN_RESULT};e.scan.ssid_len=r->ssid.nrf_wifi_ssid_len>32?32:r->ssid.nrf_wifi_ssid_len;nrf70_os_memcpy(e.scan.ssid,r->ssid.nrf_wifi_ssid,e.scan.ssid_len);e.scan.channel=r->nwk_channel;e.scan.band=r->nwk_band;e.scan.rssi_dbm=r->signal.signal_type==NRF_WIFI_SIGNAL_TYPE_MBM?(int8_t)(((int)r->signal.signal.mbm_signal)/100):(int8_t)r->signal.signal.unspec_signal;nrf70_os_memcpy(e.scan.bssid,r->mac_addr,6);e.scan.mfp=(r->mfp_flag&NRF_WIFI_MFP_REQUIRED)?2:((r->mfp_flag&NRF_WIFI_MFP_CAPABLE)?1:0);switch(r->security_type){case NRF_WIFI_OPEN:e.scan.security=NRF70_FACADE_SECURITY_OPEN;break;case NRF_WIFI_WPA2:e.scan.security=NRF70_FACADE_SECURITY_WPA2_PSK;break;case NRF_WIFI_WPA2_256:e.scan.security=NRF70_FACADE_SECURITY_WPA2_PSK_SHA256;break;case NRF_WIFI_WPA3_HNP:case NRF_WIFI_WPA3_H2E:case NRF_WIFI_WPA3_AUTO:case NRF_WIFI_WPA3_FT_SAE:e.scan.security=NRF70_FACADE_SECURITY_WPA3_SAE;break;default:e.scan.security=NRF70_FACADE_SECURITY_OTHER;}enqueue_event(&e,0);scan_result_count++;}if(!more){scan_active=0;scan_suppress=0;counters.scans_completed++;struct nrf70_facade_event e={.generation=generation,.kind=NRF70_FACADE_EVENT_SCAN_COMPLETE};enqueue_event(&e,1);}}
/* Finds IE `id` in a raw element buffer; returns element length incl. the
 * 2-byte header via *out_len, or NULL. */
static const uint8_t *find_ie(const uint8_t *ies,uint32_t len,uint8_t id,uint16_t *out_len){
    while(len>=2u){uint16_t el=(uint16_t)ies[1]+2u;if(el>len)return 0;if(ies[0]==id){*out_len=el;return ies;}ies+=el;len-=el;}
    return 0;
}
static void conn_capture_ie(const uint8_t *ies,uint32_t len,uint8_t id,uint8_t *dst,uint16_t *dst_len){
    uint16_t el;const uint8_t *e;
    if(*dst_len||!ies||!len)return;
    e=find_ie(ies,len,id,&el);
    if(e&&el<=CONN_IE_MAX){nrf70_os_memcpy(dst,e,el);*dst_len=el;}
}
/* SCAN_CONNECT results: capture the target AP's RSN IE (48) and RSNXE (244)
 * from the probe-response IEs, falling back to the beacon IEs. */
static void connect_scan_res_cb(void *vif,struct nrf_wifi_umac_event_new_scan_results*r,unsigned int len,bool more){
    (void)vif;
    if(conn.state!=CONN_SCAN_WAIT){return;}
    if(r&&len>=offsetof(struct nrf_wifi_umac_event_new_scan_results,ies))
        log_diag("connect scan: len=%u flags=%x ies=%u beacon=%u more=%u bssid=%02x:%02x:%02x:%02x:%02x:%02x",len,r->valid_fields,r->ies_len,r->beacon_ies_len,(unsigned)more,r->mac_addr[0],r->mac_addr[1],r->mac_addr[2],r->mac_addr[3],r->mac_addr[4],r->mac_addr[5]);
    /* The RPU-declared ies_len/beacon_ies_len must fit inside the delivered
     * event (the HAL allocates exactly the declared message length); a
     * malformed event is ignored rather than parsed out of bounds. */
    if(r&&len>=(unsigned int)offsetof(struct nrf_wifi_umac_event_new_scan_results,ies)&&
       (uint64_t)r->ies_len+(uint64_t)r->beacon_ies_len<=
       (uint64_t)(len-offsetof(struct nrf_wifi_umac_event_new_scan_results,ies))){
        const uint8_t *ies=r->ies,*beacon=0;uint32_t ies_len=0,beacon_len=0;
        /* Probe-response IEs live at ies[0..ies_len) only when IES_VALID.
         * Beacon IEs start at ies+ies_len, an offset that is only meaningful
         * when the probe region is valid; without IES_VALID the beacon IEs can
         * only be located when ies_len==0, otherwise skip them entirely. */
        if(r->valid_fields&NRF_WIFI_EVENT_NEW_SCAN_RESULTS_IES_VALID)ies_len=r->ies_len;
        if(r->valid_fields&NRF_WIFI_EVENT_NEW_SCAN_RESULTS_BEACON_IES_VALID){
            if(r->valid_fields&NRF_WIFI_EVENT_NEW_SCAN_RESULTS_IES_VALID){beacon=ies+r->ies_len;beacon_len=r->beacon_ies_len;}
            else if(r->ies_len==0){beacon=ies;beacon_len=r->beacon_ies_len;}
        }
        uint8_t match;
        if(conn.have_bssid){match=nrf70_os_memcmp(r->mac_addr,conn.bssid,6)==0;}
        else{uint16_t sl=0;const uint8_t *s=ies_len?find_ie(ies,ies_len,0,&sl):0;if(!s&&beacon_len){s=find_ie(beacon,beacon_len,0,&sl);}match=s&&sl==(uint16_t)conn.ssid_len+2u&&nrf70_os_memcmp(s+2,conn.ssid,conn.ssid_len)==0;}
        if(match&&!conn.scan_done&&conn.rsn_ie_len==0){
            nrf70_os_memcpy(conn.found_bssid,r->mac_addr,6);
            conn_capture_ie(ies,ies_len,48,conn.rsn_ie,&conn.rsn_ie_len);
            conn_capture_ie(beacon,beacon_len,48,conn.rsn_ie,&conn.rsn_ie_len);
            conn_capture_ie(ies,ies_len,244,conn.rsnxe,&conn.rsnxe_len);
            conn_capture_ie(beacon,beacon_len,244,conn.rsnxe,&conn.rsnxe_len);
            if(conn.rsn_ie_len)conn.have_bssid=1;
        }
    }
    if(!more)conn.scan_done=1;
}
static void fill_callbacks(struct nrf_wifi_fmac_callbk_fns*c){nrf70_os_memset(c,0,sizeof(*c));c->rpu_recovery_callbk_fn=recovery_cb;c->scan_start_callbk_fn=scan_start_cb;c->scan_done_callbk_fn=scan_done_cb;c->scan_abort_callbk_fn=scan_abort_cb;c->disp_scan_res_callbk_fn=scan_results_cb;c->scan_res_callbk_fn=connect_scan_res_cb;c->event_get_reg=get_reg_cb;c->reg_change_callbk_fn=reg_change_cb;c->if_carr_state_chg_callbk_fn=carrier_cb;c->rx_frm_callbk_fn=rx_frame_cb;c->auth_resp_callbk_fn=auth_cb;c->assoc_resp_callbk_fn=assoc_cb;c->deauth_callbk_fn=disconnected_cb;c->disassoc_callbk_fn=disconnected_cb;c->process_rssi_from_rx=rssi_cb;}

static void fmac_stop(void){callbacks_enabled=0;if(fmac_dev&&sta_vif_idx<MAX_NUM_VIFS){struct nrf_wifi_umac_chg_vif_state_info v={0};v.state=NRF_WIFI_FMAC_IF_OP_STATE_DOWN;v.if_index=sta_vif_idx;nrf_wifi_sys_fmac_chg_vif_state(fmac_dev,sta_vif_idx,&v);nrf_wifi_sys_fmac_del_vif(fmac_dev,sta_vif_idx);}if(fmac_dev)nrf_wifi_sys_fmac_dev_deinit(fmac_dev);if(fmac_dev)nrf_wifi_fmac_dev_rem(fmac_dev);if(fmac_priv)nrf_wifi_fmac_deinit(fmac_priv);nrf_wifi_osal_deinit();fmac_dev=0;fmac_priv=0;sta_vif_idx=MAX_NUM_VIFS;}
static int fmac_start(const uint8_t mac[6], const uint8_t country[2]) {
    struct nrf_wifi_data_config_params data = {0};
    struct rx_buf_pool_params rx[MAX_NUM_OF_RX_QUEUES] = {0};
    struct nrf_wifi_fmac_callbk_fns callbacks;
    struct nrf_wifi_tx_pwr_ctrl_params power = {0};
    struct nrf_wifi_tx_pwr_ceil_params ceilings;
    struct nrf_wifi_board_params board = {0};
    unsigned char alpha2[3] = {country[0], country[1], 0};
    const char *stage = "init: creating FMAC";
    data.max_tx_aggregation = 1;
    data.reorder_buf_size = 1;
    /* Feed every system-mode RX queue. The HAL reserves NUM_BUFS *
     * MAX_DATA_SIZE bytes, but FMAC adds RX_BUF_HEADROOM to each payload
     * size when laying out the pools. Include that headroom in the budget,
     * otherwise the last buffer extends beyond the end of packet RAM. */
    _Static_assert(NRF70_RX_NUM_BUFS % MAX_NUM_OF_RX_QUEUES == 0,
                   "RX buffers must split evenly across the queues");
    _Static_assert(NRF70_RX_MAX_DATA_SIZE >= NRF70_FACADE_MAX_FRAME_LEN + RX_BUF_HEADROOM,
                   "RX slot must hold an Ethernet frame plus descriptor headroom");
    for (unsigned i = 0; i < MAX_NUM_OF_RX_QUEUES; i++) {
        rx[i].num_bufs = NRF70_RX_NUM_BUFS / MAX_NUM_OF_RX_QUEUES;
        rx[i].buf_sz = NRF70_RX_MAX_DATA_SIZE - RX_BUF_HEADROOM;
    }
    fill_callbacks(&callbacks);
    log_msg(1, stage);
    nrf_wifi_osal_init(&nrf_wifi_os_bm_ops);
    fmac_priv = nrf_wifi_sys_fmac_init(&data, rx, &callbacks);
    if (!fmac_priv) goto fail;
    stage = "init: adding device (power and SPI)";
    log_msg(1, stage);
    fmac_dev = nrf_wifi_sys_fmac_dev_add(fmac_priv, (void *)platform);
    if (!fmac_dev) goto fail;
    stage = "init: loading firmware";
    log_msg(1, stage);
    if (nrf70_bm_fw_load(fmac_dev, (const uint8_t *)_bin_nrf70_facade_fw_start,
                        (const uint8_t *)_bin_nrf70_facade_fw_end) != NRF_WIFI_STATUS_SUCCESS)
        goto fail;
    nrf70_bm_conf_tx_pwr_settings(&power, &ceilings);
    nrf70_bm_conf_board_dep_params(&board);
    /* Zephyr's defaults: SWCTRL1 is the COEX_STATUS1 input and COEX_GRANT is
     * active low. The nRF54 PTA client in mcu/src/platform/coex.rs relies on
     * that polarity. */
    stage = "init: configuring coex GPIO control";
    log_msg(1, stage);
    if (nrf_wifi_coex_config_sleep_ctrl_gpio_ctrl(fmac_dev, 1, 1) != NRF_WIFI_STATUS_SUCCESS)
        goto fail;
    stage = "init: initializing firmware and RX pools";
    log_msg(1, stage);
    if (nrf_wifi_sys_fmac_dev_init(fmac_dev, HW_SLEEP_ENABLE, NRF_WIFI_DEF_PHY_CALIB,
                                  CONFIG_NRF_WIFI_OP_BAND, true, &power, &ceilings,
                                  &board, alpha2) != NRF_WIFI_STATUS_SUCCESS)
        goto fail;
    struct nrf_wifi_umac_add_vif_info add = {0};
    add.iftype = NRF_WIFI_IFTYPE_STATION;
    nrf70_os_memcpy(add.ifacename, "wlan0", 5);
    stage = "init: adding station interface";
    log_msg(1, stage);
    sta_vif_idx = nrf_wifi_sys_fmac_add_vif(fmac_dev, (void *)platform, &add);
    if (sta_vif_idx >= MAX_NUM_VIFS) goto fail;
    nrf70_os_memcpy(sta_mac, mac, 6);
    stage = "init: setting station MAC";
    log_msg(1, stage);
    if (nrf_wifi_sys_fmac_set_vif_macaddr(fmac_dev, sta_vif_idx, sta_mac) != NRF_WIFI_STATUS_SUCCESS)
        goto fail;
    struct nrf_wifi_umac_chg_vif_state_info up = {0};
    up.state = NRF_WIFI_FMAC_IF_OP_STATE_UP;
    up.if_index = sta_vif_idx;
    stage = "init: waiting for interface-up acknowledgement";
    log_msg(1, stage);
    if (nrf_wifi_sys_fmac_chg_vif_state(fmac_dev, sta_vif_idx, &up) != NRF_WIFI_STATUS_SUCCESS)
        goto fail;
    callbacks_enabled = 1;
    log_msg(1, "init: station interface ready");
    return 0;
fail:
    log_msg(3, stage);
    log_msg(3, "init failed; tearing down (interface-down may also time out)");
    fmac_stop();
    return -1;
}
int32_t nrf70_facade_init(const struct nrf70_facade_platform_ops*ops,const uint8_t mac[6],const uint8_t country[2]){if(initialized||!ops||ops->abi_version!=NRF70_FACADE_ABI_VERSION||!mac||!country)return NRF70_FACADE_INVALID;platform=ops;reset_runtime();generation++;counters.generation=generation;uint32_t s=now_us();int r=fmac_start(mac,country);account_call(s);if(r||faulted){int32_t error=faulted?NRF70_FACADE_FATAL:NRF70_FACADE_IO;reset_runtime();platform=0;return error;}initialized=1;return 0;}
/* Keep the internal IRQ callback until FMAC finishes its synchronous
 * interface-down request. bus_dev_deinit unregisters it afterwards. */
int32_t nrf70_facade_deinit(void){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;callbacks_enabled=0;scan_active=0;conn_teardown_now();uint32_t s=now_us();fmac_stop();account_call(s);initialized=0;reset_runtime();platform=0;return 0;}
int32_t nrf70_facade_reset(const uint8_t mac[6],const uint8_t country[2]){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;if(!mac||!country)return NRF70_FACADE_INVALID;callbacks_enabled=0;scan_active=0;conn_teardown_now();uint32_t s=now_us();fmac_stop();account_call(s);reset_runtime();generation++;counters.generation=generation;counters.resets++;s=now_us();int r=fmac_start(mac,country);account_call(s);if(r||faulted){initialized=0;return NRF70_FACADE_FATAL;}counters.firmware_restarts++;push_simple(NRF70_FACADE_EVENT_FIRMWARE_RESTART,0);return 0;}
int32_t nrf70_facade_set_country(const uint8_t c[2]){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;if(!c)return NRF70_FACADE_INVALID;struct nrf_wifi_fmac_reg_info reg={0};reg.alpha2[0]=c[0];reg.alpha2[1]=c[1];reg.force=true;uint32_t s=now_us();enum nrf_wifi_status r=nrf_wifi_fmac_set_reg(fmac_dev,&reg);account_call(s);return faulted?NRF70_FACADE_FATAL:(r==NRF_WIFI_STATUS_SUCCESS?0:NRF70_FACADE_IO);}
int32_t nrf70_facade_scan_start(const struct nrf70_facade_scan_request*q){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;if(scan_active||(conn.state!=CONN_IDLE&&conn.state!=CONN_AUTHORIZED))return NRF70_FACADE_BUSY;if(!q||q->channel_count>32||q->ssid_len>=32)return NRF70_FACADE_INVALID;/* The pinned nrf_wifi_sys_fmac_scan copies sizeof(info)+sizeof(struct nrf_wifi_channel)*num_scan_channels bytes from this buffer, so reserve a zeroed nrf_wifi_channel-sized area per channel; only the leading unsigned int frequencies are meaningful on the wire (upstream semantics), the rest is zeroed facade-owned slack the FMAC over-copy may read. */struct __attribute__((packed)){struct nrf_wifi_umac_scan_info info;union{unsigned int frequency[NRF70_FACADE_MAX_CHANNELS];unsigned char reserve[sizeof(struct nrf_wifi_channel)*NRF70_FACADE_MAX_CHANNELS];}ch;}scan={0};scan.info.scan_reason=SCAN_DISPLAY;scan.info.scan_params.passive_scan=q->passive;scan.info.scan_params.bands=q->channel_count?0:(NRF_WIFI_SCAN_BAND_2GHZ|NRF_WIFI_SCAN_BAND_5GHZ);scan.info.scan_params.dwell_time_active=q->dwell_active_ms;scan.info.scan_params.dwell_time_passive=q->dwell_passive_ms;if(q->ssid_len){scan.info.scan_params.num_scan_ssids=1;scan.info.scan_params.scan_ssids[0].nrf_wifi_ssid_len=q->ssid_len;nrf70_os_memcpy(scan.info.scan_params.scan_ssids[0].nrf_wifi_ssid,q->ssid,q->ssid_len);}for(unsigned i=0;i<q->channel_count;i++){if(q->channels[i].band>1)return NRF70_FACADE_INVALID;scan.info.scan_params.bands|=q->channels[i].band?NRF_WIFI_SCAN_BAND_5GHZ:NRF_WIFI_SCAN_BAND_2GHZ;int f=nrf_wifi_utils_chan_to_freq(q->channels[i].band?NRF_WIFI_BAND_5GHZ:NRF_WIFI_BAND_2GHZ,q->channels[i].channel);if(f<0)return NRF70_FACADE_INVALID;scan.ch.frequency[i]=(unsigned int)f;}scan.info.scan_params.num_scan_channels=q->channel_count;scan_active=1;scan_suppress=0;scan_result_count=0;scan_max_results=q->max_results;counters.scans_started++;uint32_t s=now_us();scan_command_active=1;enum nrf_wifi_status r=nrf_wifi_sys_fmac_scan(fmac_dev,sta_vif_idx,&scan.info);scan_command_active=0;account_call(s);if(r!=NRF_WIFI_STATUS_SUCCESS||faulted){scan_active=0;return faulted?NRF70_FACADE_FATAL:NRF70_FACADE_IO;}return 0;}
int32_t nrf70_facade_scan_cancel(void){if(!scan_active)return NRF70_FACADE_INVALID;scan_active=0;scan_suppress=1;counters.scans_cancelled++;nrf_wifi_sys_fmac_abort_scan(fmac_dev,sta_vif_idx);struct nrf70_facade_event e={.generation=generation,.status=NRF70_FACADE_CANCELLED,.kind=NRF70_FACADE_EVENT_SCAN_COMPLETE};enqueue_event(&e,1);return 0;}
/* --- connect state machine + supplicant host hooks ------------------------ */
static uint8_t conn_stepping; /* sleep_ms() re-enters process(); never re-enter wpa_sm */
static void conn_reset(void){secure_zero(&conn,sizeof(conn));secure_zero(eapol_slots,sizeof(eapol_slots));eapol_read=eapol_write=eapol_count=0;}
static void conn_fail_ex(int32_t status,uint16_t reason){counters.handshake_failures++;struct nrf70_facade_event e={.generation=generation,.kind=NRF70_FACADE_EVENT_HANDSHAKE_FAILED,.status=status,.reason_code=reason,.frequency_mhz=associated_frequency};enqueue_event(&e,1);conn.teardown=1;}
static void conn_fail(uint16_t reason){conn_fail_ex(NRF70_FACADE_IO,reason);}
/* Bounded parse of the captured AP RSN IE (tag 48, body after the 2-byte
 * element header): version, group suite, pairwise list, AKM list (collecting
 * PSK / PSK-SHA256), optional RSN capabilities (MFPC/MFPR). Every read is
 * bounds-checked; returns non-zero on any malformed structure. Trailing
 * fields (PMKID list, group mgmt suite) are ignored. */
struct conn_rsn_info { uint8_t has_psk, has_psk_sha256, group_ccmp, pairwise_ccmp, mfpc, mfpr; };
static int rsn_suite_is_ccmp(const uint8_t *s){return s[0]==0&&s[1]==0x0f&&s[2]==0xac&&s[3]==4;}
static int conn_parse_rsn(const uint8_t *ie,uint16_t ie_len,struct conn_rsn_info *out){
    nrf70_os_memset(out,0,sizeof(*out));
    if(!ie||ie_len<4u||ie[0]!=48u||(uint16_t)ie[1]+2u!=ie_len)return -1;
    const uint8_t *p=ie+2;uint16_t len=(uint16_t)(ie_len-2u),off=0;
    if(((uint16_t)p[0]|((uint16_t)p[1]<<8))!=1u)return -1; /* RSN version */
    off=2;
    if((uint16_t)(len-off)<4u)return -1; /* group data cipher suite */
    out->group_ccmp=rsn_suite_is_ccmp(p+off);
    off=(uint16_t)(off+4u);
    if((uint16_t)(len-off)<2u)return -1;
    uint16_t pairwise_count=(uint16_t)p[off]|((uint16_t)p[off+1]<<8);off=(uint16_t)(off+2u);
    if(!pairwise_count||pairwise_count>(uint16_t)((len-off)/4u))return -1;
    for(uint16_t i=0;i<pairwise_count;i++)if(rsn_suite_is_ccmp(p+off+i*4u))out->pairwise_ccmp=1;
    off=(uint16_t)(off+pairwise_count*4u);
    if((uint16_t)(len-off)<2u)return -1;
    uint16_t akm_count=(uint16_t)p[off]|((uint16_t)p[off+1]<<8);off=(uint16_t)(off+2u);
    if(!akm_count||akm_count>(uint16_t)((len-off)/4u))return -1;
    for(uint16_t i=0;i<akm_count;i++){
        const uint8_t *s=p+off+i*4u;
        if(s[0]==0x00&&s[1]==0x0F&&s[2]==0xAC){
            if(s[3]==2u)out->has_psk=1;
            else if(s[3]==6u)out->has_psk_sha256=1;
        }
    }
    off=(uint16_t)(off+akm_count*4u);
    if((uint16_t)(len-off)>=2u){
        uint16_t capab=(uint16_t)p[off]|((uint16_t)p[off+1]<<8);
        if(capab&0x0080u)out->mfpc=1;
        if(capab&0x0040u)out->mfpr=1;
    }
    return 0;
}
/* Called at process() top level only (never from FMAC callback context). */
static void conn_teardown_now(void){
    /* A connect-reason scan may still be running in the RPU; abort it so it
     * cannot collide with (or leak stale results into) a later attempt. The
     * connect scan and the display scan are mutually exclusive via the BUSY
     * checks, and the !scan_active guard keeps a display scan (and its
     * scan_suppress bookkeeping) untouched. The stale abort/done event lands
     * in scan_abort_cb/scan_done_cb after conn is reset to CONN_IDLE, where it
     * is ignored. */
    if((conn.state==CONN_SCAN_START||conn.state==CONN_SCAN_WAIT)&&!scan_active&&fmac_dev&&sta_vif_idx<MAX_NUM_VIFS)
        nrf_wifi_sys_fmac_abort_scan(fmac_dev,sta_vif_idx);
    nrf70_supp_stop();conn_reset();
}

uint32_t nrf70_supp_host_now_us(void){return now_us();}
uint8_t nrf70_supp_host_random_u8(void){return rand8();}
int32_t nrf70_supp_host_add_key(uint8_t pairwise,const uint8_t peer[6],uint8_t key_idx,uint32_t cipher_suite,const uint8_t *key,uint16_t key_len,const uint8_t *seq,uint16_t seq_len,uint8_t is_mgmt){
    struct nrf_wifi_umac_key_info i={0};
    if(!key||key_len>NRF_WIFI_MAX_KEY_LENGTH||seq_len>NRF_WIFI_MAX_SEQ_LENGTH)return NRF70_FACADE_INVALID;
    i.key_type=pairwise?NRF_WIFI_KEYTYPE_PAIRWISE:NRF_WIFI_KEYTYPE_GROUP;
    i.key_idx=key_idx;i.cipher_suite=cipher_suite;
    i.key.nrf_wifi_key_len=key_len;nrf70_os_memcpy(i.key.nrf_wifi_key,key,key_len);
    if(seq&&seq_len){i.seq.nrf_wifi_seq_len=seq_len;nrf70_os_memcpy(i.seq.nrf_wifi_seq,seq,seq_len);}
    i.valid_fields=NRF_WIFI_KEY_VALID|NRF_WIFI_KEY_TYPE_VALID|NRF_WIFI_KEY_IDX_VALID|NRF_WIFI_CIPHER_SUITE_VALID;
    if(seq&&seq_len)i.valid_fields|=NRF_WIFI_SEQ_VALID;
    enum nrf_wifi_status r=nrf_wifi_sys_fmac_add_key(rpu_ctx(),vif_idx(),&i,(const char*)(pairwise?peer:0));
    secure_zero(&i,sizeof(i));
    if(r!=NRF_WIFI_STATUS_SUCCESS)return NRF70_FACADE_IO;
    if(!pairwise){
        struct nrf_wifi_umac_key_info d={0};
        d.key_idx=key_idx;d.valid_fields=NRF_WIFI_KEY_IDX_VALID;
        d.nrf_wifi_flags=is_mgmt?(NRF_WIFI_KEY_DEFAULT|NRF_WIFI_KEY_DEFAULT_MGMT):(NRF_WIFI_KEY_DEFAULT|NRF_WIFI_KEY_DEFAULT_TYPE_MULTICAST);
        if(nrf_wifi_sys_fmac_set_key(rpu_ctx(),vif_idx(),&d)!=NRF_WIFI_STATUS_SUCCESS)return NRF70_FACADE_IO;
    }
    return 0;
}
int32_t nrf70_supp_host_ether_send(const uint8_t dst[6],uint16_t proto,const uint8_t *buf,size_t len){
    /* EAPOL goes out through the normal data path; must not require `linked`. */
    if(!initialized||!dst||!buf||len+14u>NRF70_FACADE_MAX_FRAME_LEN){counters.eapol_tx_failed++;return NRF70_FACADE_INVALID;}
    struct nbuf*n=nbuf_alloc((unsigned int)len+14u+TX_HEADROOM);
    if(!n){counters.eapol_tx_failed++;return NRF70_FACADE_NO_MEMORY;}
    nbuf_res(n,TX_HEADROOM);
    uint8_t*d=nbuf_put(n,(unsigned int)len+14u);
    if(!d){nbuf_free(n);counters.eapol_tx_failed++;return NRF70_FACADE_NO_MEMORY;}
    nrf70_os_memcpy(d,dst,6);nrf70_os_memcpy(d+6,sta_mac,6);d[12]=(uint8_t)(proto>>8);d[13]=(uint8_t)proto;
    nrf70_os_memcpy(d+14,buf,len);
    if(len>=7u)log_diag("EAPOL TX: len=%u type=%u key_info=%x",(unsigned)len,buf[1],((unsigned)buf[5]<<8)|buf[6]);
    if(nrf_wifi_fmac_start_xmit(rpu_ctx(),vif_idx(),n)!=NRF_WIFI_STATUS_SUCCESS){counters.eapol_tx_failed++;return NRF70_FACADE_IO;}
    counters.eapol_tx++;
    return 0;
}
static enum nrf_wifi_status conn_deauth(uint16_t reason) {
    struct nrf_wifi_umac_disconn_info d = {0};
    d.reason_code = reason;
    /* FMAC sets MAC_ADDR_VALID only for a nonzero peer. Without it the
     * command can return success without disconnecting the station. */
    nrf70_os_memcpy(d.mac_addr, conn.secured ? conn.found_bssid : conn.bssid, 6);
    return nrf_wifi_sys_fmac_deauth(rpu_ctx(), vif_idx(), &d);
}
void nrf70_supp_host_deauth(uint16_t reason_code){
    if(conn.state==CONN_IDLE)return;
    conn_fail(reason_code);
    conn_deauth(reason_code);
}
void nrf70_supp_host_completed(uint8_t rekey){
    if(rekey){counters.rekeys++;return;}
    struct nrf_wifi_umac_chg_sta_info i={0};
    i.sta_flags2.nrf_wifi_mask=NRF_WIFI_STA_FLAG_AUTHORIZED;
    i.sta_flags2.nrf_wifi_set=NRF_WIFI_STA_FLAG_AUTHORIZED;
    nrf70_os_memcpy(i.mac_addr,conn.found_bssid,6);
    if(nrf_wifi_sys_fmac_chg_sta(rpu_ctx(),vif_idx(),&i)!=NRF_WIFI_STATUS_SUCCESS){conn_fail(1);return;}
    conn.port_authorized=1;
    conn.state=CONN_AUTHORIZED;
    counters.handshakes_completed++;
    struct nrf70_facade_event e={.generation=generation,.kind=NRF70_FACADE_EVENT_PORT_AUTHORIZED,.frequency_mhz=associated_frequency,.rssi_dbm=current_rssi};
    enqueue_event(&e,1);
}

/* Runs at most one bounded action; returns 1 when work was done. */
static uint32_t conn_step(void){
    if(conn_stepping)return 0;
    conn_stepping=1;
    uint32_t did=1;
    if(conn.teardown){conn_teardown_now();conn_stepping=0;return 1;}
    switch(conn.state){
    case CONN_DERIVE:{
        int32_t r=nrf70_supp_pbkdf2_step(conn.pmk);
        if(r<0)conn_fail(1);
        else if(r==1){log_msg(1,"connect: PMK derived; fetching AP RSN IE");conn.pmk_ready=1;conn.state=CONN_SCAN_START;}
        break;}
    case CONN_SCAN_START:{
        /* Same over-copy contract as nrf70_facade_scan_start: the FMAC reads
         * sizeof(struct nrf_wifi_channel) per channel from this buffer, so
         * reserve zeroed slack beyond the single meaningful frequency. */
        struct __attribute__((packed)){struct nrf_wifi_umac_scan_info info;union{unsigned int frequency[1];unsigned char reserve[sizeof(struct nrf_wifi_channel)];}ch;}scan={0};
        scan.info.scan_reason=SCAN_CONNECT;
        scan.info.scan_params.bands=conn.frequency<3000?NRF_WIFI_SCAN_BAND_2GHZ:NRF_WIFI_SCAN_BAND_5GHZ;
        scan.info.scan_params.num_scan_ssids=1;
        scan.info.scan_params.scan_ssids[0].nrf_wifi_ssid_len=conn.ssid_len;
        nrf70_os_memcpy(scan.info.scan_params.scan_ssids[0].nrf_wifi_ssid,conn.ssid,conn.ssid_len);
        scan.info.scan_params.num_scan_channels=1;
        scan.info.scan_params.dwell_time_active=50;
        scan.info.scan_params.dwell_time_passive=130;
        scan.ch.frequency[0]=conn.frequency;
        scan_command_active=1;
        enum nrf_wifi_status r=nrf_wifi_sys_fmac_scan(rpu_ctx(),vif_idx(),&scan.info);
        scan_command_active=0;
        if(r!=NRF_WIFI_STATUS_SUCCESS)conn_fail(1);
        else conn.state=CONN_SCAN_WAIT;
        break;}
    case CONN_SCAN_WAIT:
        if(conn.scan_fetch){conn.scan_fetch=0;if(nrf_wifi_sys_fmac_scan_res_get(rpu_ctx(),vif_idx(),SCAN_CONNECT)!=NRF_WIFI_STATUS_SUCCESS)conn_fail(1);}
        else if(conn.scan_done){if(!conn.rsn_ie_len){log_msg(3,"connect: no AP RSN IE received");conn_fail(1);}else conn.state=CONN_AUTH_START;}
        else did=0;
        break;
    case CONN_AUTH_START:{
        log_msg(1,"connect: authenticating");
        struct nrf_wifi_umac_auth_info a={0};
        a.frequency=conn.frequency;
        a.auth_type=NRF_WIFI_AUTHTYPE_OPEN_SYSTEM;
        a.ssid.nrf_wifi_ssid_len=conn.ssid_len;
        nrf70_os_memcpy(a.ssid.nrf_wifi_ssid,conn.ssid,conn.ssid_len);
        nrf70_os_memcpy(a.nrf_wifi_bssid,conn.secured?conn.found_bssid:conn.bssid,6);
        associated_frequency=conn.frequency;
        if(nrf_wifi_sys_fmac_auth(rpu_ctx(),vif_idx(),&a)!=NRF_WIFI_STATUS_SUCCESS)conn_fail(1);
        else conn.state=CONN_AUTH_WAIT;
        break;}
    case CONN_AUTH_WAIT:
        if(conn.auth_fail)conn.teardown=1;/* AUTH event already carries the failure */
        else if(conn.auth_ok){conn.auth_ok=0;conn.state=CONN_SUPP_SETUP;}
        else did=0;
        break;
    case CONN_SUPP_SETUP:{
        struct nrf_wifi_umac_assoc_info a={0};
        if(conn.secured){
            struct conn_rsn_info rsn;
            if(conn_parse_rsn(conn.rsn_ie,conn.rsn_ie_len,&rsn)){
                secure_zero(conn.pmk,sizeof(conn.pmk));conn.pmk_ready=0;
                conn_fail_ex(NRF70_FACADE_INVALID,0);break; /* malformed AP RSN IE */
            }
            if(!rsn.group_ccmp||!rsn.pairwise_ccmp){
                log_msg(3,"connect: AP does not support the required CCMP ciphers");
                secure_zero(conn.pmk,sizeof(conn.pmk));conn.pmk_ready=0;conn_fail(0);break;
            }
            /* MFP policy vs AP capability: Required needs MFPC; an AP with
             * MFPR cannot be joined with MFP disabled. */
            if((conn.mfp==2&&!rsn.mfpc)||(rsn.mfpr&&conn.mfp==0)){
                secure_zero(conn.pmk,sizeof(conn.pmk));conn.pmk_ready=0;
                conn_fail(0);break;
            }
            /* AKM selection: mixed-AKM APs (PSK + PSK-SHA256) use plain PSK
             * for interop; PSK-SHA256 only when the AP offers nothing else. */
            uint8_t akm_sha256;
            if(rsn.has_psk)akm_sha256=0;
            else if(rsn.has_psk_sha256)akm_sha256=1;
            else{log_msg(3,"connect: AP RSN offers no PSK AKM (SAE-only/enterprise unsupported)");secure_zero(conn.pmk,sizeof(conn.pmk));conn.pmk_ready=0;conn_fail(0);break;}
            log_msg(1,akm_sha256?"connect: RSN accepts PSK-SHA256":"connect: RSN accepts WPA2-PSK");
            conn.assoc_ie_len=NRF70_SUPP_ASSOC_IE_MAX;
            int32_t r=nrf70_supp_start(sta_mac,conn.found_bssid,conn.pmk,conn.mfp,akm_sha256,conn.rsn_ie,conn.rsn_ie_len,conn.rsnxe_len?conn.rsnxe:0,conn.rsnxe_len,conn.assoc_ie,&conn.assoc_ie_len);
            secure_zero(conn.pmk,sizeof(conn.pmk));/* wpa_sm keeps the PMK for rekeying */
            conn.pmk_ready=0;
            if(r){conn_fail(1);break;}
            a.wpa_ie.ie_len=conn.assoc_ie_len;
            nrf70_os_memcpy(a.wpa_ie.ie,conn.assoc_ie,conn.assoc_ie_len);
            a.control_port=1;
            /* use_mfp is the boolean "MFP will actually be used for this
             * association", not the 3-valued policy. */
            a.use_mfp=(conn.mfp==2||(conn.mfp==1&&rsn.mfpc))?1:0;
        }else a.control_port=0;
        a.center_frequency=conn.frequency;
        a.ssid.nrf_wifi_ssid_len=conn.ssid_len;
        nrf70_os_memcpy(a.ssid.nrf_wifi_ssid,conn.ssid,conn.ssid_len);
        nrf70_os_memcpy(a.nrf_wifi_bssid,conn.secured?conn.found_bssid:conn.bssid,6);
        log_msg(1,"connect: associating");
        if(nrf_wifi_sys_fmac_assoc(rpu_ctx(),vif_idx(),&a)!=NRF_WIFI_STATUS_SUCCESS)conn_fail(1);
        else conn.state=CONN_ASSOC_WAIT;
        break;}
    case CONN_ASSOC_WAIT:
        if(conn.assoc_fail)conn.teardown=1;/* ASSOC event already carries the failure */
        else if(conn.assoc_ok){
            conn.assoc_ok=0;
            if(conn.secured){log_msg(1,"connect: associated; waiting for EAPOL handshake");nrf70_supp_notify_assoc(conn.found_bssid);conn.state=CONN_HANDSHAKE;}
            else conn.state=CONN_AUTHORIZED;/* open completion is LINK up */
        }else did=0;
        break;
    case CONN_HANDSHAKE:
    case CONN_AUTHORIZED:
        if(eapol_count){
            struct eapol_slot*s=&eapol_slots[eapol_read];
            nrf70_supp_rx_eapol(s->src,s->frame,s->length);
            secure_zero(s,sizeof(*s));
            eapol_read=(uint8_t)((eapol_read+1u)%EAPOL_SLOTS);
            eapol_count--;
        }else did=0;
        break;
    default:did=0;break;
    }
    conn_stepping=0;
    return did;
}

int32_t nrf70_facade_connect_start(const struct nrf70_facade_connect_request*q){
    static const uint8_t zero_bssid[6]={0};
    if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;
    if(faulted)return NRF70_FACADE_FATAL;
    if(scan_active||conn.state!=CONN_IDLE)return NRF70_FACADE_BUSY;
    if(!q||q->ssid_len<1||q->ssid_len>NRF70_FACADE_MAX_SSID_LEN)return NRF70_FACADE_INVALID;
    if(!((q->frequency_mhz>=2412&&q->frequency_mhz<=2484)||(q->frequency_mhz>=4900&&q->frequency_mhz<=5900)))return NRF70_FACADE_INVALID;
    if(q->mfp>2)return NRF70_FACADE_INVALID;
    if(q->security==NRF70_FACADE_SECURITY_OPEN){
        if(q->credential_kind!=NRF70_FACADE_CREDENTIAL_NONE)return NRF70_FACADE_INVALID;
    }else if(q->security==NRF70_FACADE_SECURITY_WPA2_PSK||q->security==NRF70_FACADE_SECURITY_WPA2_PSK_SHA256){
        if(q->credential_kind==NRF70_FACADE_CREDENTIAL_PASSPHRASE){
            if(q->credential_len<8||q->credential_len>63)return NRF70_FACADE_INVALID;
        }else if(q->credential_kind==NRF70_FACADE_CREDENTIAL_PSK){
            if(q->credential_len!=NRF70_SUPP_PMK_LEN)return NRF70_FACADE_INVALID;
        }else return NRF70_FACADE_INVALID;
    }else return NRF70_FACADE_INVALID;
    conn_reset();
    conn.security=q->security;
    conn.secured=q->security!=NRF70_FACADE_SECURITY_OPEN;
    conn.mfp=conn.secured?q->mfp:0;/* MFP forced off for open networks */
    conn.ssid_len=q->ssid_len;
    nrf70_os_memcpy(conn.ssid,q->ssid,q->ssid_len);
    nrf70_os_memcpy(conn.bssid,q->bssid,6);
    conn.have_bssid=nrf70_os_memcmp(q->bssid,zero_bssid,6)!=0;
    conn.frequency=q->frequency_mhz;
    if(!conn.secured){
        conn.state=CONN_AUTH_START;
    }else if(q->credential_kind==NRF70_FACADE_CREDENTIAL_PSK){
        nrf70_os_memcpy(conn.pmk,q->credential,NRF70_SUPP_PMK_LEN);
        conn.pmk_ready=1;
        conn.state=CONN_SCAN_START;
    }else{
        if(nrf70_supp_pbkdf2_start(q->credential,q->credential_len,q->ssid,q->ssid_len)){conn_reset();return NRF70_FACADE_INVALID;}
        conn.state=CONN_DERIVE;
    }
    return 0;
}
int32_t nrf70_facade_connect_abort(uint16_t reason){
    if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;
    if(conn.state==CONN_IDLE)return NRF70_FACADE_NOT_CONNECTED;
    if(conn.state>=CONN_AUTH_WAIT||linked)conn_deauth(reason);
    conn_teardown_now();
    return 0;
}
int32_t nrf70_facade_disconnect(uint16_t reason){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;uint32_t s=now_us();enum nrf_wifi_status r=conn_deauth(reason);account_call(s);conn_teardown_now();return r==NRF_WIFI_STATUS_SUCCESS?0:NRF70_FACADE_IO;}
static int convert_key(const struct nrf70_facade_key*k,struct nrf_wifi_umac_key_info*out){if(!k||k->key_type>NRF70_FACADE_KEY_PEER||k->key_len>NRF70_FACADE_MAX_KEY_LEN||k->seq_len>NRF70_FACADE_MAX_SEQ_LEN)return 0;nrf70_os_memset(out,0,sizeof(*out));out->key_type=k->key_type;out->key_idx=k->key_index;out->cipher_suite=k->cipher_suite;out->key.nrf_wifi_key_len=k->key_len;nrf70_os_memcpy(out->key.nrf_wifi_key,k->key,k->key_len);out->seq.nrf_wifi_seq_len=k->seq_len;nrf70_os_memcpy(out->seq.nrf_wifi_seq,k->sequence,k->seq_len);out->valid_fields=NRF_WIFI_KEY_VALID|NRF_WIFI_KEY_TYPE_VALID|NRF_WIFI_KEY_IDX_VALID|NRF_WIFI_CIPHER_SUITE_VALID;if(k->seq_len)out->valid_fields|=NRF_WIFI_SEQ_VALID;return 1;}
int32_t nrf70_facade_key_install(const struct nrf70_facade_key*k){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;struct nrf_wifi_umac_key_info i;if(!convert_key(k,&i))return NRF70_FACADE_INVALID;return nrf_wifi_sys_fmac_add_key(rpu_ctx(),vif_idx(),&i,(const char*)k->peer)==NRF_WIFI_STATUS_SUCCESS?0:NRF70_FACADE_IO;}
int32_t nrf70_facade_key_remove(const struct nrf70_facade_key*k){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;struct nrf_wifi_umac_key_info i;if(!convert_key(k,&i))return NRF70_FACADE_INVALID;return nrf_wifi_sys_fmac_del_key(rpu_ctx(),vif_idx(),&i,(const char*)k->peer)==NRF_WIFI_STATUS_SUCCESS?0:NRF70_FACADE_IO;}
int32_t nrf70_facade_controlled_port(uint8_t authorized,const uint8_t peer[6]){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;if(!peer)return NRF70_FACADE_INVALID;struct nrf_wifi_umac_chg_sta_info i={0};i.sta_flags2.nrf_wifi_mask=NRF_WIFI_STA_FLAG_AUTHORIZED;i.sta_flags2.nrf_wifi_set=authorized?NRF_WIFI_STA_FLAG_AUTHORIZED:0;nrf70_os_memcpy(i.mac_addr,peer,6);return nrf_wifi_sys_fmac_chg_sta(rpu_ctx(),vif_idx(),&i)==NRF_WIFI_STATUS_SUCCESS?0:NRF70_FACADE_IO;}
int32_t nrf70_facade_set_power_save(uint8_t enabled){if(!initialized)return NRF70_FACADE_NOT_INITIALIZED;return nrf_wifi_sys_fmac_set_power_save(rpu_ctx(),vif_idx(),enabled!=0)==NRF_WIFI_STATUS_SUCCESS?0:NRF70_FACADE_IO;}
/* Non-PTA registers first, then the PTA table, as sdk-nrf's coex samples do. */
int32_t nrf70_facade_coex_configure(uint8_t sr_protocol) {
    if (!initialized) return NRF70_FACADE_NOT_INITIALIZED;
    if (sr_protocol > NRF70_FACADE_COEX_SR_IEEE802154) return NRF70_FACADE_INVALID;
    bool ble = sr_protocol == NRF70_FACADE_COEX_SR_BLE;
    uint32_t s = now_us();
    int r = nrf70_coex_config_non_pta(rpu_ctx(), ble);
    if (!r) r = nrf70_coex_config_pta(rpu_ctx(), NRF70_COEX_WLAN_OP_BAND_2_4_GHZ, ble);
    account_call(s);
    if (faulted) return NRF70_FACADE_FATAL;
    return r ? NRF70_FACADE_IO : 0;
}
int32_t nrf70_facade_coex_reset(void) {
    if (!initialized) return NRF70_FACADE_NOT_INITIALIZED;
    uint32_t s = now_us();
    int r = nrf70_coex_hw_reset(rpu_ctx());
    account_call(s);
    if (faulted) return NRF70_FACADE_FATAL;
    return r ? NRF70_FACADE_IO : 0;
}
int32_t nrf70_facade_tx(uint32_t token, const uint8_t *frame, uint16_t length) {
    if (!initialized) return NRF70_FACADE_NOT_INITIALIZED;
    if (!linked) return NRF70_FACADE_NOT_CONNECTED;
    /* EAPOL bypasses this controlled-port gate via the supplicant. */
    if (conn.secured && conn.state != CONN_IDLE && conn.state != CONN_AUTHORIZED)
        return NRF70_FACADE_NOT_CONNECTED;
    if (!frame || length < 14 || length > NRF70_FACADE_MAX_FRAME_LEN)
        return NRF70_FACADE_INVALID;
    struct nbuf *n = nbuf_alloc((unsigned int)length + TX_HEADROOM);
    if (!n) return NRF70_FACADE_NO_MEMORY;
    nbuf_res(n, TX_HEADROOM);
    void *d = nbuf_put(n, length);
    if (!d) { nbuf_free(n); return NRF70_FACADE_NO_MEMORY; }
    nrf70_os_memcpy(d, frame, length);
    counters.tx_copies++;
    n->facade_tx = 1;
    n->tx_token = token;
    counters.tx_submitted++;
    tx_in_call = n;
    tx_freed_in_call = 0;
    enum nrf_wifi_status r = nrf_wifi_fmac_start_xmit(rpu_ctx(), vif_idx(), n);
    tx_in_call = 0;
    if (tx_freed_in_call) {
        tx_freed_in_call = 0;
        tx_complete(token, r == NRF_WIFI_STATUS_SUCCESS ? NRF70_FACADE_OK : NRF70_FACADE_IO);
    }
    if (r != NRF_WIFI_STATUS_SUCCESS) {
        counters.tx_queue_full++;
        return NRF70_FACADE_QUEUE_FULL;
    }
    return NRF70_FACADE_OK;
}
int32_t nrf70_facade_rx_pop(uint8_t*frame,uint16_t capacity,struct nrf70_facade_rx_meta*meta){if(!frame||!meta)return NRF70_FACADE_INVALID;if(!rx_count)return 0;struct rx_slot*s=&rx_slots[rx_read];if(capacity<s->length)return NRF70_FACADE_INVALID;nrf70_os_memcpy(frame,s->frame,s->length);nrf70_os_memset(meta,0,sizeof(*meta));meta->generation=generation;meta->length=s->length;meta->rssi_dbm=s->rssi;rx_read=(uint8_t)((rx_read+1u)%RX_SLOTS);rx_count--;counters.rx_delivered++;return 1;}
void nrf70_facade_notify_host_irq(void){irq_pending=1;}
uint32_t nrf70_facade_process(uint32_t budget){if(faulted)return 0;uint32_t ran=0;while(ran<budget){uint8_t did=0;if(irq_pending&&irq_callback&&ran<budget){irq_pending=0;irq_callback(irq_data);ran++;did=1;}if(scan_fetch_pending&&!scan_command_active&&ran<budget){scan_fetch_pending=0;if(nrf_wifi_sys_fmac_scan_res_get(fmac_dev,sta_vif_idx,SCAN_DISPLAY)!=NRF_WIFI_STATUS_SUCCESS)fatal(NRF70_FACADE_IO,"scan result fetch");ran++;did=1;}if((conn.state!=CONN_IDLE||conn.teardown)&&!conn_stepping&&!scan_command_active&&ran<budget&&conn_step()){ran++;did=1;}if(!conn_stepping&&nrf70_supp_active()&&ran<budget){conn_stepping=1;uint32_t t=nrf70_supp_eloop_poll(now_us());conn_stepping=0;if(t){ran++;did=1;}}for(unsigned i=0;i<TASKLET_SLOTS&&ran<budget;i++)if(tasklets[i].used&&tasklets[i].pending){tasklets[i].pending=0;if(tasklets[i].fn)tasklets[i].fn(tasklets[i].data);ran++;did=1;}uint32_t n=now_us();for(unsigned i=0;i<TIMER_SLOTS&&ran<budget;i++)if(timers[i].used&&timers[i].armed&&(int32_t)(n-timers[i].deadline)>=0){timers[i].armed=0;if(timers[i].fn)timers[i].fn(timers[i].data);ran++;did=1;}if(!did)break;}return ran;}
int32_t nrf70_facade_event_pop(struct nrf70_facade_event*e){if(!e)return NRF70_FACADE_INVALID;if(!event_count)return 0;*e=events[event_read];event_read=(event_read+1u)%EVENT_SLOTS;event_count--;return 1;}
void nrf70_facade_stats_get(struct nrf70_facade_stats*s){if(s)*s=counters;}uint8_t nrf70_facade_host_irq_active(void){return platform&&platform->host_irq_active?platform->host_irq_active(platform->context):0;}uint32_t nrf70_facade_now_us(void){return now_us();}
uint32_t nrf70_facade_sizeof_scan_request(void){return sizeof(struct nrf70_facade_scan_request);}uint32_t nrf70_facade_alignof_scan_request(void){return _Alignof(struct nrf70_facade_scan_request);}uint32_t nrf70_facade_sizeof_scan_result(void){return sizeof(struct nrf70_facade_scan_result);}uint32_t nrf70_facade_sizeof_connect_request(void){return sizeof(struct nrf70_facade_connect_request);}uint32_t nrf70_facade_sizeof_key(void){return sizeof(struct nrf70_facade_key);}uint32_t nrf70_facade_sizeof_event(void){return sizeof(struct nrf70_facade_event);}uint32_t nrf70_facade_sizeof_rx_meta(void){return sizeof(struct nrf70_facade_rx_meta);}uint32_t nrf70_facade_sizeof_stats(void){return sizeof(struct nrf70_facade_stats);}

_Static_assert(sizeof(enum nrf70_facade_status)==4,"facade enums must be 32-bit");
_Static_assert(sizeof(struct nrf70_facade_channel)==2,"channel ABI");
_Static_assert(offsetof(struct nrf70_facade_event,scan)==20,"event ABI");
