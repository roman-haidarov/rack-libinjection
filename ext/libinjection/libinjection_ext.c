#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

#include "ruby.h"
#include "ruby/thread.h"

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <string.h>
#include <stdlib.h>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

#include "libinjection.h"
#include "libinjection_html5.h"
#include "libinjection_sqli.h"
#include "libinjection_xss.h"

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static VALUE mLibInjection;
static VALUE eError;
static VALUE eParserError;
static VALUE eArgumentError;
static VALUE sym_sqli;
static VALUE sym_xss;

#define LI_REQUIRED_LIBINJECTION_VERSION "4.0.0"

#define LI_ARRAY_LEN(a)          (sizeof(a) / sizeof((a)[0]))
#define LI_SQLI_FINGERPRINT_SIZE (sizeof(((struct libinjection_sqli_state *)0)->fingerprint))
#ifndef LI_NOGVL_THRESHOLD
#define LI_NOGVL_THRESHOLD 1024
#endif
#ifndef LI_URL_DECODE_STACK_THRESHOLD
#define LI_URL_DECODE_STACK_THRESHOLD 8192
#endif
#if LI_URL_DECODE_STACK_THRESHOLD > 8192
#error "LI_URL_DECODE_STACK_THRESHOLD must stay <= 8192"
#endif
#ifndef LI_MAX_URL_DECODE_DEPTH
#define LI_MAX_URL_DECODE_DEPTH 32
#endif

struct li_named_int {
    const char *name;
    int value;
};

struct li_named_char {
    const char *name;
    int value;
};

static const struct li_named_int SQLI_CONTEXTS[] = {
    {"none_ansi", FLAG_QUOTE_NONE | FLAG_SQL_ANSI},
    {"none_mysql", FLAG_QUOTE_NONE | FLAG_SQL_MYSQL},
    {"single_ansi", FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI},
    {"single_mysql", FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL},
    {"double_ansi", FLAG_QUOTE_DOUBLE | FLAG_SQL_ANSI},
    {"double_mysql", FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL},
};

static const struct li_named_int SQLI_QUOTES[] = {
    {"none", FLAG_QUOTE_NONE},
    {"single", FLAG_QUOTE_SINGLE},
    {"double", FLAG_QUOTE_DOUBLE},
};

static const struct li_named_int SQLI_DIALECTS[] = {
    {"ansi", FLAG_SQL_ANSI},
    {"mysql", FLAG_SQL_MYSQL},
};

static const struct li_named_char SQLI_TOKEN_TYPES[] = {
    {"keyword", 'k'},    {"union", 'U'},       {"group", 'B'},       {"expression", 'E'},
    {"sqltype", 't'},    {"function", 'f'},    {"bareword", 'n'},    {"number", '1'},
    {"variable", 'v'},   {"string", 's'},      {"operator", 'o'},    {"logic_operator", '&'},
    {"comment", 'c'},    {"collate", 'A'},     {"left_parens", '('}, {"right_parens", ')'},
    {"left_brace", '{'}, {"right_brace", '}'}, {"dot", '.'},         {"comma", ','},
    {"colon", ':'},      {"semicolon", ';'},   {"tsql", 'T'},        {"unknown", '?'},
    {"evil", 'X'},       {"fingerprint", 'F'}, {"backslash", '\\'},
};

static const struct li_named_int HTML5_CONTEXTS[] = {
    {"data", DATA_STATE},
    {"value_no_quote", VALUE_NO_QUOTE},
    {"value_single_quote", VALUE_SINGLE_QUOTE},
    {"value_double_quote", VALUE_DOUBLE_QUOTE},
    {"value_back_quote", VALUE_BACK_QUOTE},
};

static const struct li_named_int HTML5_TOKEN_TYPES[] = {
    {"data_text", DATA_TEXT},
    {"tag_name_open", TAG_NAME_OPEN},
    {"tag_name_close", TAG_NAME_CLOSE},
    {"tag_name_selfclose", TAG_NAME_SELFCLOSE},
    {"tag_data", TAG_DATA},
    {"tag_close", TAG_CLOSE},
    {"attr_name", ATTR_NAME},
    {"attr_value", ATTR_VALUE},
    {"tag_comment", TAG_COMMENT},
    {"doctype", DOCTYPE},
};

static VALUE li_str(VALUE input) {
    StringValue(input);
    return input;
}

typedef struct {
    VALUE str;
    const char *ptr;
    size_t len;
    char *copy;
} li_input_t;

static li_input_t li_input_prepare(VALUE input) {
    li_input_t in;
    in.str = li_str(input);
    in.len = (size_t)RSTRING_LEN(in.str);
    in.copy = NULL;

    if (in.len == 0) {
        in.ptr = RSTRING_PTR(in.str);
        return in;
    }

    if (in.len >= (size_t)LI_NOGVL_THRESHOLD) {
        in.copy = (char *)ruby_xmalloc(in.len);
        memcpy(in.copy, RSTRING_PTR(in.str), in.len);
        in.ptr = in.copy;
    } else {
        in.ptr = RSTRING_PTR(in.str);
    }

    return in;
}

static void li_input_release(li_input_t *in) {
    if (in->copy != NULL) {
        ruby_xfree(in->copy);
        in->copy = NULL;
    }
}

static VALUE li_id_sym(const char *name) {
    return ID2SYM(rb_intern(name));
}

static VALUE li_hash_aref(VALUE hash, const char *key) {
    if (NIL_P(hash)) {
        return Qundef;
    }
    return rb_hash_lookup2(hash, li_id_sym(key), Qundef);
}

static const char *li_key_name(VALUE key) {
    if (SYMBOL_P(key)) {
        return rb_id2name(SYM2ID(key));
    }

    StringValue(key);
    return StringValueCStr(key);
}

static int li_lookup_named_int(const struct li_named_int *table, size_t table_len, VALUE key,
                               int *out) {
    const char *name;
    size_t i;

    if (NIL_P(key) || key == Qundef) {
        return 0;
    }

    if (RB_INTEGER_TYPE_P(key)) {
        *out = NUM2INT(key);
        return 1;
    }

    name = li_key_name(key);
    for (i = 0; i < table_len; i++) {
        if (strcmp(table[i].name, name) == 0) {
            *out = table[i].value;
            return 1;
        }
    }

    return 0;
}

static const char *li_lookup_name_by_int(const struct li_named_int *table, size_t table_len,
                                         int value) {
    size_t i;
    for (i = 0; i < table_len; i++) {
        if (table[i].value == value) {
            return table[i].name;
        }
    }
    return NULL;
}

static const char *li_lookup_name_by_char(const struct li_named_char *table, size_t table_len,
                                          int value) {
    size_t i;
    for (i = 0; i < table_len; i++) {
        if (table[i].value == value) {
            return table[i].name;
        }
    }
    return NULL;
}

static VALUE li_symbol_for_int(const struct li_named_int *table, size_t table_len, int value) {
    const char *name = li_lookup_name_by_int(table, table_len, value);
    return name ? li_id_sym(name) : Qnil;
}

static VALUE li_symbol_for_char(const struct li_named_char *table, size_t table_len, int value) {
    const char *name = li_lookup_name_by_char(table, table_len, value);
    return name ? li_id_sym(name) : Qnil;
}

static VALUE li_char_string(int ch) {
    char buf[1];
    if (ch == 0) {
        return Qnil;
    }
    buf[0] = (char)ch;
    return rb_str_new(buf, 1);
}

static VALUE li_named_int_hash(const struct li_named_int *table, size_t table_len) {
    VALUE hash = rb_hash_new();
    size_t i;
    for (i = 0; i < table_len; i++) {
        rb_hash_aset(hash, li_id_sym(table[i].name), INT2NUM(table[i].value));
    }
    return rb_hash_freeze(hash);
}

static VALUE li_named_char_hash(const struct li_named_char *table, size_t table_len) {
    VALUE hash = rb_hash_new();
    size_t i;
    for (i = 0; i < table_len; i++) {
        rb_hash_aset(hash, li_id_sym(table[i].name), li_char_string(table[i].value));
    }
    return rb_hash_freeze(hash);
}

static VALUE li_hash_opts(VALUE opts) {
    if (NIL_P(opts)) {
        return Qnil;
    }

    opts = rb_check_hash_type(opts);
    if (NIL_P(opts)) {
        rb_raise(eArgumentError, "options must be a Hash");
    }

    return opts;
}

static void raise_on_error(injection_result_t result) {
    if (result == LIBINJECTION_RESULT_ERROR) {
        rb_raise(eParserError, "libinjection parser error");
    }
}

static size_t li_bounded_strlen(const char *str, size_t max_len) {
    size_t len = 0;

    while (len < max_len && str[len] != '\0') {
        len++;
    }

    return len;
}

static VALUE li_sqli_fingerprint_value(const char *fingerprint) {
    size_t len = li_bounded_strlen(fingerprint, LI_SQLI_FINGERPRINT_SIZE);

    return len == 0 ? Qnil : rb_str_new(fingerprint, (long)len);
}

typedef struct {
    const char *src;
    size_t len;

    int want_sqli;
    int sqli_flags;
    int sqli_detected;
    char sqli_fingerprint[LI_SQLI_FINGERPRINT_SIZE];
    injection_result_t sqli_result;

    int want_xss;
    int xss_detected;
    injection_result_t xss_result;
} li_scan_work_t;

static void li_scan_perform(li_scan_work_t *work) {
    if (work->want_sqli) {
        if (work->sqli_flags == 0) {
            work->sqli_result = libinjection_sqli(work->src, work->len, work->sqli_fingerprint);
            work->sqli_detected = (work->sqli_result == LIBINJECTION_RESULT_TRUE);
        } else {
            struct libinjection_sqli_state state;
            libinjection_sqli_init(&state, work->src, work->len, work->sqli_flags);
            libinjection_sqli_fingerprint(&state, work->sqli_flags);
            work->sqli_detected = libinjection_sqli_check_fingerprint(&state) ? 1 : 0;
            work->sqli_result =
                work->sqli_detected ? LIBINJECTION_RESULT_TRUE : LIBINJECTION_RESULT_FALSE;
            memcpy(work->sqli_fingerprint, state.fingerprint, sizeof(work->sqli_fingerprint));
            work->sqli_fingerprint[sizeof(work->sqli_fingerprint) - 1] = '\0';
        }

        if (work->sqli_detected && work->want_xss) {
            work->want_xss = 0;
        }
    }

    if (work->want_xss) {
        work->xss_result = libinjection_xss(work->src, work->len);
        work->xss_detected = (work->xss_result == LIBINJECTION_RESULT_TRUE);
    }
}

static void *li_scan_nogvl_thunk(void *data) {
    li_scan_perform((li_scan_work_t *)data);
    return NULL;
}

static inline void li_scan_release_gvl(li_scan_work_t *work) {
#if defined(RB_NOGVL_OFFLOAD_SAFE)
    rb_nogvl(li_scan_nogvl_thunk, work, RUBY_UBF_PROCESS, NULL, RB_NOGVL_OFFLOAD_SAFE);
#else
    rb_thread_call_without_gvl(li_scan_nogvl_thunk, work, RUBY_UBF_PROCESS, NULL);
#endif
}

static inline void li_scan_run(li_scan_work_t *work) {
    if (work->len >= (size_t)LI_NOGVL_THRESHOLD) {
        li_scan_release_gvl(work);
    } else {
        li_scan_perform(work);
    }
}

#define LI_THREAT_SQLI 1
#define LI_THREAT_XSS  2
#define LI_THREAT_BOTH (LI_THREAT_SQLI | LI_THREAT_XSS)

typedef struct {
    int found_type;
    char sqli_fingerprint[LI_SQLI_FINGERPRINT_SIZE];
    injection_result_t sqli_result;
    injection_result_t xss_result;
} li_scan_out_t;

static void li_scan_out_reset(li_scan_out_t *out) {
    out->found_type = 0;
    out->sqli_fingerprint[0] = '\0';
    out->sqli_result = LIBINJECTION_RESULT_FALSE;
    out->xss_result = LIBINJECTION_RESULT_FALSE;
}

static void li_scan_buffer(const char *src, size_t len, int threat_mask, li_scan_out_t *out) {
    li_scan_work_t work = {0};
    work.src = src;
    work.len = len;
    work.want_sqli = (threat_mask & LI_THREAT_SQLI) != 0;
    work.want_xss = (threat_mask & LI_THREAT_XSS) != 0;

    li_scan_run(&work);

    out->sqli_result = work.sqli_result;
    out->xss_result = work.xss_result;

    if (work.sqli_detected) {
        out->found_type = LI_THREAT_SQLI;
        memcpy(out->sqli_fingerprint, work.sqli_fingerprint, sizeof(out->sqli_fingerprint));
    } else if (work.xss_detected) {
        out->found_type = LI_THREAT_XSS;
    }
}

static int li_hex_value(unsigned char ch) {
    if (ch >= '0' && ch <= '9') {
        return (int)(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return (int)(ch - 'a' + 10);
    }
    if (ch >= 'A' && ch <= 'F') {
        return (int)(ch - 'A' + 10);
    }
    return -1;
}

static int li_url_encoded_candidate(const char *src, size_t len, int plus_as_space) {
    size_t i;
    if (len == 0) {
        return 0;
    }

    if (plus_as_space && memchr(src, '+', len) != NULL) {
        return 1;
    }

    for (i = 0; i < len; i++) {
        if (src[i] == '%') {
            return 1;
        }
    }
    return 0;
}

static int li_url_decode_into(char *dst, const char *src, size_t len, size_t *out_len,
                              int plus_as_space) {
    size_t i = 0;
    size_t j = 0;

    while (i < len) {
        unsigned char ch = (unsigned char)src[i];

        if (ch == '%') {
            int hi = -1;
            int lo = -1;
            if (i + 2 < len) {
                hi = li_hex_value((unsigned char)src[i + 1]);
                lo = li_hex_value((unsigned char)src[i + 2]);
            }
            if (hi >= 0 && lo >= 0) {
                dst[j++] = (char)((hi << 4) | lo);
                i += 3;
                continue;
            }

            dst[j++] = (char)ch;
            i++;
            continue;
        }

        if (plus_as_space && ch == '+') {
            dst[j++] = ' ';
        } else {
            dst[j++] = (char)ch;
        }
        i++;
    }

    *out_len = j;
    return 1;
}

static VALUE li_scan_out_to_value(const li_scan_out_t *out) {
    if (out->found_type == LI_THREAT_SQLI) {
        return rb_ary_new3(2, sym_sqli, li_sqli_fingerprint_value(out->sqli_fingerprint));
    }
    if (out->found_type == LI_THREAT_XSS) {
        return rb_ary_new3(2, sym_xss, Qnil);
    }
    return Qnil;
}

static int li_sqli_flags_from_opts(VALUE opts, int fallback) {
    VALUE raw_flags;
    VALUE context;
    VALUE quote;
    VALUE dialect;
    int flags;
    int quote_flags;
    int dialect_flags;

    opts = li_hash_opts(opts);
    if (NIL_P(opts)) {
        return fallback;
    }

    raw_flags = li_hash_aref(opts, "flags");
    if (raw_flags != Qundef) {
        return NUM2INT(raw_flags);
    }

    context = li_hash_aref(opts, "context");
    if (context != Qundef) {
        if (!li_lookup_named_int(SQLI_CONTEXTS, LI_ARRAY_LEN(SQLI_CONTEXTS), context, &flags)) {
            rb_raise(eArgumentError, "unknown SQLi context");
        }
        return flags;
    }

    quote_flags = FLAG_QUOTE_NONE;
    dialect_flags = FLAG_SQL_ANSI;

    quote = li_hash_aref(opts, "quote");
    if (quote != Qundef &&
        !li_lookup_named_int(SQLI_QUOTES, LI_ARRAY_LEN(SQLI_QUOTES), quote, &quote_flags)) {
        rb_raise(eArgumentError, "unknown SQLi quote option");
    }

    dialect = li_hash_aref(opts, "dialect");
    if (dialect != Qundef &&
        !li_lookup_named_int(SQLI_DIALECTS, LI_ARRAY_LEN(SQLI_DIALECTS), dialect, &dialect_flags)) {
        rb_raise(eArgumentError, "unknown SQLi dialect option");
    }

    return quote_flags | dialect_flags;
}

static int li_html5_flags_from_opts(VALUE opts, int fallback) {
    VALUE raw_flags;
    VALUE context;
    int flags;

    opts = li_hash_opts(opts);
    if (NIL_P(opts)) {
        return fallback;
    }

    raw_flags = li_hash_aref(opts, "flags");
    if (raw_flags != Qundef) {
        return NUM2INT(raw_flags);
    }

    context = li_hash_aref(opts, "context");
    if (context == Qundef) {
        return fallback;
    }

    if (!li_lookup_named_int(HTML5_CONTEXTS, LI_ARRAY_LEN(HTML5_CONTEXTS), context, &flags)) {
        rb_raise(eArgumentError, "unknown HTML5/XSS context");
    }

    return flags;
}

static VALUE li_sqli_token_hash(const stoken_t *token) {
    VALUE hash = rb_hash_new();

    rb_hash_aset(hash, li_id_sym("type"),
                 li_symbol_for_char(SQLI_TOKEN_TYPES, LI_ARRAY_LEN(SQLI_TOKEN_TYPES), token->type));
    rb_hash_aset(hash, li_id_sym("code"), li_char_string(token->type));
    rb_hash_aset(hash, li_id_sym("value"), rb_str_new(token->val, token->len));
    rb_hash_aset(hash, li_id_sym("pos"), SIZET2NUM(token->pos));
    rb_hash_aset(hash, li_id_sym("length"), SIZET2NUM(token->len));
    rb_hash_aset(hash, li_id_sym("count"), INT2NUM(token->count));
    rb_hash_aset(hash, li_id_sym("str_open"), li_char_string(token->str_open));
    rb_hash_aset(hash, li_id_sym("str_close"), li_char_string(token->str_close));

    return hash;
}

static VALUE li_sqli_stats_hash(const struct libinjection_sqli_state *state) {
    VALUE hash = rb_hash_new();

    rb_hash_aset(hash, li_id_sym("reason"), INT2NUM(state->reason));
    rb_hash_aset(hash, li_id_sym("comment_ddw"), INT2NUM(state->stats_comment_ddw));
    rb_hash_aset(hash, li_id_sym("comment_ddx"), INT2NUM(state->stats_comment_ddx));
    rb_hash_aset(hash, li_id_sym("comment_c"), INT2NUM(state->stats_comment_c));
    rb_hash_aset(hash, li_id_sym("comment_hash"), INT2NUM(state->stats_comment_hash));
    rb_hash_aset(hash, li_id_sym("folds"), INT2NUM(state->stats_folds));
    rb_hash_aset(hash, li_id_sym("tokens"), INT2NUM(state->stats_tokens));

    return hash;
}

static VALUE li_sqli_result_hash(const struct libinjection_sqli_state *state,
                                 injection_result_t result, int flags, VALUE context_name) {
    VALUE hash = rb_hash_new();
    const char *fingerprint = state->fingerprint;

    rb_hash_aset(hash, li_id_sym("type"), sym_sqli);
    rb_hash_aset(hash, li_id_sym("detected"), result == LIBINJECTION_RESULT_TRUE ? Qtrue : Qfalse);
    rb_hash_aset(hash, li_id_sym("fingerprint"),
                 li_sqli_fingerprint_value(fingerprint));
    rb_hash_aset(hash, li_id_sym("flags"), INT2NUM(flags));
    rb_hash_aset(hash, li_id_sym("context"), context_name);
    rb_hash_aset(hash, li_id_sym("stats"), li_sqli_stats_hash(state));

    return hash;
}

static injection_result_t li_run_sqli_context(VALUE str, int flags,
                                              struct libinjection_sqli_state *state) {
    const char *fingerprint;
    libinjection_sqli_init(state, RSTRING_PTR(str), (size_t)RSTRING_LEN(str), flags);
    fingerprint = libinjection_sqli_fingerprint(state, flags);
    (void)fingerprint;
    return libinjection_sqli_check_fingerprint(state) ? LIBINJECTION_RESULT_TRUE
                                                      : LIBINJECTION_RESULT_FALSE;
}

typedef struct {
    VALUE input;
    li_input_t in;
    int input_prepared;
    li_scan_work_t work;
} li_work_scan_args_t;

static VALUE li_work_scan_body(VALUE data) {
    li_work_scan_args_t *args = (li_work_scan_args_t *)data;

    args->in = li_input_prepare(args->input);
    args->input_prepared = 1;
    args->work.src = args->in.ptr;
    args->work.len = args->in.len;
    li_scan_run(&args->work);

    return Qnil;
}

static VALUE li_work_scan_ensure(VALUE data) {
    li_work_scan_args_t *args = (li_work_scan_args_t *)data;

    if (args->input_prepared) {
        li_input_release(&args->in);
        RB_GC_GUARD(args->in.str);
    }

    return Qnil;
}

static VALUE rb_li_sqli_p(VALUE self, VALUE input) {
    li_work_scan_args_t args;

    (void)self;
    memset(&args, 0, sizeof(args));
    args.input = input;
    args.work.want_sqli = 1;

    rb_ensure(li_work_scan_body, (VALUE)&args, li_work_scan_ensure, (VALUE)&args);
    raise_on_error(args.work.sqli_result);

    return args.work.sqli_detected ? Qtrue : Qfalse;
}

static VALUE rb_li_sqli_fingerprint(VALUE self, VALUE input) {
    li_work_scan_args_t args;
    char fingerprint[LI_SQLI_FINGERPRINT_SIZE];

    (void)self;
    memset(&args, 0, sizeof(args));
    args.input = input;
    args.work.want_sqli = 1;
    memset(fingerprint, 0, sizeof(fingerprint));

    rb_ensure(li_work_scan_body, (VALUE)&args, li_work_scan_ensure, (VALUE)&args);
    memcpy(fingerprint, args.work.sqli_fingerprint, sizeof(fingerprint));
    raise_on_error(args.work.sqli_result);

    return args.work.sqli_detected ? li_sqli_fingerprint_value(fingerprint) : Qnil;
}

typedef struct {
    VALUE input;
    li_input_t in;
    int input_prepared;
    li_scan_out_t out;
} li_raw_scan_args_t;

static VALUE li_raw_scan_body(VALUE data) {
    li_raw_scan_args_t *args = (li_raw_scan_args_t *)data;

    args->in = li_input_prepare(args->input);
    args->input_prepared = 1;
    li_scan_out_reset(&args->out);
    li_scan_buffer(args->in.ptr, args->in.len, LI_THREAT_BOTH, &args->out);

    return Qnil;
}

static VALUE li_raw_scan_ensure(VALUE data) {
    li_raw_scan_args_t *args = (li_raw_scan_args_t *)data;

    if (args->input_prepared) {
        li_input_release(&args->in);
        RB_GC_GUARD(args->in.str);
    }

    return Qnil;
}

static VALUE rb_li_detect_raw(VALUE self, VALUE input) {
    li_raw_scan_args_t args;

    (void)self;
    memset(&args, 0, sizeof(args));
    args.input = input;
    li_scan_out_reset(&args.out);

    rb_ensure(li_raw_scan_body, (VALUE)&args, li_raw_scan_ensure, (VALUE)&args);
    raise_on_error(args.out.sqli_result);
    raise_on_error(args.out.xss_result);

    return li_scan_out_to_value(&args.out);
}

typedef struct {
    VALUE input;
    int depth;
    int plus_as_space;
    int threat_mask;
    li_scan_out_t out;
    li_input_t in;
    int input_prepared;
    char *decode_buffers[2];
    int decode_buffer_heap[2];
    injection_result_t sqli_error;
    injection_result_t xss_error;
} li_url_scan_args_t;

static VALUE li_detect_url_encoded_raw_body(VALUE data) {
    li_url_scan_args_t *args = (li_url_scan_args_t *)data;
    const char *src;
    size_t src_len;
    size_t decode_capacity;
    int level;

    args->in = li_input_prepare(args->input);
    args->input_prepared = 1;
    decode_capacity = args->in.len == 0 ? 1 : args->in.len;

    li_scan_out_reset(&args->out);
    li_scan_buffer(args->in.ptr, args->in.len, args->threat_mask, &args->out);
    if (args->out.sqli_result == LIBINJECTION_RESULT_ERROR ||
        args->out.xss_result == LIBINJECTION_RESULT_ERROR || args->out.found_type != 0 ||
        args->depth == 0 ||
        !li_url_encoded_candidate(args->in.ptr, args->in.len, args->plus_as_space)) {
        return Qnil;
    }

    src = args->in.ptr;
    src_len = args->in.len;
    for (level = 0; level < args->depth; level++) {
        int slot = level & 1;
        char *dst;
        size_t dst_len = 0;

        if (!li_url_encoded_candidate(src, src_len, args->plus_as_space)) {
            break;
        }

        dst = args->decode_buffers[slot];
        if (dst == NULL) {
            if (decode_capacity <= (size_t)LI_URL_DECODE_STACK_THRESHOLD) {
                dst = ALLOCA_N(char, decode_capacity);
            } else {
                dst = (char *)ruby_xmalloc(decode_capacity);
                args->decode_buffer_heap[slot] = 1;
            }
            args->decode_buffers[slot] = dst;
        }

        if (!li_url_decode_into(dst, src, src_len, &dst_len, args->plus_as_space)) {
            break;
        }
        if (dst_len == src_len && memcmp(dst, src, src_len) == 0) {
            break;
        }

        li_scan_out_reset(&args->out);
        li_scan_buffer(dst, dst_len, args->threat_mask, &args->out);
        if (args->out.sqli_result == LIBINJECTION_RESULT_ERROR ||
            args->out.xss_result == LIBINJECTION_RESULT_ERROR || args->out.found_type != 0) {
            break;
        }

        src = dst;
        src_len = dst_len;
    }

    return Qnil;
}

static VALUE li_detect_url_encoded_raw_ensure(VALUE data) {
    li_url_scan_args_t *args = (li_url_scan_args_t *)data;

    args->sqli_error = args->out.sqli_result;
    args->xss_error = args->out.xss_result;

    if (args->decode_buffer_heap[0] && args->decode_buffers[0] != NULL) {
        ruby_xfree(args->decode_buffers[0]);
        args->decode_buffers[0] = NULL;
    }
    if (args->decode_buffer_heap[1] && args->decode_buffers[1] != NULL) {
        ruby_xfree(args->decode_buffers[1]);
        args->decode_buffers[1] = NULL;
    }
    if (args->input_prepared) {
        li_input_release(&args->in);
        RB_GC_GUARD(args->in.str);
    }

    return Qnil;
}

static VALUE rb_li_detect_url_encoded_raw(VALUE self, VALUE input, VALUE depth_value,
                                          VALUE plus_as_space_value, VALUE threat_mask_value) {
    li_url_scan_args_t args;

    (void)self;
    memset(&args, 0, sizeof(args));
    args.input = input;
    args.depth = NUM2INT(depth_value);
    args.plus_as_space = RTEST(plus_as_space_value);
    args.threat_mask = NUM2INT(threat_mask_value);
    args.sqli_error = LIBINJECTION_RESULT_FALSE;
    args.xss_error = LIBINJECTION_RESULT_FALSE;
    li_scan_out_reset(&args.out);

    if (args.depth < 0) {
        rb_raise(eArgumentError, "depth must be >= 0");
    }
    if (args.depth > LI_MAX_URL_DECODE_DEPTH) {
        rb_raise(eArgumentError, "depth must be <= %d", LI_MAX_URL_DECODE_DEPTH);
    }
    if ((args.threat_mask & ~LI_THREAT_BOTH) != 0 || args.threat_mask == 0) {
        rb_raise(eArgumentError, "threat mask must include SQLi and/or XSS");
    }

    rb_ensure(li_detect_url_encoded_raw_body, (VALUE)&args, li_detect_url_encoded_raw_ensure,
              (VALUE)&args);
    raise_on_error(args.sqli_error);
    raise_on_error(args.xss_error);

    return li_scan_out_to_value(&args.out);
}

static VALUE rb_li_sqli_result(int argc, VALUE *argv, VALUE self) {
    VALUE input;
    VALUE opts;
    VALUE str;
    VALUE context_name = Qnil;
    int flags;
    struct libinjection_sqli_state state;
    injection_result_t result;

    (void)self;
    rb_scan_args(argc, argv, "11", &input, &opts);
    str = li_str(input);

    if (NIL_P(opts)) {
        libinjection_sqli_init(&state, RSTRING_PTR(str), (size_t)RSTRING_LEN(str), 0);
        result =
            libinjection_is_sqli(&state) ? LIBINJECTION_RESULT_TRUE : LIBINJECTION_RESULT_FALSE;
        raise_on_error(result);
        return li_sqli_result_hash(&state, result, 0, Qnil);
    }

    flags = li_sqli_flags_from_opts(opts, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    context_name = li_symbol_for_int(SQLI_CONTEXTS, LI_ARRAY_LEN(SQLI_CONTEXTS), flags);
    result = li_run_sqli_context(str, flags, &state);
    raise_on_error(result);

    return li_sqli_result_hash(&state, result, flags, context_name);
}

static VALUE rb_li_sqli_fingerprint_for(int argc, VALUE *argv, VALUE self) {
    VALUE input;
    VALUE opts;
    VALUE str;
    int flags;
    struct libinjection_sqli_state state;
    injection_result_t result;

    (void)self;
    rb_scan_args(argc, argv, "11", &input, &opts);
    str = li_str(input);
    flags = li_sqli_flags_from_opts(opts, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);

    result = li_run_sqli_context(str, flags, &state);
    raise_on_error(result);
    return li_sqli_fingerprint_value(state.fingerprint);
}

static VALUE rb_li_sqli_contexts(VALUE self, VALUE input) {
    VALUE str;
    VALUE out;
    size_t i;

    (void)self;
    str = li_str(input);
    out = rb_ary_new_capa((long)LI_ARRAY_LEN(SQLI_CONTEXTS));

    for (i = 0; i < LI_ARRAY_LEN(SQLI_CONTEXTS); i++) {
        struct libinjection_sqli_state state;
        injection_result_t result = li_run_sqli_context(str, SQLI_CONTEXTS[i].value, &state);
        raise_on_error(result);
        rb_ary_push(out, li_sqli_result_hash(&state, result, SQLI_CONTEXTS[i].value,
                                             li_id_sym(SQLI_CONTEXTS[i].name)));
    }

    return out;
}

static VALUE rb_li_sqli_tokens(int argc, VALUE *argv, VALUE self) {
    VALUE input;
    VALUE opts;
    VALUE str;
    VALUE out;
    VALUE fold_value;
    int flags;
    int folded;
    struct libinjection_sqli_state state;

    (void)self;
    rb_scan_args(argc, argv, "11", &input, &opts);
    str = li_str(input);
    opts = li_hash_opts(opts);
    flags = li_sqli_flags_from_opts(opts, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    fold_value = li_hash_aref(opts, "fold");
    folded = fold_value == Qtrue;

    libinjection_sqli_init(&state, RSTRING_PTR(str), (size_t)RSTRING_LEN(str), flags);
    out = rb_ary_new();

    if (folded) {
        int tlen;
        int i;
        libinjection_sqli_fingerprint(&state, flags);
        tlen = (int)li_bounded_strlen(state.fingerprint, LI_SQLI_FINGERPRINT_SIZE);
        for (i = 0; i < tlen; i++) {
            rb_ary_push(out, li_sqli_token_hash(&state.tokenvec[i]));
        }
        return out;
    }

    state.current = &(state.tokenvec[0]);
    while (libinjection_sqli_tokenize(&state)) {
        rb_ary_push(out, li_sqli_token_hash(state.current));
    }

    return out;
}

static VALUE rb_li_sqli_flags(int argc, VALUE *argv, VALUE self) {
    VALUE opts;
    (void)self;
    rb_scan_args(argc, argv, "01", &opts);
    return INT2NUM(li_sqli_flags_from_opts(opts, FLAG_QUOTE_NONE | FLAG_SQL_ANSI));
}

static VALUE rb_li_xss_p(VALUE self, VALUE input) {
    li_work_scan_args_t args;

    (void)self;
    memset(&args, 0, sizeof(args));
    args.input = input;
    args.work.want_xss = 1;

    rb_ensure(li_work_scan_body, (VALUE)&args, li_work_scan_ensure, (VALUE)&args);
    raise_on_error(args.work.xss_result);

    return args.work.xss_detected ? Qtrue : Qfalse;
}

static VALUE li_xss_result_hash(injection_result_t result, int flags, VALUE context_name) {
    VALUE hash = rb_hash_new();

    rb_hash_aset(hash, li_id_sym("type"), sym_xss);
    rb_hash_aset(hash, li_id_sym("detected"), result == LIBINJECTION_RESULT_TRUE ? Qtrue : Qfalse);
    rb_hash_aset(hash, li_id_sym("flags"), INT2NUM(flags));
    rb_hash_aset(hash, li_id_sym("context"), context_name);

    return hash;
}

static VALUE rb_li_xss_result(int argc, VALUE *argv, VALUE self) {
    VALUE input;
    VALUE opts;
    VALUE str;
    int flags;
    injection_result_t result;

    (void)self;
    rb_scan_args(argc, argv, "11", &input, &opts);
    str = li_str(input);

    if (NIL_P(opts)) {
        result = libinjection_xss(RSTRING_PTR(str), (size_t)RSTRING_LEN(str));
        raise_on_error(result);
        return li_xss_result_hash(result, -1, Qnil);
    }

    flags = li_html5_flags_from_opts(opts, DATA_STATE);
    result = libinjection_is_xss(RSTRING_PTR(str), (size_t)RSTRING_LEN(str), flags);
    raise_on_error(result);

    return li_xss_result_hash(
        result, flags, li_symbol_for_int(HTML5_CONTEXTS, LI_ARRAY_LEN(HTML5_CONTEXTS), flags));
}

static VALUE rb_li_xss_contexts(VALUE self, VALUE input) {
    VALUE str;
    VALUE out;
    size_t i;

    (void)self;
    str = li_str(input);
    out = rb_ary_new_capa((long)LI_ARRAY_LEN(HTML5_CONTEXTS));

    for (i = 0; i < LI_ARRAY_LEN(HTML5_CONTEXTS); i++) {
        injection_result_t result = libinjection_is_xss(RSTRING_PTR(str), (size_t)RSTRING_LEN(str),
                                                        HTML5_CONTEXTS[i].value);
        raise_on_error(result);
        rb_ary_push(out, li_xss_result_hash(result, HTML5_CONTEXTS[i].value,
                                            li_id_sym(HTML5_CONTEXTS[i].name)));
    }

    return out;
}

static VALUE li_html5_token_hash(const h5_state_t *state) {
    VALUE hash = rb_hash_new();

    rb_hash_aset(
        hash, li_id_sym("type"),
        li_symbol_for_int(HTML5_TOKEN_TYPES, LI_ARRAY_LEN(HTML5_TOKEN_TYPES), state->token_type));
    rb_hash_aset(hash, li_id_sym("value"), rb_str_new(state->token_start, state->token_len));
    rb_hash_aset(hash, li_id_sym("pos"), SIZET2NUM((size_t)(state->token_start - state->s)));
    rb_hash_aset(hash, li_id_sym("length"), SIZET2NUM(state->token_len));
    rb_hash_aset(hash, li_id_sym("is_close"), state->is_close ? Qtrue : Qfalse);

    return hash;
}

static VALUE rb_li_html5_tokens(int argc, VALUE *argv, VALUE self) {
    VALUE input;
    VALUE opts;
    VALUE str;
    VALUE out;
    int flags;
    h5_state_t state;
    injection_result_t result;

    (void)self;
    rb_scan_args(argc, argv, "11", &input, &opts);
    str = li_str(input);
    flags = li_html5_flags_from_opts(opts, DATA_STATE);

    libinjection_h5_init(&state, RSTRING_PTR(str), (size_t)RSTRING_LEN(str), flags);
    out = rb_ary_new();

    while ((result = libinjection_h5_next(&state)) == LIBINJECTION_RESULT_TRUE) {
        rb_ary_push(out, li_html5_token_hash(&state));
    }
    raise_on_error(result);

    return out;
}

static VALUE rb_li_xss_flags(int argc, VALUE *argv, VALUE self) {
    VALUE opts;
    (void)self;
    rb_scan_args(argc, argv, "01", &opts);
    return INT2NUM(li_html5_flags_from_opts(opts, DATA_STATE));
}

static void li_check_runtime_version(void) {
    const char *version = libinjection_version();
    if (strcmp(version, LI_REQUIRED_LIBINJECTION_VERSION) != 0) {
        rb_raise(eError, "libinjection runtime version mismatch: expected %s, got %s",
                 LI_REQUIRED_LIBINJECTION_VERSION, version);
    }
}

static VALUE rb_li_lib_version(VALUE self) {
    (void)self;
    return rb_str_new_cstr(libinjection_version());
}

void Init_libinjection_native(void) {
    mLibInjection = rb_define_module("LibInjection");
    if (rb_const_defined(mLibInjection, rb_intern("Error"))) {
        eError = rb_const_get(mLibInjection, rb_intern("Error"));
    } else {
        eError = rb_define_class_under(mLibInjection, "Error", rb_eStandardError);
    }

    if (rb_const_defined(mLibInjection, rb_intern("ParserError"))) {
        eParserError = rb_const_get(mLibInjection, rb_intern("ParserError"));
    } else {
        eParserError = rb_define_class_under(mLibInjection, "ParserError", eError);
    }

    eArgumentError = rb_eArgError;
    sym_sqli = ID2SYM(rb_intern("sqli"));
    sym_xss = ID2SYM(rb_intern("xss"));

    li_check_runtime_version();

    rb_define_const(mLibInjection, "SQLI_CONTEXTS",
                    li_named_int_hash(SQLI_CONTEXTS, LI_ARRAY_LEN(SQLI_CONTEXTS)));
    rb_define_const(mLibInjection, "SQLI_QUOTES",
                    li_named_int_hash(SQLI_QUOTES, LI_ARRAY_LEN(SQLI_QUOTES)));
    rb_define_const(mLibInjection, "SQLI_DIALECTS",
                    li_named_int_hash(SQLI_DIALECTS, LI_ARRAY_LEN(SQLI_DIALECTS)));
    rb_define_const(mLibInjection, "SQLI_TOKEN_TYPES",
                    li_named_char_hash(SQLI_TOKEN_TYPES, LI_ARRAY_LEN(SQLI_TOKEN_TYPES)));
    rb_define_const(mLibInjection, "HTML5_CONTEXTS",
                    li_named_int_hash(HTML5_CONTEXTS, LI_ARRAY_LEN(HTML5_CONTEXTS)));
    rb_define_const(mLibInjection, "XSS_CONTEXTS",
                    li_named_int_hash(HTML5_CONTEXTS, LI_ARRAY_LEN(HTML5_CONTEXTS)));
    rb_define_const(mLibInjection, "HTML5_TOKEN_TYPES",
                    li_named_int_hash(HTML5_TOKEN_TYPES, LI_ARRAY_LEN(HTML5_TOKEN_TYPES)));

    rb_define_singleton_method(mLibInjection, "sqli?", rb_li_sqli_p, 1);
    rb_define_singleton_method(mLibInjection, "sqli_fingerprint", rb_li_sqli_fingerprint, 1);
    rb_define_singleton_method(mLibInjection, "detect_raw", rb_li_detect_raw, 1);
    rb_define_singleton_method(mLibInjection, "detect_url_encoded_raw",
                               rb_li_detect_url_encoded_raw, 4);
    rb_define_singleton_method(mLibInjection, "sqli_result", rb_li_sqli_result, -1);
    rb_define_singleton_method(mLibInjection, "sqli_contexts", rb_li_sqli_contexts, 1);
    rb_define_singleton_method(mLibInjection, "sqli_tokens", rb_li_sqli_tokens, -1);
    rb_define_singleton_method(mLibInjection, "sqli_fingerprint_for", rb_li_sqli_fingerprint_for,
                               -1);
    rb_define_singleton_method(mLibInjection, "sqli_flags", rb_li_sqli_flags, -1);

    rb_define_singleton_method(mLibInjection, "xss?", rb_li_xss_p, 1);
    rb_define_singleton_method(mLibInjection, "xss_result", rb_li_xss_result, -1);
    rb_define_singleton_method(mLibInjection, "xss_contexts", rb_li_xss_contexts, 1);
    rb_define_singleton_method(mLibInjection, "html5_tokens", rb_li_html5_tokens, -1);
    rb_define_singleton_method(mLibInjection, "xss_flags", rb_li_xss_flags, -1);

    rb_define_singleton_method(mLibInjection, "lib_version", rb_li_lib_version, 0);
}
