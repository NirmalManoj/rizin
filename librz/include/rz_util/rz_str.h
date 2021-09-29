#ifndef RZ_STR_H
#define RZ_STR_H

#include <wchar.h>
#include "rz_str_util.h"
#include "rz_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RZ_STRING_ENC_LATIN1 = 'a',
	RZ_STRING_ENC_UTF8 = '8',
	RZ_STRING_ENC_UTF16LE = 'u',
	RZ_STRING_ENC_UTF32LE = 'U',
	RZ_STRING_ENC_UTF16BE = 'b',
	RZ_STRING_ENC_UTF32BE = 'B',
	RZ_STRING_ENC_GUESS = 'g',
} RzStrEnc;

/**
 * \brief Convenience macro for local temporary strings
 * \param buf Target buffer, **must** be an array type, not a pointer.
 *
 * This eases the common pattern where a stack-allocated string of a fixed
 * size is created and filled with `snprintf()` to be used as a temporary string.
 *
 * Example:
 *
 *     char k[32];
 *     char v[32];
 *     sdb_set(db, rz_strf(k, "key.%d", 42), rz_strf(v, "val.%d", 123));
 */
#define rz_strf(buf, ...) ( \
	snprintf(buf, sizeof(buf), __VA_ARGS__) < 0 \
	? rz_assert_log(RZ_LOGLVL_FATAL, "rz_strf error while using snprintf"), \
	NULL \
	: buf)

typedef int (*RzStrRangeCallback)(void *, int);

#define RZ_STR_ISEMPTY(x)    (!(x) || !*(x))
#define RZ_STR_ISNOTEMPTY(x) ((x) && *(x))
#define RZ_STR_DUP(x)        ((x) ? strdup((x)) : NULL)
#define rz_str_array(x, y)   ((y >= 0 && y < (sizeof(x) / sizeof(*x))) ? x[y] : "")
RZ_API RZ_OWN char *rz_str_repeat(RZ_NONNULL const char *ch, int sz);
RZ_API const char *rz_str_pad(const char ch, int len);
RZ_API RZ_BORROW const char *rz_str_rstr(RZ_NONNULL const char *base, RZ_NONNULL const char *p);
RZ_API const char *rz_strstr_ansi(const char *a, const char *b);
RZ_API RZ_BORROW const char *rz_str_rchr(RZ_NONNULL const char *base, RZ_NULLABLE const char *p, int ch);
RZ_API const char *rz_str_closer_chr(const char *b, const char *s);
RZ_API int rz_str_bounds(RZ_NONNULL const char *str, RZ_NULLABLE int *h);
RZ_API RZ_OWN char *rz_str_crop(RZ_NONNULL const char *str, unsigned int x, unsigned int y, unsigned int x2, unsigned int y2);
RZ_API RZ_OWN char *rz_str_scale(RZ_NONNULL const char *s, int w, int h);
RZ_API bool rz_str_range_in(const char *r, ut64 addr);
RZ_API size_t rz_str_len_utf8(const char *s);
RZ_API size_t rz_str_len_utf8_ansi(const char *str);
RZ_API size_t rz_str_len_utf8char(const char *s, int left);
RZ_API size_t rz_str_utf8_charsize(const char *str);
RZ_API size_t rz_str_utf8_charsize_prev(const char *str, int prev_len);
RZ_API size_t rz_str_utf8_charsize_last(const char *str);
RZ_API void rz_str_filter_zeroline(char *str, int len);
RZ_API size_t rz_str_utf8_codepoint(const char *s, size_t left);
RZ_API bool rz_str_char_fullwidth(const char *s, size_t left);
RZ_API int rz_str_write(int fd, const char *b);
RZ_API size_t rz_str_ncpy(RZ_NONNULL char *dst, RZ_NONNULL const char *src, size_t n);
RZ_API void rz_str_sanitize(char *c);
RZ_API char *rz_str_sanitize_sdb_key(const char *s);
RZ_API const char *rz_str_casestr(const char *a, const char *b);
RZ_API const char *rz_str_firstbut(const char *s, char ch, const char *but);
RZ_API const char *rz_str_lastbut(const char *s, char ch, const char *but);
RZ_API size_t rz_str_split(RZ_NONNULL char *str, char ch);
RZ_API RZ_OWN RzList *rz_str_split_list(RZ_NONNULL char *str, RZ_NONNULL const char *c, int n);
RZ_API RZ_OWN RzList *rz_str_split_duplist(RZ_NONNULL const char *str, RZ_NONNULL const char *c, bool trim);
RZ_API RZ_OWN RzList *rz_str_split_duplist_n(RZ_NONNULL const char *str, RZ_NONNULL const char *c, int n, bool trim);
RZ_API RZ_OWN size_t *rz_str_split_lines(RZ_NONNULL char *str, size_t *count);
RZ_API char *rz_str_replace(char *str, const char *key, const char *val, int g);
RZ_API char *rz_str_replace_icase(char *str, const char *key, const char *val, int g, int keep_case);
RZ_API char *rz_str_replace_in(char *str, ut32 sz, const char *key, const char *val, int g);
#define rz_str_cpy(x, y) memmove((x), (y), strlen(y) + 1);
#define rz_str_cat(x, y) memmove((x) + strlen(x), (y), strlen(y) + 1);
RZ_API int rz_str_bits(RZ_NONNULL char *strout, const ut8 *buf, int len, const char *bitz);
RZ_API int rz_str_bits64(RZ_NONNULL char *strout, ut64 in);
RZ_API ut64 rz_str_bits_from_string(RZ_NONNULL const char *buf, RZ_NONNULL const char *bitz);
RZ_API int rz_str_rwx(RZ_NONNULL const char *str);
RZ_API int rz_str_replace_ch(RZ_NONNULL char *s, char a, char b, bool global);
RZ_API int rz_str_replace_char(RZ_NONNULL char *s, int a, int b);
RZ_API int rz_str_replace_char_once(RZ_NONNULL char *s, int a, int b);
RZ_API void rz_str_remove_char(RZ_NONNULL char *str, char c);
RZ_API const char *rz_str_rwx_i(int rwx);
RZ_API int rz_str_fmtargs(RZ_NONNULL const char *fmt);
RZ_API char *rz_str_arg_escape(const char *arg);
RZ_API int rz_str_arg_unescape(char *arg);
RZ_API char **rz_str_argv(const char *str, int *_argc);
RZ_API void rz_str_argv_free(char **argv);
RZ_API RZ_OWN char *rz_str_new(RZ_NULLABLE const char *str);
RZ_API int rz_snprintf(RZ_NONNULL char *string, int len, RZ_NONNULL const char *fmt, ...) RZ_PRINTF_CHECK(3, 4);
RZ_API bool rz_str_is_ascii(const char *str);
RZ_API bool rz_str_is_utf8(RZ_NONNULL const char *str);
RZ_API char *rz_str_nextword(RZ_NONNULL char *s, char ch);
RZ_API bool rz_str_is_printable(const char *str);
RZ_API bool rz_str_is_printable_limited(const char *str, int size);
RZ_API bool rz_str_is_printable_incl_newlines(const char *str);
RZ_API RZ_OWN char *rz_str_newf(RZ_NONNULL const char *fmt, ...) RZ_PRINTF_CHECK(1, 2);
RZ_API RZ_OWN char *rz_str_newlen(RZ_NONNULL const char *str, int len);
RZ_API const char *rz_str_sysbits(const int v);
RZ_API RZ_OWN char *rz_str_trunc_ellipsis(RZ_NONNULL const char *str, int len);
RZ_API const char *rz_str_bool(int b);
RZ_API bool rz_str_is_true(RZ_NONNULL const char *s);
RZ_API bool rz_str_is_false(RZ_NONNULL const char *s);
RZ_API bool rz_str_is_bool(RZ_NONNULL const char *val);
RZ_API const char *rz_str_ansi_chrn(const char *str, size_t n);
RZ_API size_t rz_str_ansi_len(const char *str);
RZ_API size_t rz_str_ansi_nlen(const char *str, size_t len);
RZ_API int rz_str_ansi_trim(char *str, int str_len, int n);
RZ_API int rz_str_ansi_filter(char *str, char **out, int **cposs, int len);
RZ_API char *rz_str_ansi_crop(const char *str, unsigned int x, unsigned int y, unsigned int x2, unsigned int y2);
RZ_API int rz_str_word_count(RZ_NONNULL const char *string);
RZ_API int rz_str_char_count(RZ_NONNULL const char *string, char ch);
RZ_API RZ_OWN char *rz_str_word_get0set(RZ_NULLABLE char *stra, int stralen, int idx, RZ_NULLABLE const char *newstr, int *newlen);
RZ_API int rz_str_word_set0(RZ_NULLABLE char *str);
RZ_API int rz_str_word_set0_stack(RZ_NULLABLE char *str);
static inline const char *rz_str_word_get_next0(const char *str) {
	return str + strlen(str) + 1;
}
RZ_API RZ_BORROW const char *rz_str_word_get0(RZ_NONNULL const char *str, int idx);
RZ_API RZ_OWN char *rz_str_word_get_first(RZ_NONNULL const char *text);
RZ_API void rz_str_trim(char *str);
RZ_API char *rz_str_trim_dup(const char *str);
RZ_API char *rz_str_trim_lines(char *str);
RZ_API void rz_str_trim_head(char *str);
RZ_API const char *rz_str_trim_head_ro(const char *str);
RZ_API const char *rz_str_trim_head_wp(const char *str);
RZ_API void rz_str_trim_tail(char *str);
RZ_API ut32 rz_str_hash(RZ_NULLABLE const char *s);
RZ_API ut64 rz_str_hash64(RZ_NULLABLE const char *s);
RZ_API char *rz_str_trim_nc(char *str);
RZ_API RZ_BORROW const char *rz_str_nstr(RZ_NONNULL const char *s, RZ_NONNULL const char *find, int size);
RZ_API RZ_BORROW const char *rz_str_lchr(RZ_NONNULL const char *str, char chr);
RZ_API RZ_BORROW const char *rz_sub_str_lchr(RZ_NONNULL const char *str, int start, int end, char chr);
RZ_API RZ_BORROW const char *rz_sub_str_rchr(RZ_NONNULL const char *str, int start, int end, char chr);
RZ_API RZ_BORROW const char *rz_str_ichr(RZ_NONNULL const char *str, char chr);
RZ_API bool rz_str_ccmp(RZ_NONNULL const char *dst, RZ_NONNULL const char *orig, int ch);
RZ_API bool rz_str_cmp_list(RZ_NONNULL const char *list, RZ_NONNULL const char *item, char sep);
RZ_API int rz_str_cmp(RZ_NULLABLE const char *dst, RZ_NULLABLE const char *orig, int len);
RZ_API int rz_str_casecmp(RZ_NONNULL const char *s1, RZ_NONNULL const char *s2);
RZ_API int rz_str_ncasecmp(RZ_NONNULL const char *s1, RZ_NONNULL const char *s2, size_t n);
RZ_API int rz_str_ccpy(RZ_NONNULL char *dst, RZ_NONNULL const char *src, int ch);
static inline const char *rz_str_get(const char *str) {
	return str ? str : "";
}
static inline const char *rz_str_get_null(const char *str) {
	return str ? str : "(null)";
}
RZ_API RZ_OWN char *rz_str_ndup(RZ_NONNULL const char *ptr, int len);
RZ_API RZ_DEPRECATE RZ_OWN char *rz_str_dup(RZ_NULLABLE char *ptr, RZ_NONNULL const char *string);
RZ_API int rz_str_inject(char *begin, char *end, char *str, int maxlen);
RZ_API int rz_str_delta(RZ_NONNULL const char *p, char a, char b);
RZ_API void rz_str_filter(char *str, int len);
RZ_API RZ_BORROW const char *rz_str_tok(RZ_NULLABLE const char *str1, const char b, size_t len);
RZ_API RZ_OWN wchar_t *rz_str_mb_to_wc(RZ_NULLABLE const char *buf);
RZ_API RZ_OWN char *rz_str_wc_to_mb(RZ_NULLABLE const wchar_t *buf);
RZ_API RZ_OWN wchar_t *rz_str_mb_to_wc_l(RZ_NULLABLE const char *buf, int len);
RZ_API RZ_OWN char *rz_str_wc_to_mb_l(RZ_NULLABLE const wchar_t *buf, int len);
RZ_API RZ_BORROW const char *rz_str_str_xy(RZ_NONNULL const char *s, RZ_NONNULL const char *word, const char *prev, int *x, int *y);

typedef void (*str_operation)(char *c);

RZ_API int rz_str_do_until_token(str_operation op, RZ_NULLABLE char *str, const char tok);

RZ_API void rz_str_reverse(RZ_NONNULL char *str);
RZ_API int rz_str_re_match(const char *str, const char *reg);
RZ_API int rz_str_re_replace(const char *str, const char *reg, const char *sub);
RZ_API int rz_str_path_unescape(char *path);
RZ_API char *rz_str_path_escape(const char *path);
RZ_API int rz_str_unescape(char *buf);
RZ_API char *rz_str_escape(const char *buf);
RZ_API char *rz_str_escape_sh(const char *buf);
RZ_API char *rz_str_escape_dot(const char *buf);
RZ_API char *rz_str_escape_latin1(const char *buf, bool show_asciidot, bool esc_bslash, bool colors);
RZ_API char *rz_str_escape_utf8(const char *buf, bool show_asciidot, bool esc_bslash);
RZ_API char *rz_str_escape_utf8_keep_printable(const char *buf, bool show_asciidot, bool esc_bslash); // like escape_utf8 but leaves valid \uXXXX chars directly in utf-8
RZ_API char *rz_str_escape_utf16le(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
RZ_API char *rz_str_escape_utf32le(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
RZ_API char *rz_str_escape_utf16be(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
RZ_API char *rz_str_escape_utf32be(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
RZ_API void rz_str_byte_escape(const char *p, char **dst, int dot_nl, bool default_dot, bool esc_bslash);
RZ_API char *rz_str_format_msvc_argv(size_t argc, const char **argv);
RZ_API void rz_str_uri_decode(char *buf);
RZ_API char *rz_str_uri_encode(const char *buf);
RZ_API RZ_OWN char *rz_str_utf16_decode(RZ_NONNULL const ut8 *s, int len);
RZ_API int rz_str_utf16_to_utf8(ut8 *dst, int len_dst, const ut8 *src, int len_src, int little_endian);
RZ_API RZ_OWN char *rz_str_utf16_encode(RZ_NONNULL const char *s, int len);
RZ_API char *rz_str_escape_utf8_for_json(const char *s, int len);
RZ_API RZ_OWN char *rz_str_home(RZ_NONNULL const char *str);
RZ_API RZ_OWN char *rz_str_rz_prefix(RZ_NONNULL const char *str);
RZ_API size_t rz_str_nlen(const char *s, int n);
RZ_API size_t rz_str_nlen_w(const char *s, int n);
RZ_API size_t rz_wstr_clen(const char *s);
RZ_API RZ_OWN char *rz_str_prepend(RZ_NULLABLE char *ptr, RZ_NONNULL const char *string);
RZ_API RZ_OWN char *rz_str_prefix_all(const char *s, const char *pfx);
RZ_API RZ_OWN char *rz_str_append(RZ_NULLABLE char *ptr, RZ_NONNULL const char *string);
RZ_API RZ_OWN char *rz_str_append_owned(RZ_NULLABLE char *ptr, RZ_OWN RZ_NONNULL char *string);
RZ_API RZ_OWN char *rz_str_appendlen(RZ_NULLABLE char *ptr, RZ_NONNULL const char *string, int slen);
RZ_API RZ_OWN char *rz_str_appendf(RZ_NULLABLE char *ptr, RZ_NONNULL const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API RZ_OWN char *rz_str_appendch(RZ_NULLABLE char *x, char y);
RZ_API void rz_str_case(RZ_NONNULL char *str, bool up);
RZ_API void rz_str_trim_path(char *s);
RZ_API ut8 rz_str_contains_macro(const char *input_value);
RZ_API void rz_str_truncate_cmd(char *string);
RZ_API char *rz_str_replace_thunked(char *str, char *clean, int *thunk, int clen,
	const char *key, const char *val, int g);
RZ_API bool rz_str_glob(const char *str, const char *glob);
RZ_API int rz_str_binstr2bin(RZ_NONNULL const char *str, RZ_NONNULL ut8 *out, int outlen);
RZ_API RZ_OWN char *rz_str_between(RZ_NULLABLE const char *cmt, RZ_NULLABLE const char *prefix, RZ_NULLABLE const char *suffix);
RZ_API bool rz_str_startswith(RZ_NONNULL const char *str, RZ_NONNULL const char *needle);
RZ_API bool rz_str_endswith(RZ_NONNULL const char *str, RZ_NONNULL const char *needle);
RZ_API bool rz_str_isnumber(RZ_NULLABLE const char *str);
RZ_API const char *rz_str_last(RZ_NULLABLE const char *str, RZ_NULLABLE const char *ch);
RZ_API RZ_OWN char *rz_str_highlight(RZ_NULLABLE char *str, const char *word, const char *color, const char *color_reset);
RZ_API char *rz_qrcode_gen(const ut8 *text, int len, bool utf8, bool inverted);
RZ_API RZ_OWN char *rz_str_from_ut64(ut64 val);
RZ_API void rz_str_stripLine(RZ_NULLABLE char *str, RZ_NULLABLE const char *key);
RZ_API RZ_OWN char *rz_str_list_join(RzList *str, RZ_NONNULL const char *sep);
RZ_API RZ_OWN char *rz_str_array_join(RZ_NONNULL const char **a, size_t n, RZ_NONNULL const char *sep);
RZ_API RZ_OWN RzList *rz_str_wrap(RZ_NONNULL char *str, size_t width);

RZ_API RZ_BORROW const char *rz_str_sep(const char *base, const char *sep);
RZ_API RZ_BORROW const char *rz_str_rsep(const char *base, const char *p, const char *sep);
RZ_API RZ_OWN char *rz_str_version(RZ_NULLABLE const char *program);

#ifdef __cplusplus
}
#endif

#endif //  RZ_STR_H
