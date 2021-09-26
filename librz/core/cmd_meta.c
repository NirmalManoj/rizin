// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_bin.h"
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_util.h"
#include "rz_types.h"
#include <sdb.h>

char *getcommapath(RzCore *core);

RZ_IPI void rz_core_meta_comment_add(RzCore *core, const char *comment, ut64 addr) {
	const char *oldcomment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
	if (!oldcomment || (oldcomment && !strstr(oldcomment, comment))) {
		rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, comment);
	}
}

inline const char *meta_get_flag(RzCore *core, ut64 addr) {
	RzFlagItem *fi;
	fi = rz_flag_get_i(core->flags, addr);
	return fi ? fi->name : NULL;
}

#if 0
static int cmd_meta_others(RzCore *core, const char *input) {
	int n, type = input[0], subtype;
	char *t = 0, *p, *p2, name[256];
	int repeat = 1;
	ut64 addr = core->offset;

	if (!type) {
		return 0;
	}

	switch (input[1]) {
	case '?':
		switch (input[0]) {
		case 'f': // "Cf?"
			rz_cons_println(
				"Usage: Cf[-] [sz] [fmt..] [@addr]\n\n"
				"'sz' indicates the byte size taken up by struct.\n"
				"'fmt' is a 'pf?' style format string. It controls only the display format.\n\n"
				"You may wish to have 'sz' != sizeof(fmt) when you have a large struct\n"
				"but have only identified specific fields in it. In that case, use 'fmt'\n"
				"to show the fields you know about (perhaps using 'skip' fields), and 'sz'\n"
				"to match the total struct size in mem.\n");
			break;
		}
		break;
	case '.': // "Cf.", "Cd.", ...
		if (input[2] == '.') { // "Cs.."
			ut64 size;
			RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, addr, type, &size);
			if (mi) {
				rz_core_meta_print(core->analysis, mi, addr, size, input[3], NULL, false);
			}
			break;
		} else if (input[2] == 'j') { // "Cs.j"
			ut64 size;
			RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, addr, type, &size);
			if (mi) {
				rz_core_meta_print(core->analysis, mi, addr, size, input[2], NULL, false);
				rz_cons_newline();
			}
			break;
		}
		ut64 size;
		RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, addr, type, &size);
		if (!mi) {
			break;
		}
		if (type == RZ_META_TYPE_STRING) {
			meta_string_print(core, mi);
		} else if (type == RZ_META_TYPE_DATA) {
			rz_cons_printf("%" PFMT64u "\n", size);
		} else {
			rz_cons_println(mi->str);
		}
		break;
	case ' ': // "Cf", "Cd", ...
	case '\0':
	case 'g':
	case 'a':
	case '8':
		if (type != 'z' && !input[1] && !core->tmpseek) {
			rz_core_meta_print_list_all(core->analysis, type, 0);
			break;
		}
		if (type == 'z') {
			type = 's';
		}
		int len = (!input[1] || input[1] == ' ') ? 2 : 3;
		if (strlen(input) > len) {
			char *rep = strchr(input + len, '[');
			if (!rep) {
				rep = strchr(input + len, ' ');
			}
			if (*input == 'd') {
				if (rep) {
					repeat = rz_num_math(core->num, rep + 1);
				}
			}
		}
		int repcnt = 0;
		if (repeat < 1) {
			repeat = 1;
		}
		while (repcnt < repeat) {
			int off = (!input[1] || input[1] == ' ') ? 1 : 2;
			t = strdup(rz_str_trim_head_ro(input + off));
			p = NULL;
			n = 0;
			strncpy(name, t, sizeof(name) - 1);
			if (type != RZ_META_TYPE_COMMENT) {
				n = rz_num_math(core->num, t);
				if (type == RZ_META_TYPE_FORMAT) { // "Cf"
					p = strchr(t, ' ');
					if (p) {
						p = (char *)rz_str_trim_head_ro(p);
						if (*p == '.') {
							const char *realformat = rz_type_db_format_get(core->analysis->typedb, p + 1);
							if (realformat) {
								p = (char *)realformat;
							} else {
								eprintf("Cannot resolve format '%s'\n", p + 1);
								break;
							}
						}
						if (n < 1) {
							n = rz_type_format_struct_size(core->analysis->typedb, p, 0, 0);
							if (n < 1) {
								eprintf("Warning: Cannot resolve struct size for '%s'\n", p);
								n = 32; //
							}
						}
						//make sure we do not overflow on rz_type_format
						if (n > core->blocksize) {
							n = core->blocksize;
						}
						char *format = rz_type_format_data(core->analysis->typedb, core->print, addr, core->block,
							n, p, 0, NULL, NULL);
						if (!format) {
							n = -1;
						} else {
							rz_cons_print(format);
							free(format);
						}
					} else {
						eprintf("Usage: Cf [size] [pf-format-string]\n");
						break;
					}
				} else if (type == RZ_META_TYPE_STRING) { // "Cs"
					char tmp[256] = RZ_EMPTY;
					int i, j, name_len = 0;
					if (input[1] == 'a' || input[1] == '8') {
						(void)rz_io_read_at(core->io, addr, (ut8 *)name, sizeof(name) - 1);
						name[sizeof(name) - 1] = '\0';
						name_len = strlen(name);
					} else {
						(void)rz_io_read_at(core->io, addr, (ut8 *)tmp, sizeof(tmp) - 3);
						name_len = rz_str_nlen_w(tmp, sizeof(tmp) - 3);
						//handle wide strings
						for (i = 0, j = 0; i < sizeof(name); i++, j++) {
							name[i] = tmp[j];
							if (!tmp[j]) {
								break;
							}
							if (!tmp[j + 1]) {
								if (j + 3 < sizeof(tmp)) {
									if (tmp[j + 3]) {
										break;
									}
								}
								j++;
							}
						}
						name[sizeof(name) - 1] = '\0';
					}
					if (n == 0) {
						n = name_len + 1;
					} else {
						if (n > 0 && n < name_len) {
							name[n] = 0;
						}
					}
				}
				if (n < 1) {
					/* invalid length, do not insert into db */
					return false;
				}
				if (!*t || n > 0) {
					RzFlagItem *fi;
					p = strchr(t, ' ');
					if (p) {
						*p++ = '\0';
						p = (char *)rz_str_trim_head_ro(p);
						strncpy(name, p, sizeof(name) - 1);
					} else {
						if (type != 's') {
							fi = rz_flag_get_i(core->flags, addr);
							if (fi) {
								strncpy(name, fi->name, sizeof(name) - 1);
							}
						}
					}
				}
			}
			if (!n) {
				n++;
			}
			if (type == RZ_META_TYPE_STRING) {
				switch (input[1]) {
				case 'a':
				case '8':
					subtype = input[1];
					break;
				default:
					subtype = RZ_STRING_ENC_GUESS;
				}
				rz_meta_set_with_subtype(core->analysis, type, subtype, addr, n, name);
			} else {
				rz_meta_set(core->analysis, type, addr, n, name);
			}
			free(t);
			repcnt++;
			addr += n;
		}
		//rz_meta_cleanup (core->analysis->meta, 0LL, UT64_MAX);
		break;
	default:
		eprintf("Missing space after CC\n");
		break;
	}

	return true;
}

RZ_IPI int rz_cmd_meta(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	RzAnalysisFunction *f;
	RzSpaces *ms;
	int i;

	switch (*input) {
	case 'r': // "Cr" run command
	case 'h': // "Ch" comment
	case 's': // "Cs" string
	case 'z': // "Cz" zero-terminated string
	case 'd': // "Cd" data
	case 'm': // "Cm" magic
	case 'f': // "Cf" formatted
		cmd_meta_others(core, input);
		break;
	return true;
}
#endif

static void meta_string_print(RzCore *core, RzAnalysisMetaItem *mi) {
	char *esc_str;
	bool esc_bslash = core->print->esc_bslash;
	switch (mi->subtype) {
	case RZ_STRING_ENC_UTF8:
		esc_str = rz_str_escape_utf8(mi->str, false, esc_bslash);
		break;
	case 0: /* temporary legacy workaround */
		esc_bslash = false;
	default:
		esc_str = rz_str_escape_latin1(mi->str, false, esc_bslash, false);
	}
	if (esc_str) {
		rz_cons_printf("\"%s\"\n", esc_str);
		free(esc_str);
	} else {
		rz_cons_println("<oom>");
	}
}

static void meta_format_print(RzCore *core, ut64 addr, ut64 size, const char *format) {
	const char *fmt = format;
	if (*fmt == '.') {
		const char *realformat = rz_type_db_format_get(core->analysis->typedb, fmt + 1);
		if (realformat) {
			fmt = (char *)realformat;
		} else {
			RZ_LOG_ERROR("Cannot resolve format '%s'\n", fmt + 1);
			return;
		}
	}
	if (size < 1) {
		size = rz_type_format_struct_size(core->analysis->typedb, fmt, 0, 0);
		if (size < 1) {
			eprintf("Warning: Cannot resolve struct size for '%s'\n", fmt);
			size = 32; //
		}
	}
	//make sure we do not overflow on rz_type_format
	if (size > core->blocksize) {
		size = core->blocksize;
	}
	char *fmtstring = rz_type_format_data(core->analysis->typedb, core->print, addr, core->block,
		size, fmt, 0, NULL, NULL);
	if (!fmtstring) {
		size = -1;
	} else {
		rz_cons_print(format);
		free(format);
	}
}

static RzCmdStatus meta_variable_comment_list(RzCore *core, RzAnalysisVarKind kind, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->kind != kind || !var->comment) {
			continue;
		}
		PJ *pj = state->d.pj;
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", var->name);
			pj_ks(pj, "comment", var->comment);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%s : %s\n", var->name, var->comment);
			break;
		case RZ_OUTPUT_MODE_RIZIN: {
			char *b64 = sdb_encode((const ut8 *)var->comment, strlen(var->comment));
			if (!b64) {
				continue;
			}
			rz_cons_printf("\"Cv%c %s base64:%s @ 0x%08" PFMT64x "\"\n", kind, var->name, b64, fcn->addr);
			break;
		}
		default:
			rz_warn_if_reached();
			break;
		}
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus meta_variable_comment_append(RzCore *core, const char *name, const char *comment) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	char *heap_comment = NULL;
	if (RZ_STR_ISNOTEMPTY(comment)) { // new comment given
		if (!strncmp(comment, "base64:", 7)) {
			heap_comment = (char *)sdb_decode(comment + 7, NULL);
			comment = heap_comment;
		}
	}
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
	if (!var) {
		RZ_LOG_ERROR("Can't find variable named `%s`\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	if (var->comment) {
		if (comment && *comment) {
			char *text = rz_str_newf("%s\n%s", var->comment, comment);
			free(var->comment);
			var->comment = text;
		} else {
			rz_cons_println(var->comment);
		}
	} else {
		var->comment = strdup(comment);
	}
	free(heap_comment);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus meta_variable_comment_remove(RzCore *core, const char *name) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
	if (!var) {
		RZ_LOG_ERROR("Can't find variable named `%s`\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	free(var->comment);
	var->comment = NULL;
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus meta_variable_comment_editor(RzCore *core, const char *name) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
	if (!var) {
		RZ_LOG_ERROR("Can't find variable named `%s`\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	char *comment = rz_core_editor(core, NULL, var->comment);
	if (comment) {
		free(var->comment);
		var->comment = comment;
	}
	return RZ_CMD_STATUS_OK;
}

static void meta_comment_append(RzCore *core, const char *newcomment, RzAnalysisMetaType mtype, ut64 addr) {
	const char *comment = rz_meta_get_string(core->analysis, mtype, addr);
	char *nc = strdup(newcomment);
	rz_str_unescape(nc);
	if (comment) {
		char *text = rz_str_newf("%s %s", comment, nc);
		if (text) {
			rz_meta_set_string(core->analysis, mtype, addr, text);
			free(text);
		} else {
			rz_sys_perror("malloc");
		}
	} else {
		rz_meta_set_string(core->analysis, mtype, addr, nc);
	}
	free(nc);
}

static void meta_editor(RzCore *core, RzAnalysisMetaType mtype, ut64 addr) {
	const char *comment = rz_meta_get_string(core->analysis, mtype, addr);
	char *out = rz_core_editor(core, NULL, comment);
	if (out) {
		rz_meta_del(core->analysis, mtype, addr, 1);
		rz_meta_set_string(core->analysis, mtype, addr, out);
		free(out);
	}
}

static void meta_remove_all(RzCore *core, RzAnalysisMetaType mtype) {
	rz_meta_del(core->analysis, mtype, 0, UT64_MAX);
}

static void meta_remove(RzCore *core, RzAnalysisMetaType mtype, ut64 addr) {
	rz_meta_del(core->analysis, mtype, addr, 1);
}

static void meta_remove_size(RzCore *core, RzAnalysisMetaType mtype, ut64 addr, ut64 size) {
	rz_meta_del(core->analysis, mtype, addr, size);
}

RZ_IPI RzCmdStatus rz_meta_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_ANY, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_list_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_at(core, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_ANY, core->offset, 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_ANY, 0, UT64_MAX);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		meta_comment_append(core, argv[1], RZ_META_TYPE_COMMENT, core->offset);
	} else {
		rz_core_meta_print_list_all(core, RZ_META_TYPE_COMMENT, state);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_at_handler(RzCore *core, int argc, const char **argv) {
	const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset);
	if (comment) {
		rz_cons_println(comment);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_append_handler(RzCore *core, int argc, const char **argv) {
	meta_comment_append(core, argv[1], RZ_META_TYPE_COMMENT, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, core->offset, 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, UT64_MAX, UT64_MAX);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_filelink_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset);
		if (RZ_STR_ISNOTEMPTY(comment)) {
			// Append filename to the current comment
			char *nc = rz_str_newf("%s ,(%s)", comment, argv[1]);
			rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset, nc);
			free(nc);
		} else {
			char *newcomment = rz_str_newf(",(%s)", argv[1]);
			rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset, newcomment);
			free(newcomment);
		}
	} else {
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset);
		if (RZ_STR_ISNOTEMPTY(comment)) {
			char *cmtfile = rz_str_between(comment, ",(", ")");
			if (cmtfile && *cmtfile) {
				char *cwd = getcommapath(core);
				rz_cons_printf("%s" RZ_SYS_DIR "%s\n", cwd, cmtfile);
				free(cwd);
			}
			free(cmtfile);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_add_at_handler(RzCore *core, int argc, const char **argv) {
	meta_comment_append(core, argv[1], RZ_META_TYPE_COMMENT, core->offset);
	ut64 addr = rz_num_math(core->num, argv[1]);
	rz_meta_set(core->analysis, RZ_META_TYPE_COMMENT, addr, 1, argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_editor_handler(RzCore *core, int argc, const char **argv) {
	meta_editor(core, RZ_META_TYPE_COMMENT, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_function_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_in_function(core, RZ_META_TYPE_COMMENT, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_function_remove_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisBlock *bb;
	RzListIter *iter;
	rz_list_foreach (fcn->bbs, iter, bb) {
		int i;
		for (i = 0; i < bb->size; i++) {
			ut64 addr = bb->addr + i;
			rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, addr, 1);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_unique_handler(RzCore *core, int argc, const char **argv) {
	char *comment = NULL;
	if (!strncmp(argv[1], "base64:", 7)) {
		char *s = (char *)sdb_decode(argv[1] + 7, NULL);
		if (s) {
			comment = s;
		}
	} else {
		comment = strdup(argv[1]);
	}
	if (comment) {
		rz_core_meta_comment_add(core, comment, core->offset);
		free(comment);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	spaces_list(ms, state->mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_rename_handler(RzCore *core, int argc, const char **argv) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	rz_spaces_rename(ms, argv[1], argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_remove_handler(RzCore *core, int argc, const char **argv) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	rz_spaces_unset(ms, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_remove_all_handler(RzCore *core, int argc, const char **argv) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	rz_spaces_unset(ms, NULL);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_var_comment_append_handler(RzCore *core, int argc, const char **argv) {
	return meta_variable_comment_append(core, argv[1], argv[2]);
}

RZ_IPI RzCmdStatus rz_meta_var_comment_remove_handler(RzCore *core, int argc, const char **argv) {
	return meta_variable_comment_remove(core, argv[1]);
}

RZ_IPI RzCmdStatus rz_meta_var_comment_editor_handler(RzCore *core, int argc, const char **argv) {
	return meta_variable_comment_editor(core, argv[1]);
}

RZ_IPI RzCmdStatus rz_meta_var_reg_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return meta_variable_comment_list(core, RZ_ANALYSIS_VAR_KIND_REG, state);
}

RZ_IPI RzCmdStatus rz_meta_var_bp_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return meta_variable_comment_list(core, RZ_ANALYSIS_VAR_KIND_BPV, state);
}

RZ_IPI RzCmdStatus rz_meta_var_stack_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return meta_variable_comment_list(core, RZ_ANALYSIS_VAR_KIND_SPV, state);
}

RZ_IPI RzCmdStatus rz_meta_type_current_handler(RzCore *core, int argc, const char **argv) {
	const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_VARTYPE, core->offset);
	if (comment) {
		rz_cons_println(comment);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_data_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		ut64 i, addr = core->offset;
		ut64 size = rz_num_math(core->num, argv[1]);
		ut64 repeat = argc > 2 ? rz_num_math(core->num, argv[2]) : 1;
		for (i = 0; i < repeat; i++, addr += size) {
			rz_meta_set(core->analysis, RZ_META_TYPE_DATA, addr, size, NULL);
		}
	} else {
		rz_core_meta_print_list_all(core, RZ_META_TYPE_DATA, state);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_data_remove_handler(RzCore *core, int argc, const char **argv) {
	meta_remove(core, RZ_META_TYPE_DATA, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_data_remove_all_handler(RzCore *core, int argc, const char **argv) {
	meta_remove_all(core, RZ_META_TYPE_DATA);
	return RZ_CMD_STATUS_OK;
}

static meta_string_ascii_add(RzCore *core, ut64 addr, char *name) {
	(void)rz_io_read_at(core->io, addr, (ut8 *)name, sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	name_len = strlen(name);
}

static meta_string_wide_add(RzCore *core, ut64 addr, size_t limit) {
	rz_return_if_fail(limit);
	ut8 *tmp = malloc(limit + 1);
	if (!tmp) {
		return;
	}
	(void)rz_io_read_at(core->io, addr, tmp, limit - 3);
	name_len = rz_str_nlen_w(tmp, limit - 3);
	int i, j;
	for (i = 0, j = 0; i < sizeof(name); i++, j++) {
		name[i] = tmp[j];
		if (!tmp[j]) {
			break;
		}
		if (!tmp[j + 1]) {
			if (j + 3 < sizeof(tmp)) {
				if (tmp[j + 3]) {
					break;
				}
			}
			j++;
		}
	}
	name[sizeof(name) - 1] = '\0';
}

static meta_string_add(RzCore *core, ut64 addr, ut64 size, RzStrEnc encoding) {
	if (encoding == RZ_STRING_ENC_LATIN1 || encoding == RZ_STRING_ENC_UTF8) {
		meta_string_ascii_add(core, addr, name);
	} else {
		meta_string_wide_add(core, addr, name);
	}
	rz_meta_set_with_subtype(core->analysis, type, encoding, addr, n, name);
}

RZ_IPI RzCmdStatus rz_meta_string_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		ut64 i, addr = core->offset;
		ut64 size = rz_num_math(core->num, argv[1]);
		ut64 repeat = argc > 2 ? rz_num_math(core->num, argv[2]) : 1;
		for (i = 0; i < repeat; i++, addr += size) {
			rz_meta_set(core->analysis, RZ_META_TYPE_DATA, addr, size, NULL);
		}
	} else {
		rz_core_meta_print_list_all(core, RZ_META_TYPE_STRING, state);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset);
	if (comment) {
		rz_cons_println(comment);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_utf8_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = rz_num_math(core->num, argv[1]);
	if (!meta_string_add(core, core->offset, size, RZ_STRING_ENC_UTF8)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_ascii_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = rz_num_math(core->num, argv[1]);
	if (!meta_string_add(core, core->offset, size, RZ_STRING_ENC_LATIN1)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_remove_handler(RzCore *core, int argc, const char **argv) {
	meta_remove(core, RZ_META_TYPE_STRING, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_remove_all_handler(RzCore *core, int argc, const char **argv) {
	meta_remove_all(core, RZ_META_TYPE_STRING);
	return RZ_CMD_STATUS_OK;
}

// These commands follow the same pattern
#define RZ_META_COMMAND_DESCRIPTOR(name, type) \
RZ_IPI RzCmdStatus rz_meta_##name##_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) { \
	if (argc > 1) { \
		meta_comment_append(core, argv[1], type, core->offset); \
	} else { \
		rz_core_meta_print_list_all(core, type, state); \
	} \
	return RZ_CMD_STATUS_OK; \
} \
RZ_IPI RzCmdStatus rz_meta_##name##_remove_handler(RzCore *core, int argc, const char **argv) { \
	meta_remove(core, type, core->offset); \
	return RZ_CMD_STATUS_OK; \
} \
RZ_IPI RzCmdStatus rz_meta_##name##_remove_all_handler(RzCore *core, int argc, const char **argv) { \
	meta_remove_all(core, type); \
	return RZ_CMD_STATUS_OK; \
} \
RZ_IPI RzCmdStatus rz_meta_##name##_editor_handler(RzCore *core, int argc, const char **argv) { \
	meta_editor(core, type, core->offset); \
	return RZ_CMD_STATUS_OK; \
}

RZ_META_COMMAND_DESCRIPTOR(type, RZ_META_TYPE_VARTYPE);
RZ_META_COMMAND_DESCRIPTOR(format, RZ_META_TYPE_FORMAT);
RZ_META_COMMAND_DESCRIPTOR(hidden, RZ_META_TYPE_HIDE);
RZ_META_COMMAND_DESCRIPTOR(magic, RZ_META_TYPE_MAGIC);
RZ_META_COMMAND_DESCRIPTOR(run, RZ_META_TYPE_RUN);
