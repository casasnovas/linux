/* Code coverage instrumentation for fuzzing.
   Copyright (C) 2015 Free Software Foundation, Inc.
   Contributed by Dmitry Vyukov <dvyukov@google.com>

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

GCC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */


#include "config.h"

#include "gcc-plugin.h"
#include "system.h"
#include "coretypes.h"
#include "alias.h"
#include "tree.h"
#include "tree-ssa-alias.h"
#include "basic-block.h"
#include "gimple-expr.h"
#include "gimple.h"
#include "basic-block.h"
#include "rtl.h"
#include "options.h"
#include "flags.h"
#include "stmt.h"
#include "expr.h"
#include "gimple-iterator.h"
#include "tree-cfg.h"
#include "tree-pass.h"
#include "tree-iterator.h"
#include "stringpool.h"
#include "context.h"

int plugin_is_GPL_compatible;

namespace {

static tree
coverage_callback (void)
{
  tree fn_type;
  static tree def;

  if (def != NULL)
    return def;

  fn_type = build_function_type_list (void_type_node, NULL_TREE);
  def = build_fn_decl ("__fuzz_coverage", fn_type);
  TREE_NOTHROW (def) = 1;
  DECL_ATTRIBUTES (def) = tree_cons (get_identifier ("leaf"), NULL, DECL_ATTRIBUTES (def));
  DECL_ASSEMBLER_NAME (def);
  return def;
}

unsigned fuzz_pass (void)
{
  basic_block bb;
  gimple_stmt_iterator gsi;
  gimple stmt, f;

  FOR_EACH_BB_FN (bb, cfun)
    {
      gsi = gsi_start_bb (bb);
      stmt = gsi_stmt (gsi);
      while (stmt && dyn_cast <glabel *> (stmt))
        {
          gsi_next (&gsi);
          stmt = gsi_stmt (gsi);
        }
      if (!stmt)
        continue;
      f = gimple_build_call (coverage_callback (), 0);
      gimple_set_location (f, gimple_location (stmt));
      gsi_insert_before (&gsi, f, GSI_SAME_STMT);
    }
  return 0;
}

const pass_data pass_data_fuzz =
{
  GIMPLE_PASS, /* type */
  "fuzz", /* name */
  OPTGROUP_NONE, /* optinfo_flags */
  TV_NONE, /* tv_id */
  ( PROP_cfg ), /* properties_required */
  0, /* properties_provided */
  0, /* properties_destroyed */
  0, /* todo_flags_start */
  TODO_update_ssa, /* todo_flags_finish */
};

class pass_fuzz : public gimple_opt_pass
{
public:
  pass_fuzz (gcc::context *ctxt)
    : gimple_opt_pass (pass_data_fuzz, ctxt)
  {}

  opt_pass * clone () { return new pass_fuzz (m_ctxt); }
  virtual bool gate (function *) { return fuzzing_coverage_flag; }
  virtual unsigned int execute (function *) { return fuzz_pass (); }
};

} // anon namespace

static gimple_opt_pass *
make_pass (gcc::context *ctxt)
{
	return new pass_fuzz (ctxt);
}

int plugin_init(plugin_name_args* info, plugin_gcc_version* ver)
{
	struct register_pass_info new_pass = {
		.pass = make_pass(g),
		.reference_pass_name = "pass_lower_complex_O0",
		.ref_pass_instance_number = 0,
		.pos_op = PASS_POS_INSERT_AFTER,
	};
	
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, &new_pass, NULL);
}
