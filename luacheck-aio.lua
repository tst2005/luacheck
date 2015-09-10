#!/usr/bin/env lua
do local sources, priorities = {}, {};assert(not sources["luacheck.check"])sources["luacheck.check"]=([===[-- <pack luacheck.check> --
local parse = require "luacheck.parser"
local linearize = require "luacheck.linearize"
local analyze = require "luacheck.analyze"
local reachability = require "luacheck.reachability"
local handle_inline_options = require "luacheck.inline_options"
local core_utils = require "luacheck.core_utils"
local utils = require "luacheck.utils"

local function is_secondary(value)
   return value.secondaries and value.secondaries.used
end

local ChState = utils.class()

function ChState:__init()
   self.warnings = {}
end

function ChState:warn(warning, implicit_self)
   if not warning.end_column then
      warning.end_column = implicit_self and warning.column or (warning.column + #warning.name - 1)
   end

   table.insert(self.warnings, warning)
end

local action_codes = {
   set = 1,
   mutate = 2,
   access = 3
}

local type_codes = {
   var = 1,
   func = 1,
   arg = 2,
   loop = 3,
   loopi = 3
}

function ChState:warn_global(node, action, is_top)
   self:warn({
      code = "11" .. action_codes[action],
      name = node[1],
      line = node.location.line,
      column = node.location.column,
      top = is_top and (action == "set") or nil
   })
end

-- W12* (read-only global) and W131 (unused global) are patched in during filtering.

function ChState:warn_unused_variable(var)
   self:warn({
      code = "21" .. type_codes[var.type],
      name = var.name,
      line = var.location.line,
      column = var.location.column,
      secondary = is_secondary(var.values[1]) or nil,
      func = (var.values[1].type == "func") or nil,
      self = var.self
   }, var.self)
end

function ChState:warn_unset(var)
   self:warn({
      code = "221",
      name = var.name,
      line = var.location.line,
      column = var.location.column
   })
end

function ChState:warn_unaccessed(var)
   -- Mark as secondary if all assigned values are secondary.
   -- It is guaranteed that there are at least two values.
   local secondary = true

   for _, value in ipairs(var.values) do
      if not value.empty and not is_secondary(value) then
         secondary = nil
         break
      end
   end

   self:warn({
      code = "23" .. type_codes[var.type],
      name = var.name,
      line = var.location.line,
      column = var.location.column,
      secondary = secondary
   }, var.self)
end

function ChState:warn_unused_value(value)
   self:warn({
      code = "31" .. type_codes[value.type],
      name = value.var.name,
      line = value.location.line,
      column = value.location.column,
      secondary = is_secondary(value) or nil
   }, value.type == "arg" and value.var.self)
end

function ChState:warn_uninit(node)
   self:warn({
      code = "321",
      name = node[1],
      line = node.location.line,
      column = node.location.column
   })
end

function ChState:warn_redefined(var, prev_var, same_scope)
   if var.name ~= "..." then
      self:warn({
         code = "4" .. (same_scope and "1" or (var.line == prev_var.line and "2" or "3")) .. type_codes[prev_var.type],
         name = var.name,
         line = var.location.line,
         column = var.location.column,
         self = var.self and prev_var.self,
         prev_line = prev_var.location.line,
         prev_column = prev_var.location.column
      }, var.self)
   end
end

function ChState:warn_unreachable(location, unrepeatable, token)
   self:warn({
      code = "51" .. (unrepeatable and "2" or "1"),
      line = location.line,
      column = location.column,
      end_column = location.column + #token - 1
   })
end

function ChState:warn_unused_label(label)
   self:warn({
      code = "521",
      name = label.name,
      line = label.location.line,
      column = label.location.column,
      end_column = label.end_column
   })
end

function ChState:warn_unbalanced(location, shorter_lhs)
   -- Location points to `=`.
   self:warn({
      code = "53" .. (shorter_lhs and "1" or "2"),
      line = location.line,
      column = location.column,
      end_column = location.column
   })
end

function ChState:warn_empty_block(location, do_end)
   -- Location points to `do`, `then` or `else`.
   self:warn({
      code = "54" .. (do_end and "1" or "2"),
      line = location.line,
      column = location.column,
      end_column = location.column + (do_end and 1 or 3)
   })
end

local function check_or_throw(src)
   local ast, comments, code_lines = parse(src)
   local chstate = ChState()
   local line = linearize(chstate, ast)
   analyze(chstate, line)
   reachability(chstate, line)
   handle_inline_options(ast, comments, code_lines, chstate.warnings)
   core_utils.sort_by_location(chstate.warnings)
   return chstate.warnings
end

--- Checks source.
-- Returns an array of warnings and errors. Codes for errors start with "0".
-- Syntax errors (with code "011") have message stored in .msg field.
local function check(src)
   local warnings, err = utils.pcall(check_or_throw, src)

   if warnings then
      return warnings
   else
      local syntax_error = {
         code = "011",
         line = err.line,
         column = err.column,
         end_column = err.end_column,
         msg = err.msg
      }

      return {syntax_error}
   end
end

return check
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.config"])sources["luacheck.config"]=([===[-- <pack luacheck.config> --
local options = require "luacheck.options"
local stds = require "luacheck.stds"
local fs = require "luacheck.fs"
local utils = require "luacheck.utils"

local config = {}

-- Config must support special metatables for some keys:
-- autovivification for `files`, fallback to built-in stds for `stds`.

local special_mts = {
   stds = {__index = stds},
   files = {__index = function(files, key)
      files[key] = {}
      return files[key]
   end}
}

local function make_config_env_mt()
   local env_mt = {}
   local special_values = {}

   for key, mt in pairs(special_mts) do
      special_values[key] = setmetatable({}, mt)
   end

   function env_mt.__index(_, key)
      if special_mts[key] then
         return special_values[key]
      else
         return _G[key]
      end
   end

   function env_mt.__newindex(env, key, value)
      if special_mts[key] then
         if type(value) == "table" then
            setmetatable(value, special_mts[key])
         end

         special_values[key] = value
      else
         rawset(env, key, value)
      end
   end

   return env_mt, special_values
end

local function make_config_env()
   local mt, special_values = make_config_env_mt()
   return setmetatable({}, mt), special_values
end

local function remove_env_mt(env, special_values)
   setmetatable(env, nil)
   utils.update(env, special_values)
end

local top_options = {
   color = utils.has_type("boolean"),
   codes = utils.has_type("boolean"),
   formatter = utils.either(utils.has_type("string"), utils.has_type("function")),
   cache = utils.either(utils.has_type("string"), utils.has_type("boolean")),
   jobs = function(x) return type(x) == "number" and math.floor(x) == x and x >= 1 end,
   files = utils.has_type("table"),
   stds = utils.has_type("table"),
   exclude_files = utils.array_of("string"),
   include_files = utils.array_of("string")
}

utils.update(top_options, options.all_options)
options.add_order(top_options)

-- Returns error or nil if options are valid.
local function validate_options(option_set, opts)
   local ok, invalid_field = options.validate(option_set, opts)

   if not ok then
      if invalid_field then
         return ("invalid value of option '%s'"):format(invalid_field)
      else
         return "validation error"
      end
   end
end

-- Returns error or nil if config is valid.
local function validate_config(conf)
   local top_err = validate_options(top_options, conf)

   if top_err then
      return top_err
   end

   for path, opts in pairs(conf.files) do
      if type(path) == "string" then
         local override_err = validate_options(options.all_options, opts)

         if override_err then
            return ("%s in options for path '%s'"):format(override_err, path)
         end
      end
   end
end

-- Returns table with field `paths` containing sorted normalize paths
-- used in overrides and `options` mapping these paths to options.
local function normalize_overrides(files, abs_conf_dir)
   local overrides = {paths = {}, options = {}}

   local orig_paths = {}

   for path in pairs(files) do
      table.insert(orig_paths, path)
   end

   table.sort(orig_paths)

   for _, orig_path in ipairs(orig_paths) do
      local path = fs.normalize(fs.join(abs_conf_dir, orig_path))

      if not overrides.options[path] then
         table.insert(overrides.paths, path)
      end

      overrides.options[path] = files[orig_path]
   end

   table.sort(overrides.paths)
   return overrides
end

local function try_load(path)
   local src = utils.read_file(path)

   if not src then
      return
   end

   local func, err = utils.load(src, nil, "@"..path)
   return err or func
end

local function add_relative_loader(conf)
   local function loader(modname)
      local modpath = fs.join(conf.rel_dir, modname:gsub("%.", utils.dir_sep))
      return try_load(modpath..".lua") or try_load(modpath..utils.dir_sep.."init.lua"), modname
   end

   table.insert(package.loaders or package.searchers, 1, loader)
   return loader
end

local function remove_relative_loader(loader)
   for i, func in ipairs(package.loaders or package.searchers) do
      if func == loader then
         table.remove(package.loaders or package.searchers, i)
         return
      end
   end
end

config.default_path = ".luacheckrc"
config.empty_config = {empty = true}

-- Loads config from path, returns config object or nil and error message.
function config.load_config(path)
   local is_default_path = not path
   path = path or config.default_path

   local current_dir = fs.current_dir()
   local abs_conf_dir, rel_conf_dir = fs.find_file(current_dir, path)

   if not abs_conf_dir then
      if is_default_path then
         return config.empty_config
      else
         return nil, "Couldn't find configuration file "..path
      end
   end

   local conf = {
      abs_dir = abs_conf_dir,
      rel_dir = rel_conf_dir,
      cur_dir = current_dir
   }

   local conf_path = fs.join(rel_conf_dir, path)
   local env, special_values = make_config_env()
   local loader = add_relative_loader(conf)
   local load_ok, ret = utils.load_config(conf_path, env)
   remove_relative_loader(loader)

   if not load_ok then
      return nil, ("Couldn't load configuration from %s: %s error"):format(conf_path, ret)
   end

   -- Support returning some options from config instead of setting them as globals.
   -- This allows easily loading options from another file, for example using require.
   if type(ret) == "table" then
      utils.update(env, ret)
   end

   remove_env_mt(env, special_values)

   -- Update stds before validating config - std validation relies on that.
   if type(env.stds) == "table" then
      -- Ideally config shouldn't mutate global stds, not if `luacheck.config` becomes public
      -- interface.
      utils.update(stds, env.stds)
   end

   local err = validate_config(env)

   if err then
      return nil, ("Couldn't load configuration from %s: %s"):format(conf_path, err)
   end

   conf.options = env
   conf.overrides = normalize_overrides(env.files, abs_conf_dir)
   return conf
end

-- Adjusts path starting from config dir to start from current directory.
function config.relative_path(conf, path)
   if conf.empty then
      return path
   else
      return fs.join(conf.rel_dir, path)
   end
end

-- Requires module from config directory.
-- Returns success flag and module or error message.
function config.relative_require(conf, modname)
   local loader

   if not conf.empty then
      loader = add_relative_loader(conf)
   end

   local ok, mod_or_err = pcall(require, modname)

   if not conf.empty then
      remove_relative_loader(loader)
   end

   return ok, mod_or_err
end

-- Returns top-level options.
function config.get_top_options(conf)
   return conf.empty and {} or conf.options
end

-- Returns array of options for a file.
function config.get_options(conf, file)
   if conf.empty then
      return {}
   end

   local res = {conf.options}

   if type(file) ~= "string" then
      return res
   end

   local path = fs.normalize(fs.join(conf.cur_dir, file))

   for _, override_path in ipairs(conf.overrides.paths) do
      if fs.is_subpath(override_path, path) then
         table.insert(res, conf.overrides.options[override_path])
      end
   end

   return res
end

return config
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.options"])sources["luacheck.options"]=([===[-- <pack luacheck.options> --
local options = {}

local utils = require "luacheck.utils"
local stds = require "luacheck.stds"

local boolean = utils.has_type("boolean")
local array_of_strings = utils.array_of("string")

function options.split_std(std)
   local parts = utils.split(std, "+")

   if parts[1]:match("^%s*$") then
      parts.add = true
      table.remove(parts, 1)
   end

   for i, part in ipairs(parts) do
      parts[i] = utils.strip(part)

      if not stds[parts[i]] then
         return
      end
   end

   return parts
end

local function std_or_array_of_strings(x)
   return array_of_strings(x) or (type(x) == "string" and options.split_std(x))
end

function options.add_order(option_set)
   local opts = {}

   for option in pairs(option_set) do
      if type(option) == "string" then
         table.insert(opts, option)
      end
   end

   table.sort(opts)
   utils.update(option_set, opts)
end

options.nullary_inline_options = {
   global = boolean,
   unused = boolean,
   redefined = boolean,
   unused_args = boolean,
   unused_secondaries = boolean,
   self = boolean,
   compat = boolean,
   allow_defined = boolean,
   allow_defined_top = boolean,
   module = boolean
}

options.variadic_inline_options = {
   globals = array_of_strings,
   read_globals = array_of_strings,
   new_globals = array_of_strings,
   new_read_globals = array_of_strings,
   ignore = array_of_strings,
   enable = array_of_strings,
   only = array_of_strings
}

options.all_options = {
   std = std_or_array_of_strings,
   inline = boolean
}

utils.update(options.all_options, options.nullary_inline_options)
utils.update(options.all_options, options.variadic_inline_options)
options.add_order(options.all_options)

-- Returns true if opts is valid option_set.
-- Otherwise returns false and, optionally, name of the problematic option.
function options.validate(option_set, opts)
   if opts == nil then
      return true
   end

   local ok, is_valid, invalid_opt = pcall(function()
      assert(type(opts) == "table")

      for _, option in ipairs(option_set) do
         if opts[option] ~= nil then
            if not option_set[option](opts[option]) then
               return false, option
            end
         end
      end

      return true
   end)

   return ok and is_valid, invalid_opt
end

-- Option stack is an array of options with options closer to end
-- overriding options closer to beginning.

-- Returns sets of std globals and read-only std globals from option stack.
-- Std globals can be set using compat option (sets std to stds.max) or std option.
-- If std is a table, array part contains read-only globals, hash part - regular globals as keys.
-- If it is a string, it must contain names of standard sets separated by +.
-- If prefixed with +, standard sets will be added on top of existing ones.
local function get_std_sets(opts_stack)
   local base_std
   local add_stds = {}
   local no_compat = false

   for _, opts in utils.ripairs(opts_stack) do
      if opts.compat and not no_compat then
         base_std = "max"
         break
      elseif opts.compat == false then
         no_compat = true
      end

      if opts.std then
         if type(opts.std) == "table" then
            base_std = opts.std
            break
         else
            local parts = options.split_std(opts.std)

            for _, part in ipairs(parts) do
               table.insert(add_stds, part)
            end

            if not parts.add then
               base_std = {}
               break
            end
         end
      end
   end

   table.insert(add_stds, base_std or "_G")

   local std_globals = {}
   local std_read_globals = {}

   for _, add_std in ipairs(add_stds) do
      add_std = stds[add_std] or add_std

      for _, read_global in ipairs(add_std) do
         std_read_globals[read_global] = true
      end

      for global in pairs(add_std) do
         if type(global) == "string" then
            std_globals[global] = true
         end
      end
   end

   return std_globals, std_read_globals
end

local function get_globals(opts_stack, key)
   local globals_lists = {}

   for _, opts in utils.ripairs(opts_stack) do
      if opts["new_" .. key] then
         table.insert(globals_lists, opts["new_" .. key])
         break
      end

      if opts[key] then
         table.insert(globals_lists, opts[key])
      end
   end

   return utils.concat_arrays(globals_lists)
end

local function get_boolean_opt(opts_stack, option)
   for _, opts in utils.ripairs(opts_stack) do
      if opts[option] ~= nil then
         return opts[option]
      end
   end
end

local function anchor_pattern(pattern, only_start)
   if not pattern then
      return
   end

   if pattern:sub(1, 1) == "^" or pattern:sub(-1) == "$" then
      return pattern
   else
      return "^" .. pattern .. (only_start and "" or "$")
   end
end

-- Returns {pair of normalized patterns for code and name}.
-- `pattern` can be:
--    string containing '/': first part matches warning code, second - variable name;
--    string containing letters: matches variable name;
--    otherwise: matches warning code.
-- Unless anchored by user, pattern for name is anchored from both sides
-- and pattern for code is only anchored at the beginning.
local function normalize_pattern(pattern)
   local code_pattern, name_pattern
   local slash_pos = pattern:find("/")

   if slash_pos then
      code_pattern = pattern:sub(1, slash_pos - 1)
      name_pattern = pattern:sub(slash_pos + 1)
   elseif pattern:find("[_a-zA-Z]") then
      name_pattern = pattern
   else
      code_pattern = pattern
   end

   return {anchor_pattern(code_pattern, true), anchor_pattern(name_pattern)}
end

-- From most specific to less specific, pairs {option, pattern}.
-- Applying macros in order is required to get deterministic resuls
-- and get sensible results when intersecting macros are used.
-- E.g. unused = false, unused_args = true should leave unused args enabled.
local macros = {
   {"unused_args", "21[23]"},
   {"global", "1"},
   {"unused", "[23]"},
   {"redefined", "4"}
}

-- Returns array of rules which should be applied in order.
-- A rule is a table {{pattern*}, type}.
-- `pattern` is a non-normalized pattern.
-- `type` can be "enable", "disable" or "only".
local function get_rules(opts_stack)
   local rules = {}
   local used_macros = {}

   for _, opts in utils.ripairs(opts_stack) do
      for _, macro_info in ipairs(macros) do
         local option, pattern = macro_info[1], macro_info[2]

         if not used_macros[option] then
            if opts[option] ~= nil then
               table.insert(rules, {{pattern}, opts[option] and "enable" or "disable"})
               used_macros[option] = true
            end
         end
      end

      if opts.ignore then
         table.insert(rules, {opts.ignore, "disable"})
      end

      if opts.only then
         table.insert(rules, {opts.only, "only"})
      end

      if opts.enable then
         table.insert(rules, {opts.enable, "enable"})
      end
   end

   return rules
end

local function normalize_patterns(rules)
   local res = {}

   for i, rule in ipairs(rules) do
      res[i] = {{}, rule[2]}

      for j, pattern in ipairs(rule[1]) do
         res[i][1][j] = normalize_pattern(pattern)
      end
   end

   return res
end

-- Returns normalized options.
-- Normalized options have fields:
--    globals: set of strings;
--    read_globals: subset of globals;
--    unused_secondaries, module, allow_defined, allow_defined_top: booleans;
--    rules: see get_rules.
function options.normalize(opts_stack)
   local res = {}

   res.globals = utils.array_to_set(get_globals(opts_stack, "globals"))
   res.read_globals = utils.array_to_set(get_globals(opts_stack, "read_globals"))
   local std_globals, std_read_globals = get_std_sets(opts_stack)
   utils.update(res.globals, std_globals)
   utils.update(res.read_globals, std_read_globals)

   for k in pairs(res.globals) do
      res.read_globals[k] = nil
   end

   utils.update(res.globals, res.read_globals)

   for i, option in ipairs {"unused_secondaries", "self", "inline", "module", "allow_defined", "allow_defined_top"} do
      local value = get_boolean_opt(opts_stack, option)

      if value == nil then
         res[option] = i < 4
      else
         res[option] = value
      end
   end

   res.rules = normalize_patterns(get_rules(opts_stack))
   return res
end

return options
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.parser"])sources["luacheck.parser"]=([===[-- <pack luacheck.parser> --
local lexer = require "luacheck.lexer"
local utils = require "luacheck.utils"

local function new_state(src)
   return {
      lexer = lexer.new_state(src),
      code_lines = {}, -- Set of line numbers containing code.
      comments = {} -- Array of {comment = string, location = location}.
   }
end

local function location(state)
   return {
      line = state.line,
      column = state.column,
      offset = state.offset
   }
end

local function token_body_or_line(state)
   return state.lexer.src:sub(state.offset, state.lexer.offset - 1):match("^[^\r\n]*")
end

local function skip_token(state)
   while true do
      local err_end_column
      state.token, state.token_value, state.line, state.column, state.offset, err_end_column = lexer.next_token(state.lexer)

      if not state.token then
         lexer.syntax_error(state, err_end_column, state.token_value)
      elseif state.token == "comment" then
         state.comments[#state.comments+1] = {
            contents = state.token_value,
            location = location(state),
            end_column = state.column + #token_body_or_line(state) - 1
         }
      else
         state.code_lines[state.line] = true
         break
      end
   end
end

local function init_ast_node(node, loc, tag)
   node.location = loc
   node.tag = tag
   return node
end

local function new_ast_node(state, tag)
   return init_ast_node({}, location(state), tag)
end

local token_names = {
   eof = "<eof>",
   name = "identifier",
   ["do"] = "'do'",
   ["end"] = "'end'",
   ["then"] = "'then'",
   ["in"] = "'in'",
   ["until"] = "'until'",
   ["::"] = "'::'"
}

local function token_name(token)
   return token_names[token] or lexer.quote(token)
end

local function parse_error(state, msg)
   msg = msg or "syntax error"
   local token_repr, end_column

   if state.token == "eof" then
      token_repr = "<eof>"
      end_column = state.column
   else
      token_repr = token_body_or_line(state)
      end_column = state.column + #token_repr - 1
      token_repr = lexer.quote(token_repr)
   end

   lexer.syntax_error(state, end_column, msg .. " near " .. token_repr)
end

local function check_token(state, token)
   if state.token ~= token then
      parse_error(state, "expected " .. token_name(token))
   end
end

local function check_and_skip_token(state, token)
   check_token(state, token)
   skip_token(state)
end

local function test_and_skip_token(state, token)
   if state.token == token then
      skip_token(state)
      return true
   end
end

local function check_name(state)
   check_token(state, "name")
   return state.token_value
end

-- If needed, wraps last expression in expressions in "Paren" node.
local function opt_add_parens(expressions, is_inside_parentheses)
   if is_inside_parentheses then
      local last = expressions[#expressions]

      if last and last.tag == "Call" or last.tag == "Invoke" or last.tag == "Dots" then
         expressions[#expressions] = init_ast_node({last}, last.location, "Paren")
      end
   end
end

local parse_block, parse_expression

local function parse_expression_list(state)
   local list = {}
   local is_inside_parentheses

   repeat
      list[#list+1], is_inside_parentheses = parse_expression(state)
   until not test_and_skip_token(state, ",")

   opt_add_parens(list, is_inside_parentheses)
   return list
end

local function parse_id(state, tag)
   local ast_node = new_ast_node(state, tag or "Id")
   ast_node[1] = check_name(state)
   skip_token(state)  -- Skip name.
   return ast_node
end

local function atom(tag)
   return function(state)
      local ast_node = new_ast_node(state, tag)
      ast_node[1] = state.token_value
      skip_token(state)
      return ast_node
   end
end

local simple_expressions = {}

simple_expressions.number = atom("Number")
simple_expressions.string = atom("String")
simple_expressions["nil"] = atom("Nil")
simple_expressions["true"] = atom("True")
simple_expressions["false"] = atom("False")
simple_expressions["..."] = atom("Dots")

simple_expressions["{"] = function(state)
   local ast_node = new_ast_node(state, "Table")
   skip_token(state)  -- Skip "{"
   local is_inside_parentheses = false

   repeat
      if state.token == "}" then
         break
      else
         local lhs, rhs
         local item_location = location(state)

         if state.token == "name" then
            local name = state.token_value
            skip_token(state)  -- Skip name.

            if test_and_skip_token(state, "=") then
               -- `name` = `expr`.
               lhs = init_ast_node({name}, item_location, "String")
               rhs, is_inside_parentheses = parse_expression(state)
            else
               -- `name` is beginning of an expression in array part.
               -- Backtrack lexer to before name.
               state.lexer.line = item_location.line
               state.lexer.line_offset = item_location.offset-item_location.column+1
               state.lexer.offset = item_location.offset
               skip_token(state)  -- Load name again.
               rhs, is_inside_parentheses = parse_expression(state)
            end
         elseif test_and_skip_token(state, "[") then
            -- [ `expr` ] = `expr`.
            lhs = parse_expression(state)
            check_and_skip_token(state, "]")
            check_and_skip_token(state, "=")
            rhs = parse_expression(state)
         else
            -- Expression in array part.
            rhs, is_inside_parentheses = parse_expression(state)
         end

         if lhs then
            -- Pair.
            ast_node[#ast_node+1] = init_ast_node({lhs, rhs}, item_location, "Pair")
         else
            -- Array part item.
            ast_node[#ast_node+1] = rhs
         end
      end
   until not (test_and_skip_token(state, ",") or test_and_skip_token(state, ";"))

   check_and_skip_token(state, "}")
   opt_add_parens(ast_node, is_inside_parentheses)
   return ast_node
end

-- Parses argument list and the statements.
local function parse_function(state, location_)
   check_and_skip_token(state, "(")
   local args = {}

   if state.token ~= ")" then  -- Are there arguments?
      repeat
         if state.token == "name" then
            args[#args+1] = parse_id(state)
         elseif state.token == "..." then
            args[#args+1] = simple_expressions["..."](state)
            break
         else
            parse_error(state, "expected argument")
         end
      until not test_and_skip_token(state, ",")
   end

   check_and_skip_token(state, ")")
   local body = parse_block(state)
   local end_location = location(state)
   check_and_skip_token(state, "end")
   return init_ast_node({args, body, end_location = end_location}, location_, "Function")
end

simple_expressions["function"] = function(state)
   local function_location = location(state)
   skip_token(state)  -- Skip "function".
   return parse_function(state, function_location)
end

local function parse_prefix_expression(state)
   if state.token == "name" then
      return parse_id(state)
   elseif state.token == "(" then
      skip_token(state)  -- Skip "("
      local expression = parse_expression(state)
      check_and_skip_token(state, ")")
      return expression
   else
      parse_error(state, "unexpected symbol")
   end
end

local calls = {}

calls["("] = function(state)
   skip_token(state) -- Skip "(".
   local args = (state.token == ")") and {} or parse_expression_list(state)
   check_and_skip_token(state, ")")
   return args
end

calls["{"] = function(state)
   return {simple_expressions[state.token](state)}
end

calls.string = calls["{"]

local suffixes = {}

suffixes["."] = function(state, lhs)
   skip_token(state)  -- Skip ".".
   local rhs = parse_id(state, "String")
   return init_ast_node({lhs, rhs}, lhs.location, "Index")
end

suffixes["["] = function(state, lhs)
   skip_token(state)  -- Skip "[".
   local rhs = parse_expression(state)
   check_and_skip_token(state, "]")
   return init_ast_node({lhs, rhs}, lhs.location, "Index")
end

suffixes[":"] = function(state, lhs)
   skip_token(state)  -- Skip ":".
   local method_name = parse_id(state, "String")
   local args = (calls[state.token] or parse_error)(state, "expected method arguments")
   table.insert(args, 1, lhs)
   table.insert(args, 2, method_name)
   return init_ast_node(args, lhs.location, "Invoke")
end

suffixes["("] = function(state, lhs)
   local args = calls[state.token](state)
   table.insert(args, 1, lhs)
   return init_ast_node(args, lhs.location, "Call")
end

suffixes["{"] = suffixes["("]
suffixes.string = suffixes["("]

-- Additionally returns whether primary expression is prefix expression.
local function parse_primary_expression(state)
   local expression = parse_prefix_expression(state)
   local is_prefix = true

   while true do
      local handler = suffixes[state.token]

      if handler then
         is_prefix = false
         expression = handler(state, expression)
      else
         return expression, is_prefix
      end
   end
end

-- Additionally returns whether simple expression is prefix expression.
local function parse_simple_expression(state)
   return (simple_expressions[state.token] or parse_primary_expression)(state)
end

local unary_operators = {
   ["not"] = "not",
   ["-"] = "unm",  -- Not mentioned in Metalua documentation.
   ["~"] = "bnot",
   ["#"] = "len"
}

local unary_priority = 12

local binary_operators = {
   ["+"] = "add", ["-"] = "sub",
   ["*"] = "mul", ["%"] = "mod",
   ["^"] = "pow",
   ["/"] = "div", ["//"] = "idiv",
   ["&"] = "band", ["|"] = "bor", ["~"] = "bxor",
   ["<<"] = "shl", [">>"] = "shr",
   [".."] = "concat",
   ["~="] = "ne", ["=="] = "eq",
   ["<"] = "lt", ["<="] = "le",
   [">"] = "gt", [">="] = "ge",
   ["and"] = "and", ["or"] = "or"
}

local left_priorities = {
   add = 10, sub = 10,
   mul = 11, mod = 11,
   pow = 14,
   div = 11, idiv = 11,
   band = 6, bor = 4, bxor = 5,
   shl = 7, shr = 7,
   concat = 9,
   ne = 3, eq = 3,
   lt = 3, le = 3,
   gt = 3, ge = 3,
   ["and"] = 2, ["or"] = 1
}

local right_priorities = {
   add = 10, sub = 10,
   mul = 11, mod = 11,
   pow = 13,
   div = 11, idiv = 11,
   band = 6, bor = 4, bxor = 5,
   shl = 7, shr = 7,
   concat = 8,
   ne = 3, eq = 3,
   lt = 3, le = 3,
   gt = 3, ge = 3,
   ["and"] = 2, ["or"] = 1
}

-- Additionally returns whether subexpression is prefix expression.
local function parse_subexpression(state, limit)
   local expression
   local is_prefix
   local unary_operator = unary_operators[state.token]

   if unary_operator then
      local unary_location = location(state)
      skip_token(state)  -- Skip operator.
      local unary_operand = parse_subexpression(state, unary_priority)
      expression = init_ast_node({unary_operator, unary_operand}, unary_location, "Op")
   else
      expression, is_prefix = parse_simple_expression(state)
   end

   -- Expand while operators have priorities higher than `limit`.
   while true do
      local binary_operator = binary_operators[state.token]

      if not binary_operator or left_priorities[binary_operator] <= limit then
         break
      end

      is_prefix = false
      skip_token(state)  -- Skip operator.
      -- Read subexpression with higher priority.
      local subexpression = parse_subexpression(state, right_priorities[binary_operator])
      expression = init_ast_node({binary_operator, expression, subexpression}, expression.location, "Op")
   end

   return expression, is_prefix
end

-- Additionally returns whether expression is inside parentheses.
function parse_expression(state, save_first_token)
   local first_token = token_body_or_line(state)
   local expression, is_prefix = parse_subexpression(state, 0)
   expression.first_token = save_first_token and first_token
   return expression, is_prefix and first_token == "("
end

local statements = {}

statements["if"] = function(state, loc)
   local ast_node = init_ast_node({}, loc, "If")

   repeat
      ast_node[#ast_node+1] = parse_expression(state, true)
      local branch_location = location(state)
      check_and_skip_token(state, "then")
      ast_node[#ast_node+1] = parse_block(state, branch_location)
   until not test_and_skip_token(state, "elseif")

   if state.token == "else" then
      local branch_location = location(state)
      skip_token(state)
      ast_node[#ast_node+1] = parse_block(state, branch_location)
   end

   check_and_skip_token(state, "end")
   return ast_node
end

statements["while"] = function(state, loc)
   local condition = parse_expression(state)
   check_and_skip_token(state, "do")
   local block = parse_block(state)
   check_and_skip_token(state, "end")
   return init_ast_node({condition, block}, loc, "While")
end

statements["do"] = function(state, loc)
   local ast_node = init_ast_node(parse_block(state), loc, "Do")
   check_and_skip_token(state, "end")
   return ast_node
end

statements["for"] = function(state, loc)
   local ast_node = init_ast_node({}, loc)  -- Will set ast_node.tag later.
   local first_var = parse_id(state)

   if state.token == "=" then
      -- Numeric "for" loop.
      ast_node.tag = "Fornum"
      skip_token(state)
      ast_node[1] = first_var
      ast_node[2] = parse_expression(state)
      check_and_skip_token(state, ",")
      ast_node[3] = parse_expression(state)

      if test_and_skip_token(state, ",") then
         ast_node[4] = parse_expression(state)
      end

      check_and_skip_token(state, "do")
      ast_node[#ast_node+1] = parse_block(state)
   elseif state.token == "," or state.token == "in" then
      -- Generic "for" loop.
      ast_node.tag = "Forin"

      local iter_vars = {first_var}
      while test_and_skip_token(state, ",") do
         iter_vars[#iter_vars+1] = parse_id(state)
      end

      ast_node[1] = iter_vars
      check_and_skip_token(state, "in")
      ast_node[2] = parse_expression_list(state)
      check_and_skip_token(state, "do")
      ast_node[3] = parse_block(state)
   else
      parse_error(state, "expected '=', ',' or 'in'")
   end

   check_and_skip_token(state, "end")
   return ast_node
end

statements["repeat"] = function(state, loc)
   local block = parse_block(state)
   check_and_skip_token(state, "until")
   local condition = parse_expression(state, true)
   return init_ast_node({block, condition}, loc, "Repeat")
end

statements["function"] = function(state, loc)
   local lhs_location = location(state)
   local lhs = parse_id(state)
   local self_location

   while (not self_location) and (state.token == "." or state.token == ":") do
      self_location = state.token == ":" and location(state)
      skip_token(state)  -- Skip "." or ":".
      lhs = init_ast_node({lhs, parse_id(state, "String")}, lhs_location, "Index")
   end

   local function_node = parse_function(state, loc)

   if self_location then
      -- Insert implicit "self" argument.
      local self_arg = init_ast_node({"self", implicit = true}, self_location, "Id")
      table.insert(function_node[1], 1, self_arg)
   end

   return init_ast_node({{lhs}, {function_node}}, loc, "Set")
end

statements["local"] = function(state, loc)
   if state.token == "function" then
      -- Localrec
      local function_location = location(state)
      skip_token(state)  -- Skip "function".
      local var = parse_id(state)
      local function_node = parse_function(state, function_location)
      -- Metalua would return {{var}, {function}} for some reason.
      return init_ast_node({var, function_node}, loc, "Localrec")
   end

   local lhs = {}
   local rhs

   repeat
      lhs[#lhs+1] = parse_id(state)
   until not test_and_skip_token(state, ",")

   local equals_location = location(state)

   if test_and_skip_token(state, "=") then
      rhs = parse_expression_list(state)
   end

   -- According to Metalua spec, {lhs} should be returned if there is no rhs.
   -- Metalua does not follow the spec itself and returns {lhs, {}}.
   return init_ast_node({lhs, rhs, equals_location = rhs and equals_location}, loc, "Local")
end

statements["::"] = function(state, loc)
   local end_column = loc.column + 1
   local name = check_name(state)

   if state.line == loc.line then
      -- Label name on the same line as opening `::`, pull token end to name end.
      end_column = state.column + #state.token_value - 1
   end

   skip_token(state)  -- Skip label name.

   if state.line == loc.line then
      -- Whole label is on one line, pull token end to closing `::` end.
      end_column = state.column + 1
   end

   check_and_skip_token(state, "::")
   return init_ast_node({name, end_column = end_column}, loc, "Label")
end

local closing_tokens = utils.array_to_set({
   "end", "eof", "else", "elseif", "until"})

statements["return"] = function(state, loc)
   if closing_tokens[state.token] or state.token == ";" then
      -- No return values.
      return init_ast_node({}, loc, "Return")
   else
      return init_ast_node(parse_expression_list(state), loc, "Return")
   end
end

statements["break"] = function(_, loc)
   return init_ast_node({}, loc, "Break")
end

statements["goto"] = function(state, loc)
   local name = check_name(state)
   skip_token(state)  -- Skip label name.
   return init_ast_node({name}, loc, "Goto")
end

local function parse_expression_statement(state, loc)
   local lhs

   repeat
      local first_token = state.token
      local primary_expression, is_prefix = parse_primary_expression(state)

      if is_prefix and first_token == "(" then
         -- (expr) is invalid.
         parse_error(state)
      end

      if primary_expression.tag == "Call" or primary_expression.tag == "Invoke" then
         if lhs then
            -- This is an assingment, and a call is not a valid lvalue.
            parse_error(state)
         else
            -- It is a call.
            primary_expression.location = loc
            return primary_expression
         end
      end

      -- This is an assignment.
      lhs = lhs or {}
      lhs[#lhs+1] = primary_expression
   until not test_and_skip_token(state, ",")

   local equals_location = location(state)
   check_and_skip_token(state, "=")
   local rhs = parse_expression_list(state)
   return init_ast_node({lhs, rhs, equals_location = equals_location}, loc, "Set")
end

local function parse_statement(state)
   local loc = location(state)
   local statement_parser = statements[state.token]

   if statement_parser then
      skip_token(state)
      return statement_parser(state, loc)
   else
      return parse_expression_statement(state, loc)
   end
end

function parse_block(state, loc)
   local block = {location = loc}

   while not closing_tokens[state.token] do
      local first_token = state.token

      if first_token == ";" then
         skip_token(state)
      else
         first_token = state.token_value or first_token
         local statement = parse_statement(state)
         statement.first_token = first_token
         block[#block+1] = statement

         if first_token == "return" then
            -- "return" must be the last statement.
            -- However, one ";" after it is allowed.
            test_and_skip_token(state, ";")
            
            if not closing_tokens[state.token] then
               parse_error(state, "expected end of block")
            end
         end
      end
   end

   return block
end

local function parse(src)
   local state = new_state(src)
   skip_token(state)
   local ast = parse_block(state)
   check_token(state, "eof")
   return ast, state.comments, state.code_lines
end

return parse
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.globbing"])sources["luacheck.globbing"]=([===[-- <pack luacheck.globbing> --
local fs = require "luacheck.fs"
local utils = require "luacheck.utils"

-- Only ?, *, ** and simple character classes (with ranges and negation) are supported.
-- Hidden files are not treated specially. Special characters can't be escaped.
local globbing = {}

local cur_dir = fs.current_dir()

local function is_regular_path(glob)
   return not glob:find("[*?%[]")
end

local function get_parts(path)
   local parts = {}

   for part in path:gmatch("[^"..utils.dir_sep.."]+") do
      table.insert(parts, part)
   end

   return parts
end

local function glob_pattern_escaper(c)
   return ((c == "*" or c == "?") and "." or "%")..c
end

local function glob_range_escaper(c)
   return c == "-" and c or ("%"..c)
end

local function glob_part_to_pattern(glob_part)
   local buffer = {"^"}
   local i = 1

   while i <= #glob_part do
      local bracketless
      bracketless, i = glob_part:match("([^%[]*)()", i)
      table.insert(buffer, (bracketless:gsub("%p", glob_pattern_escaper)))

      if glob_part:sub(i, i) == "[" then
         table.insert(buffer, "[")
         i = i + 1
         local first_char = glob_part:sub(i, i)

         if first_char == "!" then
            table.insert(buffer, "^")
            i = i + 1
         elseif first_char == "]" then
            table.insert(buffer, "%]")
            i = i + 1
         end

         bracketless, i = glob_part:match("([^%]]*)()", i)

         if bracketless:sub(1, 1) == "-" then
            table.insert(buffer, "%-")
            bracketless = bracketless:sub(2)
         end

         local last_dash = ""

         if bracketless:sub(-1) == "-" then
            last_dash = "-"
            bracketless = bracketless:sub(1, -2)
         end

         table.insert(buffer, (bracketless:gsub("%p", glob_range_escaper)))
         table.insert(buffer, last_dash.."]")
         i = i + 1
      end
   end

   table.insert(buffer, "$")
   return table.concat(buffer)
end

local function part_match(glob_part, path_part)
   return utils.pmatch(path_part, glob_part_to_pattern(glob_part))
end

local function parts_match(glob_parts, glob_i, path_parts, path_i)
   local glob_part = glob_parts[glob_i]

   if not glob_part then
      -- Reached glob end, path matches the glob or its subdirectory.
      -- E.g. path "foo/bar/baz/src.lua" matches glob "foo/*/baz".
      return true
   end

   if glob_part == "**" then
      -- "**" can consume any number of path parts.
      for i = path_i, #path_parts + 1 do
         if parts_match(glob_parts, glob_i + 1, path_parts, i) then
            return true
         end
      end

      return false
   end

   local path_part = path_parts[path_i]
   return path_part and part_match(glob_part, path_part) and parts_match(glob_parts, glob_i + 1, path_parts, path_i + 1)
end

-- Checks if a path matches a globbing pattern.
function globbing.match(glob, path)
   glob = fs.normalize(fs.join(cur_dir, glob))
   path = fs.normalize(fs.join(cur_dir, path))

   if is_regular_path(glob) then
      return fs.is_subpath(glob, path)
   end

   local glob_base, path_base
   glob_base, glob = fs.split_base(glob)
   path_base, path = fs.split_base(path)

   if glob_base ~= path_base then
      return false
   end

   local glob_parts = get_parts(glob)
   local path_parts = get_parts(path)
   return parts_match(glob_parts, 1, path_parts, 1)
end

return globbing
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.lexer"])sources["luacheck.lexer"]=([===[-- <pack luacheck.lexer> --
local utils = require "luacheck.utils"

-- Lexer should support syntax of Lua 5.1, Lua 5.2, Lua 5.3 and LuaJIT(64bit and complex cdata literals).
local lexer = {}

local sbyte = string.byte
local ssub = string.sub
local schar = string.char
local sreverse = string.reverse
local tconcat = table.concat
local mfloor = math.floor

-- No point in inlining these, fetching a constant ~= fetching a local.
local BYTE_0, BYTE_9, BYTE_f, BYTE_F = sbyte("0"), sbyte("9"), sbyte("f"), sbyte("F")
local BYTE_x, BYTE_X, BYTE_i, BYTE_I = sbyte("x"), sbyte("X"), sbyte("i"), sbyte("I")
local BYTE_l, BYTE_L, BYTE_u, BYTE_U = sbyte("l"), sbyte("L"), sbyte("u"), sbyte("U")
local BYTE_e, BYTE_E, BYTE_p, BYTE_P = sbyte("e"), sbyte("E"), sbyte("p"), sbyte("P")
local BYTE_a, BYTE_z, BYTE_A, BYTE_Z = sbyte("a"), sbyte("z"), sbyte("A"), sbyte("Z")
local BYTE_DOT, BYTE_COLON = sbyte("."), sbyte(":")
local BYTE_OBRACK, BYTE_CBRACK = sbyte("["), sbyte("]")
local BYTE_OBRACE, BYTE_CBRACE = sbyte("{"), sbyte("}")
local BYTE_QUOTE, BYTE_DQUOTE = sbyte("'"), sbyte('"')
local BYTE_PLUS, BYTE_DASH, BYTE_LDASH = sbyte("+"), sbyte("-"), sbyte("_")
local BYTE_SLASH, BYTE_BSLASH = sbyte("/"), sbyte("\\")
local BYTE_EQ, BYTE_NE = sbyte("="), sbyte("~")
local BYTE_LT, BYTE_GT = sbyte("<"), sbyte(">")
local BYTE_LF, BYTE_CR = sbyte("\n"), sbyte("\r")
local BYTE_SPACE, BYTE_FF, BYTE_TAB, BYTE_VTAB = sbyte(" "), sbyte("\f"), sbyte("\t"), sbyte("\v")

local function to_hex(b)
   if BYTE_0 <= b and b <= BYTE_9 then
      return b-BYTE_0
   elseif BYTE_a <= b and b <= BYTE_f then
      return 10+b-BYTE_a
   elseif BYTE_A <= b and b <= BYTE_F then
      return 10+b-BYTE_A
   else
      return nil
   end
end

local function to_dec(b)
   if BYTE_0 <= b and b <= BYTE_9 then
      return b-BYTE_0
   else
      return nil
   end
end

local function to_utf(codepoint)
   if codepoint < 0x80 then  -- ASCII?
      return schar(codepoint)
   end

   local buf = {}
   local mfb = 0x3F

   repeat
      buf[#buf+1] = schar(codepoint % 0x40 + 0x80)
      codepoint = mfloor(codepoint / 0x40)
      mfb = mfloor(mfb / 2)
   until codepoint <= mfb

   buf[#buf+1] = schar(0xFE - mfb*2 + codepoint)
   return sreverse(tconcat(buf))
end

local function is_alpha(b)
   return (BYTE_a <= b and b <= BYTE_z) or
      (BYTE_A <= b and b <= BYTE_Z) or b == BYTE_LDASH
end

local function is_newline(b)
   return (b == BYTE_LF) or (b == BYTE_CR)
end

local function is_space(b)
   return (b == BYTE_SPACE) or (b == BYTE_FF) or
      (b == BYTE_TAB) or (b == BYTE_VTAB)
end

local keywords = utils.array_to_set({
   "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in",
   "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"})

local simple_escapes = {
   [sbyte("a")] = sbyte("\a"),
   [sbyte("b")] = sbyte("\b"),
   [sbyte("f")] = sbyte("\f"),
   [sbyte("n")] = sbyte("\n"),
   [sbyte("r")] = sbyte("\r"),
   [sbyte("t")] = sbyte("\t"),
   [sbyte("v")] = sbyte("\v"),
   [BYTE_BSLASH] = BYTE_BSLASH,
   [BYTE_QUOTE] = BYTE_QUOTE,
   [BYTE_DQUOTE] = BYTE_DQUOTE
}

local function next_byte(state, inc)
   inc = inc or 1
   state.offset = state.offset+inc
   return sbyte(state.src, state.offset)
end

-- Skipping helpers.
-- Take the current character, skip something, return next character.

local function skip_newline(state, newline)
   local b = next_byte(state)

   if b ~= newline and is_newline(b) then
      b = next_byte(state)
   end

   state.line = state.line+1
   state.line_offset = state.offset
   return b
end

local function skip_till_newline(state, b)
   while not is_newline(b) and b ~= nil do 
      b = next_byte(state)
   end

   return b
end

local function skip_space(state, b)
   while is_space(b) or is_newline(b) do
      if is_newline(b) then
         b = skip_newline(state, b)
      else
         b = next_byte(state)
      end
   end

   return b
end

-- Skips "[=*" or "]=*". Returns next character and number of "="s.
local function skip_long_bracket(state)
   local start = state.offset
   local b = next_byte(state)

   while b == BYTE_EQ do
      b = next_byte(state)
   end

   return b, state.offset-start-1
end

-- Token handlers.

-- Called after the opening "[=*" has been skipped.
-- Takes number of "=" in the opening bracket and token type(comment or string).
local function lex_long_string(state, opening_long_bracket, token)
   local b = next_byte(state)

   if is_newline(b) then
      b = skip_newline(state, b)
   end

   local lines = {}
   local line_start = state.offset

   while true do
      if is_newline(b) then
         -- Add the finished line.
         lines[#lines+1] = ssub(state.src, line_start, state.offset-1)

         b = skip_newline(state, b)
         line_start = state.offset
      elseif b == BYTE_CBRACK then
         local long_bracket
         b, long_bracket = skip_long_bracket(state)

         if b == BYTE_CBRACK and long_bracket == opening_long_bracket then
            break
         end
      elseif b == nil then
         return nil, token == "string" and "unfinished long string" or "unfinished long comment"
      else
         b = next_byte(state)
      end
   end

   -- Add last line. 
   lines[#lines+1] = ssub(state.src, line_start, state.offset-opening_long_bracket-2)
   next_byte(state)
   return token, tconcat(lines, "\n")
end

local function lex_short_string(state, quote)
   local b = next_byte(state)
   local chunks  -- Buffer is only required when there are escape sequences.
   local chunk_start = state.offset

   while b ~= quote do
      if b == BYTE_BSLASH then
         -- Escape sequence.

         if not chunks then
            -- This is the first escape sequence, init buffer.
            chunks = {}
         end

         -- Put previous chunk into buffer.
         if chunk_start ~= state.offset then
            chunks[#chunks+1] = ssub(state.src, chunk_start, state.offset-1)
         end

         b = next_byte(state)

         -- The final string escape sequence evaluates to.
         local s

         local escape_byte = simple_escapes[b]

         if escape_byte then  -- Is it a simple escape sequence?
            b = next_byte(state)
            s = schar(escape_byte)
         elseif is_newline(b) then
            b = skip_newline(state, b)
            s = "\n"
         elseif b == BYTE_x then
            -- Hexadecimal escape.
            b = next_byte(state)  -- Skip "x".
            -- Exactly two hexadecimal digits.
            local c1, c2

            if b then
               c1 = to_hex(b)
            end

            if not c1 then
               return nil, "invalid hexadecimal escape sequence", -2
            end

            b = next_byte(state)

            if b then
               c2 = to_hex(b)
            end

            if not c2 then
               return nil, "invalid hexadecimal escape sequence", -3
            end

            b = next_byte(state)
            s = schar(c1*16 + c2)
         elseif b == BYTE_u then
            b = next_byte(state)  -- Skip "u".

            if b ~= BYTE_OBRACE then
               return nil, "invalid UTF-8 escape sequence", -2
            end

            b = next_byte(state)  -- Skip "{".

            local codepoint = to_hex(b)  -- There should be at least one digit.

            if not codepoint then
               return nil, "invalid UTF-8 escape sequence", -3
            end

            local hexdigits = 0

            while true do
               b = next_byte(state)
               local hex

               if b then
                  hex = to_hex(b)
               end

               if hex then
                  hexdigits = hexdigits + 1
                  codepoint = codepoint*16 + hex

                  if codepoint > 0x10FFFF then
                     -- UTF-8 value too large.
                     return nil, "invalid UTF-8 escape sequence", -hexdigits-3
                  end
               else
                  break
               end
            end

            if b ~= BYTE_CBRACE then
               return nil, "invalid UTF-8 escape sequence", -hexdigits-4
            end

            b = next_byte(state)  -- Skip "}".
            s = to_utf(codepoint)
         elseif b == BYTE_z then
            -- Zap following span of spaces.
            b = skip_space(state, next_byte(state))
         else
            -- Must be a decimal escape.
            local cb = to_dec(b)

            if not cb then
               return nil, "invalid escape sequence", -1
            end

            -- Up to three decimal digits.
            b = next_byte(state)

            if b then
               local c2 = to_dec(b)

               if c2 then
                  cb = 10*cb + c2
                  b = next_byte(state)

                  if b then
                     local c3 = to_dec(b)

                     if c3 then
                        cb = 10*cb + c3

                        if cb > 255 then
                           return nil, "invalid decimal escape sequence", -3
                        end

                        b = next_byte(state)
                     end
                  end
               end
            end

            s = schar(cb)
         end

         if s then
            chunks[#chunks+1] = s
         end

         -- Next chunk starts after escape sequence.
         chunk_start = state.offset
      elseif b == nil or is_newline(b) then
         return nil, "unfinished string"
      else
         b = next_byte(state)
      end
   end

   -- Offset now points at the closing quote.
   local string_value

   if chunks then
      -- Put last chunk into buffer.
      if chunk_start ~= state.offset then
         chunks[#chunks+1] = ssub(state.src, chunk_start, state.offset-1)
      end

      string_value = tconcat(chunks)
   else
      -- There were no escape sequences.
      string_value = ssub(state.src, chunk_start, state.offset-1)
   end

   next_byte(state)  -- Skip the closing quote.
   return "string", string_value
end

-- Payload for a number is simply a substring.
-- Luacheck is supposed to be forward-compatible with Lua 5.3 and LuaJIT syntax, so
--    parsing it into actual number may be problematic.
-- It is not needed currently anyway as Luacheck does not do static evaluation yet.
local function lex_number(state, b)
   local start = state.offset

   local exp_lower, exp_upper = BYTE_e, BYTE_E
   local is_digit = to_dec
   local has_digits = false
   local is_float = false

   if b == BYTE_0 then
      b = next_byte(state)

      if b == BYTE_x or b == BYTE_X then
         exp_lower, exp_upper = BYTE_p, BYTE_P
         is_digit = to_hex
         b = next_byte(state)
      else
         has_digits = true
      end
   end

   while b ~= nil and is_digit(b) do
      b = next_byte(state)
      has_digits = true
   end

   if b == BYTE_DOT then
      -- Fractional part.
      is_float = true
      b = next_byte(state)  -- Skip dot.

      while b ~= nil and is_digit(b) do
         b = next_byte(state)
         has_digits = true
      end
   end

   if b == exp_lower or b == exp_upper then
      -- Exponent part.
      is_float = true
      b = next_byte(state)

      -- Skip optional sign.
      if b == BYTE_PLUS or b == BYTE_DASH then
         b = next_byte(state)
      end

      -- Exponent consists of one or more decimal digits.
      if b == nil or not to_dec(b) then
         return nil, "malformed number"
      end

      repeat
         b = next_byte(state)
      until b == nil or not to_dec(b)
   end

   if not has_digits then
      return nil, "malformed number"
   end

   -- Is it cdata literal?
   if b == BYTE_i or b == BYTE_I then
      -- It is complex literal. Skip "i" or "I".
      next_byte(state)
   else
      -- uint64_t and int64_t literals can not be fractional.
      if not is_float then
         if b == BYTE_u or b == BYTE_U then
            -- It may be uint64_t literal.
            local b1, b2 = sbyte(state.src, state.offset+1, state.offset+2)

            if (b1 == BYTE_l or b1 == BYTE_L) and (b2 == BYTE_l or b2 == BYTE_L) then
               -- It is uint64_t literal.
               next_byte(state, 3)
            end
         elseif b == BYTE_l or b == BYTE_L then
            -- It may be uint64_t or int64_t literal.
            local b1, b2 = sbyte(state.src, state.offset+1, state.offset+2)

            if b1 == BYTE_l or b1 == BYTE_L then
               if b2 == BYTE_u or b2 == BYTE_U then
                  -- It is uint64_t literal.
                  next_byte(state, 3)
               else
                  -- It is int64_t literal.
                  next_byte(state, 2)
               end
            end
         end
      end
   end

   return "number", ssub(state.src, start, state.offset-1)
end

local function lex_ident(state)
   local start = state.offset
   local b = next_byte(state)

   while (b ~= nil) and (is_alpha(b) or to_dec(b)) do
      b = next_byte(state)
   end

   local ident = ssub(state.src, start, state.offset-1)

   if keywords[ident] then
      return ident
   else
      return "name", ident
   end
end

local function lex_dash(state)
   local b = next_byte(state)

   -- Is it "-" or comment?
   if b ~= BYTE_DASH then
      return "-"
   else
      -- It is a comment.
      b = next_byte(state)
      local start = state.offset

      -- Is it a long comment?
      if b == BYTE_OBRACK then
         local long_bracket
         b, long_bracket = skip_long_bracket(state)

         if b == BYTE_OBRACK then
            return lex_long_string(state, long_bracket, "comment")
         end
      end

      -- Short comment.
      b = skip_till_newline(state, b)
      local comment_value = ssub(state.src, start, state.offset-1)
      skip_newline(state, b)
      return "comment", comment_value
   end
end

local function lex_bracket(state)
   -- Is it "[" or long string?
   local b, long_bracket = skip_long_bracket(state)

   if b == BYTE_OBRACK then
      return lex_long_string(state, long_bracket, "string")
   elseif long_bracket == 0 then
      return "["
   else
      return nil, "invalid long string delimiter"
   end
end

local function lex_eq(state)
   local b = next_byte(state)

   if b == BYTE_EQ then
      next_byte(state)
      return "=="
   else
      return "="
   end
end

local function lex_lt(state)
   local b = next_byte(state)

   if b == BYTE_EQ then
      next_byte(state)
      return "<="
   elseif b == BYTE_LT then
      next_byte(state)
      return "<<"
   else
      return "<"
   end
end

local function lex_gt(state)
   local b = next_byte(state)

   if b == BYTE_EQ then
      next_byte(state)
      return ">="
   elseif b == BYTE_GT then
      next_byte(state)
      return ">>"
   else
      return ">"
   end
end

local function lex_div(state)
   local b = next_byte(state)

   if b == BYTE_SLASH then
      next_byte(state)
      return "//"
   else
      return "/"
   end
end

local function lex_ne(state)
   local b = next_byte(state)

   if b == BYTE_EQ then
      next_byte(state)
      return "~="
   else
      return "~"
   end
end

local function lex_colon(state)
   local b = next_byte(state)

   if b == BYTE_COLON then
      next_byte(state)
      return "::"
   else
      return ":"
   end
end

local function lex_dot(state)
   local b = next_byte(state)

   if b == BYTE_DOT then
      b = next_byte(state)

      if b == BYTE_DOT then
         next_byte(state)
         return "...", "..."
      else
         return ".."
      end
   elseif to_dec(b) then
      -- Backtrack to dot.
      return lex_number(state, next_byte(state, -1))
   else
      return "."
   end
end

local function lex_any(state, b)
   next_byte(state)
   return schar(b)
end

-- Maps first bytes of tokens to functions that handle them.
-- Each handler takes the first byte as an argument.
-- Each handler stops at the character after the token and returns the token and,
--    optionally, a value associated with the token.
-- On error handler returns nil, error message and, optionally, start of reported location as negative offset.
local byte_handlers = {
   [BYTE_DOT] = lex_dot,
   [BYTE_COLON] = lex_colon,
   [BYTE_OBRACK] = lex_bracket,
   [BYTE_QUOTE] = lex_short_string,
   [BYTE_DQUOTE] = lex_short_string,
   [BYTE_DASH] = lex_dash,
   [BYTE_SLASH] = lex_div,
   [BYTE_EQ] = lex_eq,
   [BYTE_NE] = lex_ne,
   [BYTE_LT] = lex_lt,
   [BYTE_GT] = lex_gt,
   [BYTE_LDASH] = lex_ident
}

for b=BYTE_0, BYTE_9 do
   byte_handlers[b] = lex_number
end

for b=BYTE_a, BYTE_z do
   byte_handlers[b] = lex_ident
end

for b=BYTE_A, BYTE_Z do
   byte_handlers[b] = lex_ident
end

local function decimal_escaper(char)
   return "\\" .. tostring(sbyte(char))
end

-- Returns quoted printable representation of s.
function lexer.quote(s)
   return "'" .. s:gsub("[^\32-\126]", decimal_escaper) .. "'"
end

-- Creates and returns lexer state for source.
function lexer.new_state(src)
   local state = {
      src = src,
      line = 1,
      line_offset = 1,
      offset = 1
   }

   if ssub(src, 1, 2) == "#!" then
      -- Skip shebang.
      skip_newline(state, skip_till_newline(state, next_byte(state, 2)))
   end

   return state
end

function lexer.syntax_error(location, end_column, msg)
   error({
      line = location.line,
      column = location.column,
      end_column = end_column,
      msg = msg})
end

-- Looks for next token starting from state.line, state.line_offset, state.offset.
-- Returns next token, its value and its location (line, column, offset).
-- Sets state.line, state.line_offset, state.offset to token end location + 1.
-- On error returns nil, error message, error location (line, column, offset), error end column.
function lexer.next_token(state)
   local b = skip_space(state, sbyte(state.src, state.offset))

   -- Save location of token start.
   local token_line = state.line
   local token_column = state.offset - state.line_offset + 1
   local token_offset = state.offset

   local token, token_value, err_offset, err_end_column

   if b == nil then
      token = "eof"
   else
      token, token_value, err_offset = (byte_handlers[b] or lex_any)(state, b)
   end

   if err_offset then
      local token_body = ssub(state.src, state.offset + err_offset, state.offset)
      token_value = token_value .. " " .. lexer.quote(token_body)
      token_line = state.line
      token_column = state.offset - state.line_offset + 1 + err_offset
      token_offset = state.offset + err_offset
      err_end_column = token_column + #token_body - 1
   end

   return token, token_value, token_line, token_column, token_offset, err_end_column or token_column
end

return lexer
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.fs"])sources["luacheck.fs"]=([===[-- <pack luacheck.fs> --
local fs = {}

local utils = require "luacheck.utils"

fs.has_lfs, fs.lfs = pcall(require, "lfs")

local function ensure_dir_sep(path)
   if path:sub(-1) ~= utils.dir_sep then
      return path .. utils.dir_sep
   end

   return path
end

if utils.is_windows then
   function fs.split_base(path)
      if path:match("^%a:\\") then
         return path:sub(1, 3), path:sub(4)
      else
         -- Disregard UNC stuff for now.
         return "", path
      end
   end
else
   function fs.split_base(path)
      if path:match("^/") then
         if path:match("^//") then
            return "//", path:sub(3)
         else
            return "/", path:sub(2)
         end
      else
         return "", path
      end
   end
end

local function is_absolute(path)
   return fs.split_base(path) ~= ""
end

function fs.normalize(path)
   local base, rest = fs.split_base(path)
   rest = rest:gsub("[/\\]", utils.dir_sep)

   local parts = {}

   for part in rest:gmatch("[^"..utils.dir_sep.."]+") do
      if part ~= "." then
         if part == ".." and #parts > 0 and parts[#parts] ~= ".." then
            parts[#parts] = nil
         else
            parts[#parts + 1] = part
         end
      end
   end

   if base == "" and #parts == 0 then
      return "."
   else
      return base..table.concat(parts, utils.dir_sep)
   end
end

function fs.join(base, path)
   if base == "" or is_absolute(path) then
      return path
   else
      return ensure_dir_sep(base)..path
   end
end

function fs.is_subpath(path, subpath)
   local base1, rest1 = fs.split_base(path)
   local base2, rest2 = fs.split_base(subpath)

   if base1 ~= base2 then
      return false
   end

   if rest2:sub(1, #rest1) ~= rest1 then
      return false
   end

   return rest1 == rest2 or rest2:sub(#rest1 + 1, #rest1 + 1) == utils.dir_sep
end

-- Searches for file starting from path, going up until the file
-- is found or root directory is reached.
-- Path must be absolute.
-- Returns absolute and relative paths to directory containing file or nil.
function fs.find_file(path, file)
   if is_absolute(file) then
      return fs.is_file(file) and path, ""
   end

   path = fs.normalize(path)
   local base, rest = fs.split_base(path)
   local rel_path = ""

   while true do
      if fs.is_file(fs.join(base..rest, file)) then
         return base..rest, rel_path
      elseif rest == "" then
         break
      end

      rest = rest:match("^(.*)"..utils.dir_sep..".*$") or ""
      rel_path = rel_path..".."..utils.dir_sep
   end
end

if not fs.has_lfs then
   function fs.is_dir(_)
      return false
   end

   function fs.is_file(path)
      local fh = io.open(path)

      if fh then
         fh:close()
         return true
      else
         return false
      end
   end

   function fs.extract_files(_, _)
      return {}
   end

   function fs.mtime(_)
      return 0
   end

   local pwd_command = utils.is_windows and "cd" or "pwd"

   function fs.current_dir()
      local fh = io.popen(pwd_command)
      local current_dir = fh:read("*a")
      fh:close()
      -- Remove extra newline at the end.
      return ensure_dir_sep(current_dir:sub(1, -2))
   end

   return fs
end

-- Returns whether path points to a directory. 
function fs.is_dir(path)
   return fs.lfs.attributes(path, "mode") == "directory"
end

-- Returns whether path points to a file. 
function fs.is_file(path)
   return fs.lfs.attributes(path, "mode") == "file"
end

-- Returns list of all files in directory matching pattern. 
function fs.extract_files(dir_path, pattern)
   local res = {}

   local function scan(dir)
      for path in fs.lfs.dir(dir) do
         if path ~= "." and path ~= ".." then
            local full_path = dir .. utils.dir_sep .. path

            if fs.is_dir(full_path) then
               scan(full_path)
            elseif path:match(pattern) and fs.is_file(full_path) then
               table.insert(res, full_path)
            end
         end
      end
   end

   scan(dir_path)
   table.sort(res)
   return res
end

-- Returns modification time for a file. 
function fs.mtime(path)
   return fs.lfs.attributes(path, "modification")
end

-- Returns absolute path to current working directory.
function fs.current_dir()
   return ensure_dir_sep(assert(fs.lfs.currentdir()))
end

return fs
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.expand_rockspec"])sources["luacheck.expand_rockspec"]=([===[-- <pack luacheck.expand_rockspec> --
local utils = require "luacheck.utils"

local function extract_lua_files(rockspec)
   local res = {}
   local build = rockspec.build

   local function scan(t)
      for _, file in pairs(t) do
         if type(file) == "string" and file:sub(-#".lua") == ".lua" then
            table.insert(res, file)
         end
      end
   end

   if build.type == "builtin" then
      scan(build.modules)
   end

   if build.install then
      if build.install.lua then
         scan(build.install.lua)
      end

      if build.install.bin then
         scan(build.install.bin)
      end
   end

   table.sort(res)
   return res
end

-- Receives a name of a rockspec, returns list of related .lua files or nil and "syntax" or "error". 
local function expand_rockspec(file)
   local rockspec, err = utils.load_config(file)

   if not rockspec then
      return nil, err
   end

   local ok, files = pcall(extract_lua_files, rockspec)

   if not ok then
      return nil, "syntax"
   end

   return files
end

return expand_rockspec
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.multithreading"])sources["luacheck.multithreading"]=([===[-- <pack luacheck.multithreading> --
local utils = require "luacheck.utils"

local multithreading = {}

local ok, lanes = pcall(require, "lanes")
ok = ok and pcall(lanes.configure)
multithreading.has_lanes = ok
multithreading.lanes = lanes

if not ok then
   return multithreading
end

-- Worker thread reads pairs {outkey, arg} from inkey channel of linda,
-- applies func to arg and sends result to outkey channel of linda
-- until arg is nil.
local function worker_task(linda, inkey, func)
   while true do
      local _, pair = linda:receive(nil, inkey)
      local outkey, arg = pair[1], pair[2]

      if arg == nil then
         return true
      end

      linda:send(nil, outkey, func(arg))
   end
end

local worker_gen = lanes.gen("*", worker_task)

-- Maps func over array, performing at most jobs calls in parallel.
function multithreading.pmap(func, array, jobs)
   jobs = math.min(jobs, #array)

   if jobs < 2 then
      return utils.map(func, array)
   end

   local workers = {}
   local linda = lanes.linda()

   for i = 1, jobs do
      workers[i] = worker_gen(linda, 0, func)
   end

   for i, item in ipairs(array) do
      linda:send(nil, 0, {i, item})
   end

   for _ = 1, jobs do
      linda:send(nil, 0, {})
   end

   local results = {}

   for i in ipairs(array) do
      local _, result = linda:receive(nil, i)
      results[i] = result
   end

   for _, worker in ipairs(workers) do
      assert(worker:join())
   end

   return results
end

return multithreading
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.stds"])sources["luacheck.stds"]=([===[-- <pack luacheck.stds> --
local utils = require "luacheck.utils"

local stds = {}

stds.busted = {
   "describe", "insulate", "expose", "it", "pending", "before_each", "after_each",
   "lazy_setup", "lazy_teardown", "strict_setup", "strict_teardown", "setup", "teardown",
   "context", "spec", "test", "assert", "spy", "mock", "stub", "finally"}

stds.lua51 = {
   _G = true, package = true, "_VERSION", "arg", "assert", "collectgarbage", "coroutine",
   "debug", "dofile", "error", "gcinfo", "getfenv", "getmetatable", "io", "ipairs", "load",
   "loadfile", "loadstring", "math", "module", "newproxy", "next", "os", "pairs", "pcall",
   "print", "rawequal", "rawget", "rawset", "require", "select", "setfenv", "setmetatable",
   "string", "table", "tonumber", "tostring", "type", "unpack", "xpcall"}

stds.lua52 = {
   _ENV = true, _G = true, package = true, "_VERSION", "arg", "assert", "bit32",
   "collectgarbage", "coroutine", "debug", "dofile", "error", "getmetatable", "io", "ipairs",
   "load", "loadfile", "math", "next", "os", "pairs", "pcall", "print", "rawequal", "rawget",
   "rawlen", "rawset", "require", "select", "setmetatable", "string", "table", "tonumber",
   "tostring", "type", "xpcall"}

stds.lua52c = {
   _ENV = true, _G = true, package = true, "_VERSION", "arg", "assert", "bit32",
   "collectgarbage", "coroutine", "debug", "dofile", "error", "getmetatable", "io", "ipairs",
   "load", "loadfile", "loadstring", "math", "module", "next", "os", "pairs", "pcall", "print",
   "rawequal", "rawget", "rawlen", "rawset", "require", "select", "setmetatable", "string",
   "table", "tonumber", "tostring", "type", "unpack", "xpcall"}

stds.lua53 = {
   _ENV = true, _G = true, package = true, "_VERSION", "arg", "assert", "collectgarbage",
   "coroutine", "debug", "dofile", "error", "getmetatable", "io", "ipairs", "load", "loadfile",
   "math", "next", "os", "pairs", "pcall", "print", "rawequal", "rawget", "rawlen", "rawset",
   "require", "select", "setmetatable", "string", "table", "tonumber", "tostring", "type",
   "utf8", "xpcall"}

stds.lua53c = {
   _ENV = true, _G = true, package = true, "_VERSION", "arg", "assert", "bit32",
   "collectgarbage", "coroutine", "debug", "dofile", "error", "getmetatable", "io", "ipairs",
   "load", "loadfile", "math", "next", "os", "pairs", "pcall", "print", "rawequal", "rawget",
   "rawlen", "rawset", "require", "select", "setmetatable", "string", "table", "tonumber",
   "tostring", "type", "utf8", "xpcall"}

stds.luajit = {
   _G = true, package = true, "_VERSION", "arg", "assert", "bit", "collectgarbage", "coroutine",
   "debug", "dofile", "error", "gcinfo", "getfenv", "getmetatable", "io", "ipairs", "jit",
   "load", "loadfile", "loadstring", "math", "module", "newproxy", "next", "os", "pairs",
   "pcall", "print", "rawequal", "rawget", "rawset", "require", "select", "setfenv",
   "setmetatable", "string", "table", "tonumber", "tostring", "type", "unpack", "xpcall"}

local min = {_G = true, package = true}
local std_sets = {}

for name, std in pairs(stds) do
   std_sets[name] = utils.array_to_set(std)
end

for global in pairs(std_sets.lua51) do
   if std_sets.lua52[global] and std_sets.lua53[global] and std_sets.luajit[global] then
      table.insert(min, global)
   end
end

stds.min = min
stds.max = utils.concat_arrays {stds.lua51, stds.lua52, stds.lua53, stds.luajit}
stds.max._G = true
stds.max._ENV = true
stds.max.package = true

stds._G = {}

for global in pairs(_G) do
   if global == "_G" or global == "package" then
      stds._G[global] = true
   else
      table.insert(stds._G, global)
   end
end

local function has_env()
   local _ENV = {} -- luacheck: ignore
   return not _G
end

if has_env() then
   stds._G._ENV = true
end

stds.none = {}

return stds
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.filter"])sources["luacheck.filter"]=([===[-- <pack luacheck.filter> --
local options = require "luacheck.options"
local core_utils = require "luacheck.core_utils"
local utils = require "luacheck.utils"

local filter = {}

-- Returns array of normalized options, one for each file.
local function get_normalized_opts(report, opts)
   local res = {}

   for i in ipairs(report) do
      local option_stack = {opts}

      if opts and opts[i] then
         option_stack[2] = opts[i]

         for _, nested_opts in ipairs(opts[i]) do
            table.insert(option_stack, nested_opts)
         end
      end

      res[i] = options.normalize(option_stack)
   end

   return res
end

-- A global is implicitly defined in a file if opts.allow_defined == true and it is set anywhere in the file,
--    or opts.allow_defined_top == true and it is set in the top level function scope.
-- By default, accessing and setting globals in a file is allowed for explicitly defined globals (standard and custom)
--    for that file and implicitly defined globals from that file and all other files except modules (files with opts.module == true).
-- Accessing other globals results in "accessing undefined variable" warning.
-- Setting other globals results in "setting non-standard global variable" warning.
-- Unused implicitly defined global results in "unused global variable" warning.
-- For modules, accessing globals uses same rules as normal files, however, setting globals is only allowed for implicitly defined globals
--    from the module.
-- Setting a global not defined in the module results in "setting non-module global variable" warning.

-- Extracts sets of defined, exported and used globals from a file report.
local function get_defined_and_used_globals(file_report, opts)
   local defined, globally_defined, used = {}, {}, {}

   for _, warning in ipairs(file_report) do
      if warning.code:match("11.") then
         if warning.code == "111" then
            if (opts.inline and warning.definition) or core_utils.is_definition(opts, warning) then
               if (opts.inline and warning.in_module) or opts.module then
                  defined[warning.name] = true
               else
                  globally_defined[warning.name] = true
               end
            end
         else
            used[warning.name] = true
         end
      end
   end

   return defined, globally_defined, used
end


-- Returns {globally_defined = globally_defined, globally_used = globally_used, locally_defined = locally_defined},
--    where `globally_defined` is set of globals defined across all files except modules,
--    where `globally_used` is set of globals defined across all files except modules,
--    where `locally_defined` is an array of sets of globals defined per file.
local function get_implicit_defs_info(report, opts)
   local info = {
      globally_defined = {},
      globally_used = {},
      locally_defined = {}
   }

   for i, file_report in ipairs(report) do
      local defined, globally_defined, used = get_defined_and_used_globals(file_report, opts[i])
      utils.update(info.globally_defined, globally_defined)
      utils.update(info.globally_used, used)
      info.locally_defined[i] = defined
   end

   return info
end

-- Returns file report clear of implicit definitions.
local function filter_implicit_defs_file(file_report, opts, globally_defined, globally_used, locally_defined)
   local res = {}

   for _, warning in ipairs(file_report) do
      if warning.code:match("11.") then
         if warning.code == "111" then
            if (opts.inline and warning.in_module) or opts.module then
               if not locally_defined[warning.name] then
                  warning.module = true
                  table.insert(res, warning)
               end
            else
               if (opts.inline and  warning.definition) or core_utils.is_definition(opts, warning) then
                  if not globally_used[warning.name] then
                     warning.code = "131"
                     warning.top = nil
                     table.insert(res, warning)
                  end
               else
                  if not globally_defined[warning.name] then
                     table.insert(res, warning)
                  end
               end
            end
         else
            if not globally_defined[warning.name] and not locally_defined[warning.name] then
               table.insert(res, warning)
            end
         end
      else
         table.insert(res, warning)
      end
   end

   return res
end

-- Returns report clear of implicit definitions.
local function filter_implicit_defs(report, opts)
   local res = {}
   local info = get_implicit_defs_info(report, opts)

   for i, file_report in ipairs(report) do
      if not file_report.fatal then
         res[i] = filter_implicit_defs_file(file_report, opts[i], info.globally_defined, info.globally_used, info.locally_defined[i])
      else
         res[i] = file_report
      end
   end

   return res
end

-- Returns two optional booleans indicating if warning matches pattern by code and name.
local function match(warning, pattern)
   local matches_code, matches_name
   local code_pattern, name_pattern = pattern[1], pattern[2]

   if code_pattern then
      matches_code = utils.pmatch(warning.code, code_pattern)
   end

   if name_pattern then
      if warning.code:match("5..") then
         -- Statement-related warnings can't match by name.
         matches_name = false
      else
         matches_name = utils.pmatch(warning.name, name_pattern)
      end
   end

   return matches_code, matches_name
end

local function is_enabled(rules, warning)
   -- A warning is enabled when its code and name are enabled.
   local enabled_code, enabled_name = false, false

   for _, rule in ipairs(rules) do
      local matches_one = false

      for _, pattern in ipairs(rule[1]) do
         local matches_code, matches_name = match(warning, pattern)

         -- If a factor is enabled, warning can't be disable by it.
         if enabled_code then
            matches_code = rule[2] ~= "disable"
         end

         if enabled_name then
            matches_code = rule[2] ~= "disable"
         end

         if (matches_code and matches_name ~= false) or
               (matches_name and matches_code ~= false) then
            matches_one = true
         end

         if rule[2] == "enable" then
            if matches_code then
               enabled_code = true
            end

            if matches_name then
               enabled_name = true
            end

            if enabled_code and enabled_name then
               -- Enable as matching to some `enable` pattern by code and to other by name.
               return true
            end
         elseif rule[2] == "disable" then
            if matches_one then
               -- Disable as matching to `disable` pattern.
               return false
            end
         end
      end

      if rule[2] == "only" and not matches_one then
         -- Disable as not matching to any of `only` patterns.
         return false
      end
   end

   -- Enable by default.
   return true
end

function filter.filters(opts, warning)
   if warning.code:match("[234]..") and warning.name == "_" then
      return true
   end

   if warning.code:match("11.") and not warning.module and opts.globals[warning.name] then
      return true
   end

   if warning.secondary and not opts.unused_secondaries then
      return true
   end

   if warning.self and not opts.self then
      return true
   end

   return not is_enabled(opts.rules, warning)
end

local function filter_file_report(report, opts)
   local res = {}

   for _, event in ipairs(report) do
      if ((opts.inline and event.read_only) or event.code:match("11[12]")
            and not event.module and opts.read_globals[event.name]) and not (
               (opts.inline and event.global) or (opts.globals[event.name] and not opts.read_globals[event.name])) then
         event.code = "12" .. event.code:sub(3, 3)
      end

      if event.code == "011" or (event.code:match("02.") and opts.inline) or (event.code:sub(1, 1) ~= "0" and (not event.filtered and
            not event["filtered_" .. event.code] or not opts.inline) and not filter.filters(opts, event)) then
         table.insert(res, event)
      end
   end

   return res
end

-- Assumes `opts` are normalized. 
local function filter_report(report, opts)
   local res = {}

   for i, file_report in ipairs(report) do
      if not file_report.fatal then
         res[i] = filter_file_report(file_report, opts[i])
      else
         res[i] = file_report
      end
   end

   return res
end

-- Removes warnings from report that do not match options. 
-- `opts[i]`, if present, is used as options when processing `report[i]`
-- together with options in its array part. 
function filter.filter(report, opts)
   opts = get_normalized_opts(report, opts)
   report = filter_implicit_defs(report, opts)
   return filter_report(report, opts)
end

return filter
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.main"])sources["luacheck.main"]=([===[-- <pack luacheck.main> --
local luacheck = require "luacheck"
local argparse = require "luacheck.argparse"
local config = require "luacheck.config"
local options = require "luacheck.options"
local expand_rockspec = require "luacheck.expand_rockspec"
local multithreading = require "luacheck.multithreading"
local cache = require "luacheck.cache"
local format = require "luacheck.format"
local version = require "luacheck.version"
local fs = require "luacheck.fs"
local globbing = require "luacheck.globbing"
local utils = require "luacheck.utils"

local function critical(msg)
   io.stderr:write("Critical error: "..msg.."\n")
   os.exit(3)
end

local function global_error_handler(err)
   if type(err) == "table" and err.pattern then
      critical("Invalid pattern '" .. err.pattern .. "'")
   else
      critical(debug.traceback(
         ("Luacheck %s bug (please report at github.com/mpeterv/luacheck/issues):\n%s"):format(luacheck._VERSION, err), 2))
   end
end

local function main()
   local default_cache_path = ".luacheckcache"

   local function get_parser()
      local parser = argparse("luacheck", "luacheck " .. luacheck._VERSION .. ", a simple static analyzer for Lua.", [[
Links:

   Luacheck on GitHub: https://github.com/mpeterv/luacheck
   Luacheck documentation: http://luacheck.readthedocs.org]])

      parser:argument "files"
         :description (fs.has_lfs and [[List of files, directories and rockspecs to check.
Pass "-" to check stdin.]] or [[List of files and rockspecs to check.
Pass "-" to check stdin.]])
         :args "+"
         :argname "<file>"

      parser:flag("-g --no-global", [[Filter out warnings related to global variables.
Equivalent to --ignore 1.]])
      parser:flag("-u --no-unused", [[Filter out warnings related to unused variables
and values. Equivalent to --ignore [23].]])
      parser:flag("-r --no-redefined", [[Filter out warnings related to redefined variables.
Equivalent to --ignore 4.]])

      parser:flag("-a --no-unused-args", [[Filter out warnings related to unused arguments and
loop variables. Equivalent to --ignore 21[23].]])
      parser:flag("-s --no-unused-secondaries", [[Filter out warnings related to unused variables set
together with used ones.]])
      parser:flag("--no-self", "Filter out warnings related to implicit self argument.")

      parser:option("--std", [[Set standard globals. <std> can be one of:
   _G (default) - globals of the current Lua
      interpreter;
   lua51 - globals of Lua 5.1;
   lua52 - globals of Lua 5.2;
   lua52c - globals of Lua 5.2 with LUA_COMPAT_ALL;
   lua53 - globals of Lua 5.3;
   lua53c - globals of Lua 5.3 with LUA_COMPAT_5_2;
   luajit - globals of LuaJIT 2.0;
   min - intersection of globals of Lua 5.1, Lua 5.2,
      Lua 5.3 and LuaJIT 2.0;
   max - union of globals of Lua 5.1, Lua 5.2, Lua 5.3
      and LuaJIT 2.0;
   busted - globals added by Busted 2.0;
   none - no standard globals.

   Sets can be combined using "+".]])
      parser:option("--globals", "Add custom globals on top of standard ones.")
         :args "*"
         :count "*"
         :argname "<global>"
      parser:option("--read-globals", "Add read-only globals.")
         :args "*"
         :count "*"
         :argname "<global>"
      parser:option("--new-globals", [[Set custom globals. Removes custom globals added
previously.]])
         :args "*"
         :count "*"
         :argname "<global>"
      parser:option("--new-read-globals", [[Set read-only globals. Removes read-only globals added
previously.]])
         :args "*"
         :count "*"
         :argname "<global>"
      parser:flag("-c --compat", "Equivalent to --std max.")
      parser:flag("-d --allow-defined", "Allow defining globals implicitly by setting them.")
      parser:flag("-t --allow-defined-top", [[Allow defining globals implicitly by setting them in
the top level scope.]])
      parser:flag("-m --module", [[Limit visibility of implicitly defined globals to
their files.]])

      parser:option("--ignore -i", [[Filter out warnings matching these patterns.
If a pattern contains slash, part before slash matches
warning code and part after it matches name of related
variable. Otherwise, if the pattern contains letters
or underscore, it matches name of related variable.
Otherwise, the pattern matches warning code.]])
         :args "+"
         :count "*"
         :argname "<patt>"
      parser:option("--enable -e", "Do not filter out warnings matching these patterns.")
         :args "+"
         :count "*"
         :argname "<patt>"
      parser:option("--only -o", "Filter out warnings not matching these patterns.")
         :args "+"
         :count "*"
         :argname "<patt>"

      parser:flag("--no-inline", "Disable inline options.")

      parser:mutex(
         parser:option("--config", "Path to configuration file. (default: "..config.default_path..")"),
         parser:flag("--no-config", "Do not look up configuration file.")
      )

      parser:option("--filename", [[Use another filename in output and for selecting
configuration overrides.]])

      parser:option("--exclude-files", "Do not check files matching these globbing patterns.")
         :args "+"
         :count "*"
         :argname "<glob>"
      parser:option("--include-files", [[Do not check files not matching these globbing
patterns.]])
         :args "+"
         :count "*"
         :argname "<glob>"

      if fs.has_lfs then
         parser:mutex(
            parser:option("--cache", "Path to cache file.", default_cache_path)
               :defmode "arg",
            parser:flag("--no-cache", "Do not use cache.")
         )
      end

      if multithreading.has_lanes then
         parser:option("-j --jobs", "Check <jobs> files in parallel.")
            :convert(tonumber)
      end

      parser:option("--formatter" , [[Use custom formatter.
<formatter> must be a module name or one of:
   TAP - Test Anything Protocol formatter;
   JUnit - JUnit XML formatter;
   plain - simple warning-per-line formatter;
   default - standard formatter.]])

      parser:flag("-q --quiet", [[Suppress output for files without warnings.
   -qq: Suppress output of warnings.
   -qqq: Only print total number of warnings and
      errors.]])
         :count "0-3"

      parser:flag("--codes", "Show warning codes.")
      parser:flag("--ranges", "Show ranges of columns related to warnings.")
      parser:flag("--no-color", "Do not color output.")

      parser:flag("-v --version", "Show version info and exit.")
         :action(function() print(version.string) os.exit(0) end)

      return parser
   end

   local function match_any(globs, name)
      for _, glob in ipairs(globs) do
         if globbing.match(glob, name) then
            return true
         end
      end

      return false
   end

   local function is_included(args, name)
      return not match_any(args.exclude_files, name) and (#args.include_files == 0 or match_any(args.include_files, name))
   end

   -- Expands folders, rockspecs, -
   -- Returns new array of filenames and table mapping indexes of bad rockspecs to error messages.
   -- Removes "./" in the beginnings of file names.
   -- Filters filenames using args.exclude_files and args.include_files.
   local function expand_files(args)
      local res, bad_rockspecs = {}, {}

      local function add(file)
         if type(file) == "string" then
            file = file:gsub("^./", "")
         end

         local name = args.filename or file

         if type(name) == "string" then
            if not is_included(args, name) then
               return false
            end
         end

         table.insert(res, file)
         return true
      end

      for _, file in ipairs(args.files) do
         if file == "-" then
            add(io.stdin)
         elseif fs.is_dir(file) then
            for _, nested_file in ipairs(fs.extract_files(file, "%.lua$")) do
               add(nested_file)
            end
         elseif file:sub(-#".rockspec") == ".rockspec" then
            local related_files, err = expand_rockspec(file)

            if related_files then
               for _, related_file in ipairs(related_files) do
                  add(related_file)
               end
            else
               if add(file) then
                  bad_rockspecs[#res] = err
               end
            end
         else
            add(file)
         end
      end

      return res, bad_rockspecs
   end

   local function validate_args(args, parser)
      if args.jobs and args.jobs < 1 then
         parser:error("<jobs> must be at least 1")
      end

      if args.std and not options.split_std(args.std) then
         parser:error("<std> must name a standard library")
      end
   end

   local function get_options(args)
      local res = {}

      for _, argname in ipairs {"allow_defined", "allow_defined_top", "module", "compat", "std"} do
         if args[argname] then
            res[argname] = args[argname]
         end
      end

      for _, argname in ipairs {"global", "unused", "redefined", "unused", "unused_args",
            "unused_secondaries", "self", "inline"} do
         if args["no_"..argname] then
            res[argname] = false
         end
      end

      for _, argname in ipairs {"globals", "read_globals", "new_globals", "new_read_globals",
            "ignore", "enable", "only"} do
         if #args[argname] > 0 then
            res[argname] = utils.concat_arrays(args[argname])
         end
      end

      return res
   end

   local function combine_conf_and_args_path_arrays(conf, args, option)
      local conf_opts = config.get_top_options(conf)

      if conf_opts[option] then
         for i, path in ipairs(conf_opts[option]) do
            conf_opts[option][i] = config.relative_path(conf, path)
         end

         table.insert(args[option], conf_opts[option])
      end

      args[option] = utils.concat_arrays(args[option])
   end

   -- Applies cli-specific options from config to args.
   local function combine_config_and_args(conf, args)
      local conf_opts = config.get_top_options(conf)

      if args.no_color then
         args.color = false
      else
         args.color = conf_opts.color ~= false
      end

      args.codes = args.codes or conf_opts.codes
      args.formatter = args.formatter or conf_opts.formatter or "default"

      if args.no_cache or not fs.has_lfs then
         args.cache = false
      elseif not args.cache then
         if type(conf_opts.cache) == "string" then
            args.cache = config.relative_path(conf, conf_opts.cache)
         else
            args.cache = conf_opts.cache
         end
      end

      if args.cache == true then
         args.cache = config.relative_path(conf, default_cache_path)
      end

      args.jobs = args.jobs or conf_opts.jobs

      combine_conf_and_args_path_arrays(conf, args, "exclude_files")
      combine_conf_and_args_path_arrays(conf, args, "include_files")
   end

   -- Returns sparse array of mtimes and map of filenames to cached reports.
   local function get_mtimes_and_cached_reports(cache_filename, files, bad_files)
      local cache_files = {}
      local cache_mtimes = {}
      local sparse_mtimes = {}

      for i, file in ipairs(files) do
         if not bad_files[i] and file ~= io.stdin then
            table.insert(cache_files, file)
            local mtime = fs.mtime(file)
            table.insert(cache_mtimes, mtime)
            sparse_mtimes[i] = mtime
         end
      end

      return sparse_mtimes, cache.load(cache_filename, cache_files, cache_mtimes) or critical(
         ("Couldn't load cache from %s: data corrupted"):format(cache_filename))
   end

   -- Returns sparse array of sources of files that need to be checked, updates bad_files with files that had I/O issues.
   local function get_srcs_to_check(cached_reports, files, bad_files)
      local res = {}

      for i, file in ipairs(files) do
         if not bad_files[i] and not cached_reports[file] then
            local src = utils.read_file(file)

            if src then
               res[i] = src
            else
               bad_files[i] = "I/O"
            end
         end
      end

      return res
   end

   -- Returns sparse array of new reports.
   local function get_new_reports(files, srcs, jobs)
      local dense_srcs = {}
      local dense_to_sparse = {}

      for i in ipairs(files) do
         if srcs[i] then
            table.insert(dense_srcs, srcs[i])
            dense_to_sparse[#dense_srcs] = i
         end
      end

      local map = jobs and multithreading.has_lanes and multithreading.pmap or utils.map
      local dense_res = map(luacheck.get_report, dense_srcs, jobs)

      local res = {}

      for i in ipairs(dense_srcs) do
         res[dense_to_sparse[i]] = dense_res[i]
      end

      return res
   end

   -- Updates cache with new_reports. Updates bad_files for which mtime is absent.
   local function update_cache(cache_filename, files, bad_files, srcs, mtimes, new_reports)
      local cache_files = {}
      local cache_mtimes = {}
      local cache_reports = {}

      for i, file in ipairs(files) do
         if srcs[i] and file ~= io.stdin then
            if not mtimes[i] then
               bad_files[i] = "I/O"
            else
               table.insert(cache_files, file)
               table.insert(cache_mtimes, mtimes[i])
               table.insert(cache_reports, new_reports[i] or false)
            end
         end
      end

      return cache.update(cache_filename, cache_files, cache_mtimes, cache_reports) or critical(
         ("Couldn't save cache to %s: I/O error"):format(cache_filename))
   end

   -- Returns array of reports for files.
   local function get_reports(cache_filename, files, bad_rockspecs, jobs)
      local bad_files = utils.update({}, bad_rockspecs)
      local mtimes
      local cached_reports

      if cache_filename then
         mtimes, cached_reports = get_mtimes_and_cached_reports(cache_filename, files, bad_files)
      else
         cached_reports = {}
      end

      local srcs = get_srcs_to_check(cached_reports, files, bad_files)
      local new_reports = get_new_reports(files, srcs, jobs)

      if cache_filename then
         update_cache(cache_filename, files, bad_files, srcs, mtimes, new_reports)
      end

      local res = {}

      for i, file in ipairs(files) do
         if bad_files[i] then
            res[i] = {fatal = bad_files[i]}
         else
            res[i] = cached_reports[file] or new_reports[i]
         end
      end

      return res
   end

   local function combine_config_and_options(conf, cli_opts, files)
      local res = {}

      for i, file in ipairs(files) do
         res[i] = config.get_options(conf, file)
         table.insert(res[i], cli_opts)
      end

      return res
   end

   local function substitute_filename(new_filename, files)
      if new_filename then
         for i = 1, #files do
            files[i] = new_filename
         end
      end
   end

   local function normalize_stdin_in_filenames(files)
      for i, file in ipairs(files) do
         if type(file) ~= "string" then
            files[i] = "stdin"
         end
      end
   end

   local builtin_formatters = utils.array_to_set({"TAP", "JUnit", "plain", "default"})

   local function pformat(report, file_names, conf, args)
      if builtin_formatters[args.formatter] then
         return format.format(report, file_names, args)
      end

      local formatter = args.formatter
      local ok, output

      if type(formatter) == "string" then
         ok, formatter = config.relative_require(conf, formatter)

         if not ok then
            critical(("Couldn't load custom formatter '%s': %s"):format(args.formatter, formatter))
         end
      end

      ok, output = pcall(formatter, report, file_names, args)

      if not ok then
         critical(("Couldn't run custom formatter '%s': %s"):format(tostring(args.formatter), output))
      end

      return output
   end

   local parser = get_parser()
   local args = parser:parse()
   local opts = get_options(args)
   local conf

   if args.no_config then
      conf = config.empty_config
   else
      local err
      conf, err = config.load_config(args.config)

      if not conf then
         critical(err)
      end
   end

   -- Validate args only after loading config so that custom stds are already in place.
   validate_args(args, parser)
   combine_config_and_args(conf, args)

   local files, bad_rockspecs = expand_files(args)
   local reports = get_reports(args.cache, files, bad_rockspecs, args.jobs)
   substitute_filename(args.filename, files)
   local report = luacheck.process_reports(reports, combine_config_and_options(conf, opts, files))
   normalize_stdin_in_filenames(files)

   local output = pformat(report, files, conf, args)

   if #output > 0 and output:sub(-1) ~= "\n" then
      output = output .. "\n"
   end

   io.stdout:write(output)

   local exit_code

   if report.fatals > 0 then
      exit_code = 2
   elseif report.warnings > 0 or report.errors > 0 then
      exit_code = 1
   else
      exit_code = 0
   end

   os.exit(exit_code)
end

xpcall(main, global_error_handler)
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.inline_options"])sources["luacheck.inline_options"]=([===[-- <pack luacheck.inline_options> --
local options = require "luacheck.options"
local filter = require "luacheck.filter"
local core_utils = require "luacheck.core_utils"
local utils = require "luacheck.utils"

-- Inline option is a comment starting with "luacheck:".
-- Body can be "push", "pop" or comma delimited options, where option
-- is option name plus space delimited arguments.

-- If there is code on line with inline option, it only affects that line;
-- otherwise, it affects everything till the end of current closure.
-- Option scope can also be regulated using "push" and "pop" options:
-- -- luacheck: push
-- -- luacheck: ignore foo
-- foo() -- Ignored.
-- -- luacheck: pop
-- foo() -- Not ignored.

local function add_closure_boundaries(ast, events)
   if ast.tag == "Function" then
      table.insert(events, {push = true, closure = true,
         line = ast.location.line, column = ast.location.column})
      table.insert(events, {pop = true, closure = true,
         line = ast.end_location.line, column = ast.end_location.column})
   else
      for _, node in ipairs(ast) do
         if type(node) == "table" then
            add_closure_boundaries(node, events)
         end
      end
   end
end

-- Parses inline option body, returns options or nil.
local function get_options(body)
   local opts = {}

   for _, name_and_args in ipairs(utils.split(body, ",")) do
      local args = utils.split(name_and_args)
      local name = table.remove(args, 1)

      if not name then
         return
      end

      if name == "std" then
         if #args ~= 1 or not options.split_std(args[1]) then
            return
         end

         opts.std = args[1]
      elseif name == "ignore" and #args == 0 then
         opts.ignore = {".*/.*"}
      else
         local flag = true

         if name == "no" then
            flag = false
            name = table.remove(args, 1)
         end

         while true do
            if options.variadic_inline_options[name] then
               if flag then
                  opts[name] = args
                  break
               else
                  -- Array option with 'no' prefix is invalid.
                  return
               end
            elseif #args == 0 then
               if options.nullary_inline_options[name] then
                  opts[name] = flag
                  break
               else
                  -- Consumed all arguments but didn't find a valid option name.
                  return
               end
            else
               -- Join name with next argument,
               name = name.."_"..table.remove(args, 1)
            end
         end
      end
   end

   return opts
end

-- Returns whether option is valid.
local function add_inline_option(events, per_line_opts, body, location, end_column, is_code_line)
   body = utils.strip(body)

   if body == "push" or body == "pop" then
      table.insert(events, {[body] = true, line = location.line, column = location.column, end_column = end_column})
      return true
   end

   local opts = get_options(body)

   if not opts then
      return false
   end

   if is_code_line then
      if not per_line_opts[location.line] then
         per_line_opts[location.line] = {}
      end

      table.insert(per_line_opts[location.line], opts)
   else
      table.insert(events, {options = opts, line = location.line, column = location.column, end_column = end_column})
   end

   return true
end

-- Returns map of per line options and array of invalid comments.
local function add_inline_options(events, comments, code_lines)
   local per_line_opts = {}
   local invalid_comments = {}

   for _, comment in ipairs(comments) do
      local contents = utils.strip(comment.contents)
      local body = utils.after(contents, "^luacheck:")

      if body then
         if not add_inline_option(events, per_line_opts, body, comment.location, comment.end_column, code_lines[comment.location.line]) then
            table.insert(invalid_comments, comment)
         end
      end
   end

   return per_line_opts, invalid_comments
end

local function alert_code(warning, code)
   local new_warning = utils.update({}, warning)
   new_warning.code = code
   return new_warning
end

local function apply_possible_filtering(opts, warning, code)
   if filter.filters(opts, code and alert_code(warning, code) or warning) then
      warning["filtered_" .. (code or warning.code)] = true
   end
end

local function apply_inline_options(option_stack, per_line_opts, warnings)
   if not option_stack.top.normalized then
      option_stack.top.normalize = options.normalize(option_stack)
   end

   local normalized_options = option_stack.top.normalize

   for _, warning in ipairs(warnings) do
      local opts = normalized_options

      if per_line_opts[warning.line] then
         opts = options.normalize(utils.concat_arrays({option_stack, per_line_opts[warning.line]}))
      end

      if warning.code:match("1..") then
         apply_possible_filtering(opts, warning)

         if warning.code ~= "113" then
            warning.read_only = opts.read_globals[warning.name]
            warning.global = opts.globals[warning.name] and not warning.read_only or nil

            if warning.code == "111" then
               if opts.module then
                  warning.in_module = true
                  warning.filtered_111 = nil
               end

               if core_utils.is_definition(opts, warning) then
                  warning.definition = true
               end

               apply_possible_filtering(opts, warning, "121")
               apply_possible_filtering(opts, warning, "131")
            else
               apply_possible_filtering(opts, warning, "122")
            end
         end
      elseif filter.filters(opts, warning) then
         warning.filtered = true
      end
   end
end

-- Mutates shape of warnings in events according to inline options.
-- Warnings which are simply filtered are marked with .filtered.
-- Returns arrays of unpaired push events and unpaired pop events.
local function handle_events(events, per_line_opts)
   local unpaired_pushes, unpaired_pops = {}, {}
   local unfiltered_warnings = {}
   local option_stack = utils.Stack()
   local boundaries = utils.Stack()

   option_stack:push({std = "none"})

   -- Go through all events.
   for _, event in ipairs(events) do
      if event.code then
         -- It's a warning, put it into list of not handled warnings.
         table.insert(unfiltered_warnings, event)
      elseif event.options then
         if #unfiltered_warnings ~= 0 then
            -- There are new options added and there were not handled warnings.
            -- Handle them using old option stack.
            apply_inline_options(option_stack, per_line_opts, unfiltered_warnings)
            unfiltered_warnings = {}
         end

         option_stack:push(event.options)
      elseif event.push then
         -- New boundary. Save size of the option stack to rollback later
         -- when boundary is popped.
         event.last_option_index = option_stack.size
         boundaries:push(event)
      elseif event.pop then
         if boundaries.size == 0 or (boundaries.top.closure and not event.closure) then
            -- Unpaired pop boundary, do nothing.
            table.insert(unpaired_pops, event)
         else
            if event.closure then
               -- There could be unpaired push boundaries, pop them.
               while not boundaries.top.closure do
                  table.insert(unpaired_pushes, boundaries:pop())
               end
            end

            -- Pop closure boundary.
            local new_last_option_index = boundaries:pop().last_option_index

            if new_last_option_index ~= option_stack.size and #unfiltered_warnings ~= 0 then
               -- Some options are going to be popped, handle not handled warnings.
               apply_inline_options(option_stack, per_line_opts, unfiltered_warnings)
               unfiltered_warnings = {}
            end

            while new_last_option_index ~= option_stack.size do
               option_stack:pop()
            end
         end
      end
   end

   if #unfiltered_warnings ~= 0 then
      apply_inline_options(option_stack, per_line_opts, unfiltered_warnings)
   end

   return unpaired_pushes, unpaired_pops
end

-- Filteres warnings using inline options, adds invalid comments.
-- Warnings which are altered in shape:
--    .filtered is added to warnings filtered by inline options;
--    .filtered_<code> is added to warnings that would be filtered by inline options if their code was <code>
--       (111 can change to 121 and 131, 112 can change to 122);
--    .definition is added to global set warnings (111) that are implicit definitions due to inline options;
--    .in_module is added to 111 warnings that are in module due to inline options.
--    .read_only is added to 111 and 112 warnings related to read only globals.
--    .global is added to 111 and 112 related to regular globals.
-- Invalid comments have same shape as warnings, with codes:
--    021 - syntactically invalid comment;
--    022 - unpaired push comment;
--    023 - unpaired pop comment.
local function handle_inline_options(ast, comments, code_lines, warnings)
   -- Create array of all events sorted by location.
   -- This includes inline options, warnings and implicit push/pop operations corresponding to closure starts/ends.
   local events = utils.update({}, warnings)

   -- Add implicit push/pop around main chunk.
   table.insert(events, {push = true, closure = true,
      line = -1, column = 0})
   table.insert(events, {pop = true, closure = true,
      line = math.huge, column = 0})

   add_closure_boundaries(ast, events)
   local per_line_opts, invalid_comments = add_inline_options(events, comments, code_lines)
   core_utils.sort_by_location(events)
   local unpaired_pushes, unpaired_pops = handle_events(events, per_line_opts)

   for _, comment in ipairs(invalid_comments) do
      table.insert(warnings, {code = "021", line = comment.location.line, column = comment.location.column, end_column = comment.end_column})
   end

   for _, event in ipairs(unpaired_pushes) do
      table.insert(warnings, {code = "022", line = event.line, column = event.column, end_column = event.end_column})
   end

   for _, event in ipairs(unpaired_pops) do
      table.insert(warnings, {code = "023", line = event.line, column = event.column, end_column = event.end_column})
   end

   return warnings
end

return handle_inline_options
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.linearize"])sources["luacheck.linearize"]=([===[-- <pack luacheck.linearize> --
local lexer = require "luacheck.lexer"
local utils = require "luacheck.utils"

local pseudo_labels = utils.array_to_set({"do", "else", "break", "end", "return"})

-- Who needs classes anyway.
local function new_line()
   return {
      accessed_upvalues = {}, -- Maps variables to arrays of accessing items.
      set_upvalues = {}, -- Maps variables to arays of setting items.
      lines = {},
      items = utils.Stack()
   }
end

local function new_scope(line)
   return {
      vars = {},
      labels = {},
      gotos = {},
      line = line
   }
end

local function new_var(line, node, type_)
   return {
      name = node[1],
      location = node.location,
      type = type_,
      self = node.implicit,
      line = line,
      scope_start = line.items.size + 1,
      values = {}
   }
end

local function new_value(var_node, value_node, is_init)
   return {
      var = var_node.var,
      location = var_node.location,
      type = value_node and value_node.tag == "Function" and "func" or (is_init and var_node.var.type or "var"),
      initial = is_init,
      empty = is_init and not value_node and (var_node.var.type == "var")
   }
end

local function new_label(line, name, location, end_column)
   return {
      name = name,
      location = location,
      end_column = end_column,
      index = line.items.size + 1
   }
end

local function new_goto(name, jump, location)
   return {
      name = name,
      jump = jump,
      location = location
   }
end

local function new_jump_item(is_conditional)
   return {
      tag = is_conditional and "Cjump" or "Jump"
   }
end

local function new_eval_item(expr)
   return {
      tag = "Eval",
      expr = expr,
      location = expr.location,
      token = expr.first_token,
      accesses = {},
      used_values = {},
      lines = {}
   }
end

local function new_noop_item(node, loop_end)
   return {
      tag = "Noop",
      location = node.location,
      token = node.first_token,
      loop_end = loop_end
   }
end

local function new_local_item(lhs, rhs, location, token)
   return {
      tag = "Local",
      lhs = lhs,
      rhs = rhs,
      location = location,
      token = token,
      accesses = rhs and {},
      used_values = rhs and {},
      lines = rhs and {}
   }
end

local function new_set_item(lhs, rhs, location, token)
   return {
      tag = "Set",
      lhs = lhs,
      rhs = rhs,
      location = location,
      token = token,
      accesses = {},
      used_values = {},
      lines = {}
   }
end

local function is_unpacking(node)
   return node.tag == "Dots" or node.tag == "Call" or node.tag == "Invoke"
end

local LinState = utils.class()

function LinState:__init(chstate)
   self.chstate = chstate
   self.lines = utils.Stack()
   self.scopes = utils.Stack()
end

function LinState:enter_scope()
   self.scopes:push(new_scope(self.lines.top))
end

function LinState:leave_scope()
   local left_scope = self.scopes:pop()
   local prev_scope = self.scopes.top

   for _, goto_ in ipairs(left_scope.gotos) do
      local label = left_scope.labels[goto_.name]

      if label then
         goto_.jump.to = label.index
         label.used = true
      else
         if not prev_scope or prev_scope.line ~= self.lines.top then
            if goto_.name == "break" then
               lexer.syntax_error(goto_.location, goto_.location.column + 4, "'break' is not inside a loop")
            else
               lexer.syntax_error(goto_.location, goto_.location.column + 3, ("no visible label '%s'"):format(goto_.name))
            end
         end

         table.insert(prev_scope.gotos, goto_)
      end
   end

   for name, label in pairs(left_scope.labels) do
      if not label.used and not pseudo_labels[name] then
         self.chstate:warn_unused_label(label)
      end
   end

   for _, var in pairs(left_scope.vars) do
      var.scope_end = self.lines.top.items.size
   end
end

function LinState:register_var(node, type_)
   local var = new_var(self.lines.top, node, type_)
   local prev_var = self:resolve_var(var.name)

   if prev_var then
      local same_scope = self.scopes.top.vars[var.name]
      self.chstate:warn_redefined(var, prev_var, same_scope)

      if same_scope then
         prev_var.scope_end = self.lines.top.items.size
      end
   end

   self.scopes.top.vars[var.name] = var
   node.var = var
   return var
end

function LinState:register_vars(nodes, type_)
   for _, node in ipairs(nodes) do
      self:register_var(node, type_)
   end
end

function LinState:resolve_var(name)
   for _, scope in utils.ripairs(self.scopes) do
      local var = scope.vars[name]

      if var then
         return var
      end
   end
end

function LinState:check_var(node, action)
   local var = self:resolve_var(node[1])

   if not var then
      self.chstate:warn_global(node, action, self.lines.size == 1)
   else
      node.var = var
   end

   return var
end

function LinState:register_label(name, location, end_column)
   if self.scopes.top.labels[name] then
      assert(not pseudo_labels[name])
      lexer.syntax_error(location, end_column, ("label '%s' already defined on line %d"):format(
         name, self.scopes.top.labels[name].location.line))
   end

   self.scopes.top.labels[name] = new_label(self.lines.top, name, location, end_column)
end

-- `node` is assignment node (`Local or `Set).
function LinState:check_balance(node)
   if node[2] then
      if #node[1] < #node[2] then
         self.chstate:warn_unbalanced(node.equals_location, true)
      elseif (#node[1] > #node[2]) and node.tag ~= "Local" and not is_unpacking(node[2][#node[2]]) then
         self.chstate:warn_unbalanced(node.equals_location)
      end
   end
end

function LinState:check_empty_block(block)
   if #block == 0 then
      self.chstate:warn_empty_block(block.location, block.tag == "Do")
   end
end

function LinState:emit(item)
   self.lines.top.items:push(item)
end

function LinState:emit_goto(name, is_conditional, location)
   local jump = new_jump_item(is_conditional)
   self:emit(jump)
   table.insert(self.scopes.top.gotos, new_goto(name, jump, location))
end

local tag_to_boolean = {
   Nil = false, False = false,
   True = true, Number = true, String = true, Table = true, Function = true
}

-- Emits goto that jumps to ::name:: if bool(cond_node) == false.
function LinState:emit_cond_goto(name, cond_node)
   local cond_bool = tag_to_boolean[cond_node.tag]

   if cond_bool ~= true then
      self:emit_goto(name, cond_bool ~= false)
   end
end

function LinState:emit_noop(node, loop_end)
   self:emit(new_noop_item(node, loop_end))
end

function LinState:emit_stmt(stmt)
   self["emit_stmt_" .. stmt.tag](self, stmt)
end

function LinState:emit_stmts(stmts)
   for _, stmt in ipairs(stmts) do
      self:emit_stmt(stmt)
   end
end

function LinState:emit_block(block)
   self:enter_scope()
   self:emit_stmts(block)
   self:leave_scope()
end

function LinState:emit_stmt_Do(node)
   self:check_empty_block(node)
   self:emit_noop(node)
   self:emit_block(node)
end

function LinState:emit_stmt_While(node)
   self:emit_noop(node)
   self:enter_scope()
   self:register_label("do")
   self:emit_expr(node[1])
   self:emit_cond_goto("break", node[1])
   self:emit_block(node[2])
   self:emit_noop(node, true)
   self:emit_goto("do")
   self:register_label("break")
   self:leave_scope()
end

function LinState:emit_stmt_Repeat(node)
   self:emit_noop(node)
   self:enter_scope()
   self:register_label("do")
   self:enter_scope()
   self:emit_stmts(node[1])
   self:emit_expr(node[2])
   self:leave_scope()
   self:emit_cond_goto("do", node[2])
   self:register_label("break")
   self:leave_scope()
end

function LinState:emit_stmt_Fornum(node)
   self:emit_noop(node)
   self:emit_expr(node[2])
   self:emit_expr(node[3])

   if node[5] then
      self:emit_expr(node[4])
   end

   self:enter_scope()
   self:register_label("do")
   self:emit_goto("break", true)
   self:enter_scope()
   self:emit(new_local_item({node[1]}))
   self:register_var(node[1], "loopi")
   self:emit_stmts(node[5] or node[4])
   self:leave_scope()
   self:emit_noop(node, true)
   self:emit_goto("do")
   self:register_label("break")
   self:leave_scope()
end

function LinState:emit_stmt_Forin(node)
   self:emit_noop(node)
   self:emit_exprs(node[2])
   self:enter_scope()
   self:register_label("do")
   self:emit_goto("break", true)
   self:enter_scope()
   self:emit(new_local_item(node[1]))
   self:register_vars(node[1], "loop")
   self:emit_stmts(node[3])
   self:leave_scope()
   self:emit_noop(node, true)
   self:emit_goto("do")
   self:register_label("break")
   self:leave_scope()
end

function LinState:emit_stmt_If(node)
   self:emit_noop(node)
   self:enter_scope()

   for i = 1, #node - 1, 2 do
      self:enter_scope()
      self:emit_expr(node[i])
      self:emit_cond_goto("else", node[i])
      self:check_empty_block(node[i + 1])
      self:emit_block(node[i + 1])
      self:emit_goto("end")
      self:register_label("else")
      self:leave_scope()
   end

   if #node % 2 == 1 then
      self:check_empty_block(node[#node])
      self:emit_block(node[#node])
   end

   self:register_label("end")
   self:leave_scope()
end

function LinState:emit_stmt_Label(node)
   self:register_label(node[1], node.location, node.end_column)
end

function LinState:emit_stmt_Goto(node)
   self:emit_noop(node)
   self:emit_goto(node[1], false, node.location)
end

function LinState:emit_stmt_Break(node)
   self:emit_goto("break", false, node.location)
end

function LinState:emit_stmt_Return(node)
   self:emit_noop(node)
   self:emit_exprs(node)
   self:emit_goto("return")
end

function LinState:emit_expr(node)
   local item = new_eval_item(node)
   self:scan_expr(item, node)
   self:emit(item)
end

function LinState:emit_exprs(exprs)
   for _, expr in ipairs(exprs) do
      self:emit_expr(expr)
   end
end

LinState.emit_stmt_Call = LinState.emit_expr
LinState.emit_stmt_Invoke = LinState.emit_expr

function LinState:emit_stmt_Local(node)
   self:check_balance(node)
   local item = new_local_item(node[1], node[2], node.location, node.first_token)
   self:emit(item)

   if node[2] then
      self:scan_exprs(item, node[2])
   end

   self:register_vars(node[1], "var")
end

function LinState:emit_stmt_Localrec(node)
   local item = new_local_item({node[1]}, {node[2]}, node.location, node.first_token)
   self:register_var(node[1], "var")
   self:emit(item)
   self:scan_expr(item, node[2])
end

function LinState:emit_stmt_Set(node)
   self:check_balance(node)
   local item = new_set_item(node[1], node[2], node.location, node.first_token)
   self:scan_exprs(item, node[2])

   for _, expr in ipairs(node[1]) do
      if expr.tag == "Id" then
         local var = self:check_var(expr, "set")

         if var then
            self:register_upvalue_action(item, var, "set")
         end
      else
         assert(expr.tag == "Index")

         if expr[1].tag == "Id" and not self:resolve_var(expr[1][1]) then
            -- Warn about mutated global.
            self:check_var(expr[1], "mutate")
         else
            self:scan_expr(item, expr[1])
         end

         self:scan_expr(item, expr[2])
      end
   end

   self:emit(item)
end


function LinState:scan_expr(item, node)
   local scanner = self["scan_expr_" .. node.tag]

   if scanner then
      scanner(self, item, node)
   end
end

function LinState:scan_exprs(item, nodes)
   for _, node in ipairs(nodes) do
      self:scan_expr(item, node)
   end
end

function LinState:register_upvalue_action(item, var, action)
   local key = (action == "set") and "set_upvalues" or "accessed_upvalues"

   for _, line in utils.ripairs(self.lines) do
      if line == var.line then
         break
      end

      if not line[key][var] then
         line[key][var] = {}
      end

      table.insert(line[key][var], item)
   end
end

function LinState:mark_access(item, node)
   node.var.accessed = true

   if not item.accesses[node.var] then
      item.accesses[node.var] = {}
   end

   table.insert(item.accesses[node.var], node)
   self:register_upvalue_action(item, node.var, "access")
end

function LinState:scan_expr_Id(item, node)
   if self:check_var(node, "access") then
      self:mark_access(item, node)
   end
end

function LinState:scan_expr_Dots(item, node)
   local dots = self:check_var(node, "access")

   if not dots or dots.line ~= self.lines.top then
      lexer.syntax_error(node.location, node.location.column + 2, "cannot use '...' outside a vararg function")
   end

   self:mark_access(item, node)
end

LinState.scan_expr_Index = LinState.scan_exprs
LinState.scan_expr_Call = LinState.scan_exprs
LinState.scan_expr_Invoke = LinState.scan_exprs
LinState.scan_expr_Paren = LinState.scan_exprs
LinState.scan_expr_Pair = LinState.scan_exprs
LinState.scan_expr_Table = LinState.scan_exprs

function LinState:scan_expr_Op(item, node)
   self:scan_expr(item, node[2])

   if node[3] then
      self:scan_expr(item, node[3])
   end
end

-- Puts tables {var = value{} into field `set_variables` of items in line which set values.
-- Registers set values in field `values` of variables.
function LinState:register_set_variables()
   local line = self.lines.top

   for _, item in ipairs(line.items) do
      if item.tag == "Local" or item.tag == "Set" then
         item.set_variables = {}

         local is_init = item.tag == "Local"
         local unpacking_item -- Rightmost item of rhs which may unpack into several lhs items.

         if item.rhs then
            local last_rhs_item = item.rhs[#item.rhs]

            if is_unpacking(last_rhs_item) then
               unpacking_item = last_rhs_item
            end
         end

         local secondaries -- Array of values unpacked from rightmost rhs item.

         if unpacking_item and (#item.lhs > #item.rhs) then
            secondaries = {}
         end

         for i, node in ipairs(item.lhs) do
            local value

            if node.var then
               value = new_value(node, item.rhs and item.rhs[i] or unpacking_item, is_init)
               item.set_variables[node.var] = value
               table.insert(node.var.values, value)
            end

            if secondaries and (i >= #item.rhs) then
               if value then
                  value.secondaries = secondaries
                  table.insert(secondaries, value)
               else
                  -- If one of secondary values is assigned to a global or index,
                  -- it is considered used.
                  secondaries.used = true
               end
            end
         end
      end
   end
end

function LinState:build_line(args, block)
   self.lines:push(new_line())
   self:enter_scope()
   self:emit(new_local_item(args))
   self:enter_scope()
   self:register_vars(args, "arg")
   self:emit_stmts(block)
   self:leave_scope()
   self:register_label("return")
   self:leave_scope()
   self:register_set_variables()
   local line = self.lines:pop()

   for _, prev_line in ipairs(self.lines) do
      table.insert(prev_line.lines, line)
   end

   return line
end

function LinState:scan_expr_Function(item, node)
   local line = self:build_line(node[1], node[2])
   table.insert(item.lines, line)

   for _, nested_line in ipairs(line.lines) do
      table.insert(item.lines, nested_line)
   end
end

-- Builds linear representation of AST and returns it.
-- Emits warnings: global, redefined/shadowed, unused label, unbalanced assignment, empty block.
local function linearize(chstate, ast)
   local linstate = LinState(chstate)
   local line = linstate:build_line({{tag = "Dots", "..."}}, ast)
   assert(linstate.lines.size == 0)
   assert(linstate.scopes.size == 0)
   return line
end

return linearize
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.analyze"])sources["luacheck.analyze"]=([===[-- <pack luacheck.analyze> --
local core_utils = require "luacheck.core_utils"

local function register_value(values_per_var, var, value)
   if not values_per_var[var] then
      values_per_var[var] = {}
   end

   table.insert(values_per_var[var], value)
end

local function add_resolution(item, var, value)
   register_value(item.used_values, var, value)
   value.used = true

   if value.secondaries then
      value.secondaries.used = true
   end
end

local function in_scope(var, index)
   return (var.scope_start <= index) and (index <= var.scope_end)
end

-- Called when value of var is live at an item, maybe several times.
-- Registers value as live where variable is accessed or liveness propogation stops.
-- Stops when out of scope of variable, at another assignment to it or at an item
-- encountered already.
-- When stopping at a visited item, only save value if the item is in the current stack
-- of items, i.e. when propogation followed some path from it to previous item
local function value_propogation_callback(line, stack, index, item, visited, var, value)
   if not item then
      register_value(line.last_live_values, var, value)
      return true
   end

   if not visited[index] and item.accesses and item.accesses[var] then
      add_resolution(item, var, value)
   end

   if stack[index] or (not visited[index] and (not in_scope(var, index) or item.set_variables and item.set_variables[var])) then
      if not item.live_values then  
         item.live_values = {}    
      end

      register_value(item.live_values, var, value)  
      return true
   end

   if visited[index] then
      return true
   end

   visited[index] = true
end

-- For each node accessing variables, adds table {var = {values}} to field `used_values`.
-- A pair `var = {values}` in this table means that accessed local variable `var` can contain one of values `values`.
-- Values that can be accessed locally are marked as used.
local function propogate_values(line)
   -- {var = values} live at the end of line.   
   line.last_live_values = {}

   -- It is not very clever to simply propogate every single assigned value.
   -- Fortunately, performance hit seems small (can be compenstated by inlining a few functions in lexer).
   for i, item in ipairs(line.items) do
      if item.set_variables then
         for var, value in pairs(item.set_variables) do
            if var.line == line then
               -- Values are only live at the item after assignment.
               core_utils.walk_line(line, i + 1, value_propogation_callback, {}, var, value)
            end
         end
      end
   end
end

-- Called when closure (subline) is live at index.
-- Updates variable resolution:
-- When a closure accessing upvalue is live at item where a value of the variable is live,
-- the access can resolve to the value.
-- When a closure setting upvalue is live at item where the variable is accessed,
-- the access can resolve to the value.
-- Live values are only stored when their liveness ends. However, as closure propogation is unrestricted,
-- if there is an intermediate item where value is factually live and closure is live, closure will at some
-- point be propogated to where value liveness ends and is stored as live.
-- (Chances that I will understand this comment six months later: non-existent)
local function closure_propogation_callback(line, _, item, subline)
   local live_values    

   if not item then
      live_values = line.last_live_values
   else   
      live_values = item.live_values
   end

   if live_values then
      for var, accessing_items in pairs(subline.accessed_upvalues) do
         if var.line == line then
            if live_values[var] then
               for _, accessing_item in ipairs(accessing_items) do
                  for _, value in ipairs(live_values[var]) do
                     add_resolution(accessing_item, var, value)
                  end
               end
            end
         end
      end
   end

   if not item then
      return true
   end

   if item.accesses then
      for var, setting_items in pairs(subline.set_upvalues) do
         if var.line == line then
            if item.accesses[var] then
               for _, setting_item in ipairs(setting_items) do
                  add_resolution(item, var, setting_item.set_variables[var])
               end
            end
         end
      end
   end
end

-- Updates variable resolution to account for closures and upvalues.
local function propogate_closures(line)
   for i, item in ipairs(line.items) do
      if item.lines then
         for _, subline in ipairs(item.lines) do
            -- Closures are considered live at the item they are created.
            core_utils.walk_line_once(line, {}, i, closure_propogation_callback, subline)
         end
      end
   end

   -- It is assumed that all closures are live at the end of the line.
   -- Therefore, all accesses and sets inside closures can resolve to each other.
   for _, subline in ipairs(line.lines) do
      for var, accessing_items in pairs(subline.accessed_upvalues) do
         if var.line == line then
            for _, accessing_item in ipairs(accessing_items) do
               for _, another_subline in ipairs(line.lines) do
                  if another_subline.set_upvalues[var] then
                     for _, setting_item in ipairs(another_subline.set_upvalues[var]) do
                        add_resolution(accessing_item, var, setting_item.set_variables[var])
                     end
                  end
               end
            end
         end
      end
   end
end

local function analyze_line(line)
   propogate_values(line)
   propogate_closures(line)
end

-- Emits warnings for variable.
local function check_var(chstate, var)
   if #var.values == 1 then
      if not var.values[1].used then
         chstate:warn_unused_variable(var)
      elseif var.values[1].empty then
         var.empty = true
         chstate:warn_unset(var)
      end
   elseif not var.accessed then
      chstate:warn_unaccessed(var)
   else
      for _, value in ipairs(var.values) do
         if (not value.used) and (not value.empty) then
            chstate:warn_unused_value(value)
         end
      end
   end
end

-- Emits warnings for unused variables and values and unset variables in line.
local function check_for_warnings(chstate, line)
   for _, item in ipairs(line.items) do
      if item.tag == "Local" then
         for var in pairs(item.set_variables) do
            -- Do not check implicit top level vararg.
            if var.location then
               check_var(chstate, var)
            end
         end
      end
   end
end

-- Finds reaching assignments for all variable accesses.
-- Emits warnings: unused variable, unused value, unset variable.
local function analyze(chstate, line)
   analyze_line(line)

   for _, nested_line in ipairs(line.lines) do
      analyze_line(nested_line)
   end

   check_for_warnings(chstate, line)

   for _, nested_line in ipairs(line.lines) do
      check_for_warnings(chstate, nested_line)
   end
end

return analyze
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.reachability"])sources["luacheck.reachability"]=([===[-- <pack luacheck.reachability> --
local core_utils = require "luacheck.core_utils"

local reachability

local function noop_callback() end

local function reachability_callback(_, _, item, chstate)
   if not item then
      return true
   end

   if item.lines then
      for _, subline in ipairs(item.lines) do
         reachability(chstate, subline)
      end
   end

   if item.accesses then
      for var, accessing_nodes in pairs(item.accesses) do
         local possible_values = item.used_values[var]

         if not var.empty and (#possible_values == 1) and possible_values[1].empty then
            for _, accessing_node in ipairs(accessing_nodes) do
               chstate:warn_uninit(accessing_node)
            end
         end
      end
   end
end

-- Emits warnings: unreachable code, uninitialized access.
function reachability(chstate, line)
   local reachable_indexes = {}
   core_utils.walk_line_once(line, reachable_indexes, 1, reachability_callback, chstate)

   for i, item in ipairs(line.items) do
      if not reachable_indexes[i] then
         if item.location then
            chstate:warn_unreachable(item.location, item.loop_end, item.token)
            core_utils.walk_line_once(line, reachable_indexes, i, noop_callback)
         end
      end
   end
end

return reachability
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.core_utils"])sources["luacheck.core_utils"]=([===[-- <pack luacheck.core_utils> --
local core_utils = {}

-- Calls callback with line, stack_set, index, item, ... for each item reachable from starting item.
-- `stack_set` is a set of indices of items in current propogation path from root, excluding current item.
-- Callback can return true to stop walking from current item.
function core_utils.walk_line(line, index, callback, ...)
   local stack = {}
   local stack_set = {}
   local backlog = {}
   local level = 0

   while index do
      local item = line.items[index]

      if not callback(line, stack_set, index, item, ...) and item then
         level = level + 1
         stack[level] = index
         stack_set[index] = true

         if item.tag == "Jump" then
            index = item.to
         elseif item.tag == "Cjump" then
            backlog[level] = index + 1
            index = item.to
         else
            index = index + 1
         end
      else
         while level > 0 and not backlog[level] do
            stack_set[stack[level]] = nil
            level = level - 1
         end

         index = backlog[level]
         backlog[level] = nil
      end
   end
end

local function once_per_item_callback_adapter(line, _, index, item, visited, callback, ...)
   if visited[index] then
      return true
   end

   visited[index] = true
   return callback(line, index, item, ...)
end

-- Calls callback with line, index, item, ... for each item reachable from starting item once.
-- `visited` is a set of already visited indexes.
-- Callback can return true to stop walking from current item.
function core_utils.walk_line_once(line, visited, index, callback, ...)
   return core_utils.walk_line(line, index, once_per_item_callback_adapter, visited, callback, ...)
end

-- Given a "global set" warning, return whether it is an implicit definition.
function core_utils.is_definition(opts, warning)
   return opts.allow_defined or (opts.allow_defined_top and warning.top)
end

local function location_comparator(event1, event2)
   -- If two events share location, neither can be an invalid comment event.
   -- However, they can be equal by identity due to the way table.sort is implemented.
   return event1.line < event2.line or
      event1.line == event2.line and (event1.column < event2.column or
      event1.column == event2.column and event1.code and event1.code < event2.code)
end

function core_utils.sort_by_location(array)
   table.sort(array, location_comparator)
end

return core_utils
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.version"])sources["luacheck.version"]=([===[-- <pack luacheck.version> --
local luacheck = require "luacheck"
local fs = require "luacheck.fs"
local multithreading = require "luacheck.multithreading"

local version = {}

version.luacheck = luacheck._VERSION

if rawget(_G, "jit") then
   version.lua = rawget(_G, "jit").version
else
   version.lua = _VERSION
end

if fs.has_lfs then
   version.lfs = fs.lfs._VERSION
else
   version.lfs = "Not found"
end

if multithreading.has_lanes then
   version.lanes = multithreading.lanes.ABOUT.version
else
   version.lanes = "Not found"
end

version.string = ([[
Luacheck: %s
Lua: %s
LuaFileSystem: %s
LuaLanes: %s]]):format(version.luacheck, version.lua, version.lfs, version.lanes)

return version
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.format"])sources["luacheck.format"]=([===[-- <pack luacheck.format> --
local utils = require "luacheck.utils"

local format = {}

local color_support = not utils.is_windows or os.getenv("ANSICON")

local message_formats = {
   ["011"] = function(w) return (w.msg:gsub("%%", "%%%%")) end,
   ["021"] = "invalid inline option",
   ["022"] = "unpaired push directive",
   ["023"] = "unpaired pop directive",
   ["111"] = function(w)
      if w.module then return "setting non-module global variable %s"
         else return "setting non-standard global variable %s" end end,
   ["112"] = "mutating non-standard global variable %s",
   ["113"] = "accessing undefined variable %s",
   ["121"] = "setting read-only global variable %s",
   ["122"] = "mutating read-only global variable %s",
   ["131"] = "unused global variable %s",
   ["211"] = function(w)
      if w.func then return "unused function %s"
         else return "unused variable %s" end end,
   ["212"] = function(w)
      if w.name == "..." then return "unused variable length argument"
         else return "unused argument %s" end end,
   ["213"] = "unused loop variable %s",
   ["221"] = "variable %s is never set",
   ["231"] = "variable %s is never accessed",
   ["232"] = "argument %s is never accessed",
   ["233"] = "loop variable %s is never accessed",
   ["311"] = "value assigned to variable %s is unused",
   ["312"] = "value of argument %s is unused",
   ["313"] = "value of loop variable %s is unused",
   ["321"] = "accessing uninitialized variable %s",
   ["411"] = "variable %s was previously defined on line %s",
   ["412"] = "variable %s was previously defined as an argument on line %s",
   ["413"] = "variable %s was previously defined as a loop variable on line %s",
   ["421"] = "shadowing definition of variable %s on line %s",
   ["422"] = "shadowing definition of argument %s on line %s",
   ["423"] = "shadowing definition of loop variable %s on line %s",
   ["431"] = "shadowing upvalue %s on line %s",
   ["432"] = "shadowing upvalue argument %s on line %s",
   ["433"] = "shadowing upvalue loop variable %s on line %s",
   ["511"] = "unreachable code",
   ["512"] = "loop is executed at most once",
   ["521"] = "unused label %s",
   ["531"] = "left-hand side of assignment is too short",
   ["532"] = "left-hand side of assignment is too long",
   ["541"] = "empty do..end block",
   ["542"] = "empty if branch"
}

local function get_message_format(warning)
   local message_format = message_formats[warning.code]

   if type(message_format) == "function" then
      return message_format(warning)
   else
      return message_format
   end
end

local function plural(number)
   return (number == 1) and "" or "s"
end

local color_codes = {
   reset = 0,
   bright = 1,
   red = 31,
   green = 32
}

local function encode_color(c)
   return "\27[" .. tostring(color_codes[c]) .. "m"
end

local function colorize(str, ...)
   str = str .. encode_color("reset")

   for _, color in ipairs({...}) do
      str = encode_color(color) .. str
   end

   return encode_color("reset") .. str
end

local function format_color(str, color, ...)
   return color and colorize(str, ...) or str
end

local function format_name(name, color)
   return color and colorize(name, "bright") or ("'" .. name .. "'")
end

local function format_number(number, color)
   return format_color(tostring(number), color, "bright", (number > 0) and "red" or "reset")
end

local function capitalize(str)
   return str:gsub("^.", string.upper)
end

local function fatal_type(file_report)
   return capitalize(file_report.fatal) .. " error"
end

local function count_warnings_errors(events)
   local warnings, errors = 0, 0

   for _, event in ipairs(events) do
      if event.code:sub(1, 1) == "0" then
         errors = errors + 1
      else
         warnings = warnings + 1
      end
   end

   return warnings, errors
end

local function format_file_report_header(report, file_name, opts)
   local label = "Checking " .. file_name
   local status

   if report.fatal then
      status = format_color(fatal_type(report), opts.color, "bright")
   elseif #report == 0 then
      status = format_color("OK", opts.color, "bright", "green")
   else
      local warnings, errors = count_warnings_errors(report)

      if warnings > 0 then
         status = format_color(tostring(warnings).." warning"..plural(warnings), opts.color, "bright", "red")
      end

      if errors > 0 then
         status = status and (status.." / ") or ""
         status = status..(format_color(tostring(errors).." error"..plural(errors), opts.color, "bright"))
      end
   end

   return label .. (" "):rep(math.max(50 - #label, 1)) .. status
end

local function format_location(file, location, opts)
   local res = ("%s:%d:%d"):format(file, location.line, location.column)

   if opts.ranges then
      res = ("%s-%d"):format(res, location.end_column)
   end

   return res
end

local function event_code(event)
   return (event.code:sub(1, 1) == "0" and "E" or "W")..event.code
end

local function format_message(event, color)
   return get_message_format(event):format(event.name and format_name(event.name, color), event.prev_line)
end

-- Returns formatted message for an issue, without color.
function format.get_message(event)
   return format_message(event)
end

local function format_event(file_name, event, opts)
   local message = format_message(event, opts.color)

   if opts.codes then
      message = ("(%s) %s"):format(event_code(event), message)
   end

   return format_location(file_name, event, opts) .. ": " .. message
end

local function format_file_report(report, file_name, opts)
   local buf = {format_file_report_header(report, file_name, opts)}

   if #report > 0 then
      table.insert(buf, "")

      for _, event in ipairs(report) do
         table.insert(buf, "    " .. format_event(file_name, event, opts))
      end

      table.insert(buf, "")
   end

   return table.concat(buf, "\n")
end

local formatters = {}

function formatters.default(report, file_names, opts)
   local buf = {}

   if opts.quiet <= 2 then
      for i, file_report in ipairs(report) do
         if opts.quiet == 0 or file_report.fatal or #file_report > 0 then
            table.insert(buf, (opts.quiet == 2 and format_file_report_header or format_file_report) (
               file_report, file_names[i], opts))
         end
      end

      if #buf > 0 and buf[#buf]:sub(-1) ~= "\n" then
         table.insert(buf, "")
      end
   end

   local total = ("Total: %s warning%s / %s error%s in %d file%s"):format(
      format_number(report.warnings, opts.color), plural(report.warnings),
      format_number(report.errors, opts.color), plural(report.errors),
      #report - report.fatals, plural(#report - report.fatals))

   if report.fatals > 0 then
      total = total..(", couldn't check %s file%s"):format(
         report.fatals, plural(report.fatals))
   end

   table.insert(buf, total)
   return table.concat(buf, "\n")
end

function formatters.TAP(report, file_names, opts)
   opts.color = false
   local buf = {}

   for i, file_report in ipairs(report) do
      if file_report.fatal then
         table.insert(buf, ("not ok %d %s: %s"):format(#buf + 1, file_names[i], fatal_type(file_report)))
      elseif #file_report == 0 then
         table.insert(buf, ("ok %d %s"):format(#buf + 1, file_names[i]))
      else
         for _, warning in ipairs(file_report) do
            table.insert(buf, ("not ok %d %s"):format(#buf + 1, format_event(file_names[i], warning, opts)))
         end
      end
   end

   table.insert(buf, 1, "1.." .. tostring(#buf))
   return table.concat(buf, "\n")
end

function formatters.JUnit(report, file_names)
   -- JUnit formatter doesn't support any options.
   local opts = {}
   local buf = {[[<?xml version="1.0" encoding="UTF-8"?>]]}
   local num_testcases = 0

   for _, file_report in ipairs(report) do
      if file_report.fatal or #file_report == 0 then
         num_testcases = num_testcases + 1
      else
         num_testcases = num_testcases + #file_report
      end
   end

   table.insert(buf, ([[<testsuite name="Luacheck report" tests="%d">]]):format(num_testcases))

   for file_i, file_report in ipairs(report) do
      if file_report.fatal then
         table.insert(buf, ([[    <testcase name="%s" classname="%s">]]):format(file_names[file_i], file_names[file_i]))
         table.insert(buf, ([[        <error type="%s"/>]]):format(fatal_type(file_report)))
         table.insert(buf, [[    </testcase>]])
      elseif #file_report == 0 then
         table.insert(buf, ([[    <testcase name="%s" classname="%s"/>]]):format(file_names[file_i], file_names[file_i]))
      else
         for event_i, event in ipairs(file_report) do
            table.insert(buf, ([[    <testcase name="%s:%d" classname="%s">]]):format(file_names[file_i], event_i, file_names[file_i]))
            table.insert(buf, ([[        <failure type="%s" message="%s"/>]]):format(
               event_code(event), format_event(file_names[file_i], event, opts)))
            table.insert(buf, [[    </testcase>]])
         end
      end
   end

   table.insert(buf, [[</testsuite>]])
   return table.concat(buf, "\n")
end

function formatters.plain(report, file_names, opts)
   opts.color = false
   local buf = {}

   for i, file_report in ipairs(report) do
      if file_report.fatal then
         table.insert(buf, ("%s: %s"):format(file_names[i], fatal_type(file_report)))
      else
         for _, event in ipairs(file_report) do
            table.insert(buf, format_event(file_names[i], event, opts))
         end
      end
   end

   return table.concat(buf, "\n")
end

--- Formats a report.
-- Recognized options:
--    `options.formatter`: name of used formatter. Default: "default".
--    `options.quiet`: integer in range 0-3. See CLI. Default: 0.
--    `options.color`: should use ansicolors? Default: true.
--    `options.codes`: should output warning codes? Default: false.
--    `options.ranges`: should output token end column? Default: false.
function format.format(report, file_names, options)
   return formatters[options.formatter or "default"](report, file_names, {
      quiet = options.quiet or 0,
      color = (options.color ~= false) and color_support,
      codes = options.codes,
      ranges = options.ranges
   })
end

return format
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.utils"])sources["luacheck.utils"]=([===[-- <pack luacheck.utils> --
local utils = {}

utils.dir_sep = package.config:sub(1,1)
utils.is_windows = utils.dir_sep == "\\"

local bom = "\239\187\191"

-- Returns all contents of file (path or file handler) or nil. 
function utils.read_file(file)
   local handler

   if type(file) == "string" then
      handler = io.open(file, "rb")

      if not handler then
         return nil
      end
   else
      handler = file
   end

   local res = handler:read("*a")
   handler:close()

   -- Use :len() instead of # operator because in some environments
   -- string library is patched to handle UTF.
   if res and res:sub(1, bom:len()) == bom then
      res = res:sub(bom:len() + 1)
   end

   return res
end

-- luacheck: push
-- luacheck: compat
if _VERSION:find "5.1" then
   -- Loads Lua source string in an environment, returns function or nil, error.
   function utils.load(src, env, chunkname)
      local func, err = loadstring(src, chunkname)

      if func then
         if env then
            setfenv(func, env)
         end

         return func
      else
         return nil, err
      end
   end
else
   -- Loads Lua source string in an environment, returns function or nil, error.
   function utils.load(src, env, chunkname)
      return load(src, chunkname, "t", env or _ENV)
   end
end
-- luacheck: pop

-- Loads config containing assignments to global variables from path. 
-- Returns config table and return value of config or nil and error message
-- ("I/O" or "syntax" or "runtime"). 
function utils.load_config(path, env)
   env = env or {}
   local src = utils.read_file(path)

   if not src then
      return nil, "I/O"
   end

   local func = utils.load(src, env)

   if not func then
      return nil, "syntax"
   end

   local ok, res = pcall(func)

   if not ok then
      return nil, "runtime"
   end

   return env, res
end

function utils.array_to_set(array)
   local set = {}

   for index, value in ipairs(array) do
      set[value] = index
   end

   return set
end

function utils.concat_arrays(array)
   local res = {}

   for _, subarray in ipairs(array) do
      for _, item in ipairs(subarray) do
         table.insert(res, item)
      end
   end

   return res
end

function utils.update(t1, t2)
   for k, v in pairs(t2) do
      t1[k] = v
   end

   return t1
end

local class_metatable = {}

function class_metatable.__call(class, ...)
   local obj = setmetatable({}, class)

   if class.__init then
      class.__init(obj, ...)
   end

   return obj
end

function utils.class()
   local class = setmetatable({}, class_metatable)
   class.__index = class
   return class
end

utils.Stack = utils.class()

function utils.Stack:__init()
   self.size = 0
end

function utils.Stack:push(value)
   self.size = self.size + 1
   self[self.size] = value
   self.top = value
end

function utils.Stack:pop()
   local value = self[self.size]
   self[self.size] = nil
   self.size = self.size - 1
   self.top = self[self.size]
   return value
end

local function error_handler(err)
   return {
      err = err,
      traceback = debug.traceback()
   }
end

-- Calls f with arg, returns what it does.
-- If f throws a table, returns nil, the table.
-- If f throws not a table, rethrows.
function utils.pcall(f, arg)
   local function task()
      return f(arg)
   end

   local ok, res = xpcall(task, error_handler)

   if ok then
      return res
   elseif type(res.err) == "table" then
      return nil, res.err
   else
      error(tostring(res.err) .. "\n" .. res.traceback, 0)
   end
end

local function ripairs_iterator(array, i)
   if i == 1 then
      return nil
   else
      i = i - 1
      return i, array[i]
   end
end

function utils.ripairs(array)
   return ripairs_iterator, array, #array + 1
end

function utils.after(str, pattern)
   local _, last_matched_index = str:find(pattern)

   if last_matched_index then
      return str:sub(last_matched_index + 1)
   end
end

function utils.strip(str)
   local _, last_start_space = str:find("^%s*")
   local first_end_space = str:find("%s*$")
   return str:sub(last_start_space + 1, first_end_space - 1)
end

-- `sep` must be nil or a single character. Behaves like python's `str.split`.
function utils.split(str, sep)
   local parts = {}
   local pattern

   if sep then
      pattern = sep .. "([^" .. sep .. "]*)"
      str = sep .. str
   else
      pattern = "%S+"
   end

   for part in str:gmatch(pattern) do
      table.insert(parts, part)
   end

   return parts
end

-- Behaves like string.match, except it normally returns boolean and
-- throws a table {pattern = pattern} on invalid pattern.
-- The error message turns into original error when tostring is used on it,
-- to ensure behaviour is predictable when luacheck is used as a module.
function utils.pmatch(str, pattern)
   assert(type(str) == "string")
   assert(type(pattern) == "string")

   local ok, res = pcall(string.match, str, pattern)

   if not ok then
      error(setmetatable({pattern = pattern}, {__tostring = function() return res end}))
   else
      return not not res
   end
end

-- Maps func over array.
function utils.map(func, array)
   local res = {}

   for i, item in ipairs(array) do
      res[i] = func(item)
   end

   return res
end

-- Returns predicate checking type.
function utils.has_type(type_)
   return function(x)
      return type(x) == type_
   end
end

-- Returns predicate checking that value is an array with
-- elements of type.
function utils.array_of(type_)
   return function(x)
      if type(x) ~= "table" then
         return false
      end

      for _, item in ipairs(x) do
         if type(item) ~= type_ then
            return false
         end
      end

      return true
   end
end

-- Returns predicate chacking if value satisfies on of predicates.
function utils.either(pred1, pred2)
   return function(x)
      return pred1(x) or pred2(x)
   end
end

return utils
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.argparse"])sources["luacheck.argparse"]=([===[-- <pack luacheck.argparse> --
local function deep_update(t1, t2)
   for k, v in pairs(t2) do
      if type(v) == "table" then
         v = deep_update({}, v)
      end

      t1[k] = v
   end

   return t1
end

-- A property is a tuple {name, callback}.
-- properties.args is number of properties that can be set as arguments
-- when calling an object.
local function new_class(prototype, properties, parent)
   -- Class is the metatable of its instances.
   local class = {}
   class.__index = class

   if parent then
      class.__prototype = deep_update(deep_update({}, parent.__prototype), prototype)
   else
      class.__prototype = prototype
   end

   local names = {}

   -- Create setter methods and fill set of property names. 
   for _, property in ipairs(properties) do
      local name, callback = property[1], property[2]

      class[name] = function(self, value)
         if not callback(self, value) then
            self["_" .. name] = value
         end

         return self
      end

      names[name] = true
   end

   function class.__call(self, ...)
      -- When calling an object, if the first argument is a table,
      -- interpret keys as property names, else delegate arguments
      -- to corresponding setters in order.
      if type((...)) == "table" then
         for name, value in pairs((...)) do
            if names[name] then
               self[name](self, value)
            end
         end
      else
         local nargs = select("#", ...)

         for i, property in ipairs(properties) do
            if i > nargs or i > properties.args then
               break
            end

            local arg = select(i, ...)

            if arg ~= nil then
               self[property[1]](self, arg)
            end
         end
      end

      return self
   end

   -- If indexing class fails, fallback to its parent.
   local class_metatable = {}
   class_metatable.__index = parent

   function class_metatable.__call(self, ...)
      -- Calling a class returns its instance.
      -- Arguments are delegated to the instance.
      local object = deep_update({}, self.__prototype)
      setmetatable(object, self)
      return object(...)
   end

   return setmetatable(class, class_metatable)
end

local function typecheck(name, types, value)
   for _, type_ in ipairs(types) do
      if type(value) == type_ then
         return true
      end
   end

   error(("bad property '%s' (%s expected, got %s)"):format(name, table.concat(types, " or "), type(value)))
end

local function typechecked(name, ...)
   local types = {...}
   return {name, function(_, value) typecheck(name, types, value) end}
end

local multiname = {"name", function(self, value)
   typecheck("name", {"string"}, value)

   for alias in value:gmatch("%S+") do
      self._name = self._name or alias
      table.insert(self._aliases, alias)
   end

   -- Do not set _name as with other properties.
   return true
end}

local function parse_boundaries(str)
   if tonumber(str) then
      return tonumber(str), tonumber(str)
   end

   if str == "*" then
      return 0, math.huge
   end

   if str == "+" then
      return 1, math.huge
   end

   if str == "?" then
      return 0, 1
   end

   if str:match "^%d+%-%d+$" then
      local min, max = str:match "^(%d+)%-(%d+)$"
      return tonumber(min), tonumber(max)
   end

   if str:match "^%d+%+$" then
      local min = str:match "^(%d+)%+$"
      return tonumber(min), math.huge
   end
end

local function boundaries(name)
   return {name, function(self, value)
      typecheck(name, {"number", "string"}, value)

      local min, max = parse_boundaries(value)

      if not min then
         error(("bad property '%s'"):format(name))
      end

      self["_min" .. name], self["_max" .. name] = min, max
   end}
end

local add_help = {"add_help", function(self, value)
   typecheck("add_help", {"boolean", "string", "table"}, value)

   if self._has_help then
      table.remove(self._options)
      self._has_help = false
   end

   if value then
      local help = self:flag()
         :description "Show this help message and exit."
         :action(function()
            print(self:get_help())
            os.exit(0)
         end)

      if value ~= true then
         help = help(value)
      end

      if not help._name then
         help "-h" "--help"
      end

      self._has_help = true
   end
end}

local Parser = new_class({
   _arguments = {},
   _options = {},
   _commands = {},
   _mutexes = {},
   _require_command = true,
   _handle_options = true
}, {
   args = 3,
   typechecked("name", "string"),
   typechecked("description", "string"),
   typechecked("epilog", "string"),
   typechecked("usage", "string"),
   typechecked("help", "string"),
   typechecked("require_command", "boolean"),
   typechecked("handle_options", "boolean"),
   add_help
})

local Command = new_class({
   _aliases = {}
}, {
   args = 3,
   multiname,
   typechecked("description", "string"),
   typechecked("epilog", "string"),
   typechecked("target", "string"),
   typechecked("usage", "string"),
   typechecked("help", "string"),
   typechecked("require_command", "boolean"),
   typechecked("handle_options", "boolean"),
   typechecked("action", "function"),
   add_help
}, Parser)

local Argument = new_class({
   _minargs = 1,
   _maxargs = 1,
   _mincount = 1,
   _maxcount = 1,
   _defmode = "unused",
   _show_default = true
}, {
   args = 5,
   typechecked("name", "string"),
   typechecked("description", "string"),
   typechecked("default", "string"),
   typechecked("convert", "function", "table"),
   boundaries("args"),
   typechecked("target", "string"),
   typechecked("defmode", "string"),
   typechecked("show_default", "boolean"),
   typechecked("argname", "string", "table")
})

local Option = new_class({
   _aliases = {},
   _mincount = 0,
   _overwrite = true
}, {
   args = 6,
   multiname,
   typechecked("description", "string"),
   typechecked("default", "string"),
   typechecked("convert", "function", "table"),
   boundaries("args"),
   boundaries("count"),
   typechecked("target", "string"),
   typechecked("defmode", "string"),
   typechecked("show_default", "boolean"),
   typechecked("overwrite", "boolean"),
   typechecked("argname", "string", "table"),
   typechecked("action", "function")
}, Argument)

function Argument:_get_argument_list()
   local buf = {}
   local i = 1

   while i <= math.min(self._minargs, 3) do
      local argname = self:_get_argname(i)

      if self._default and self._defmode:find "a" then
         argname = "[" .. argname .. "]"
      end

      table.insert(buf, argname)
      i = i+1
   end

   while i <= math.min(self._maxargs, 3) do
      table.insert(buf, "[" .. self:_get_argname(i) .. "]")
      i = i+1

      if self._maxargs == math.huge then
         break
      end
   end

   if i < self._maxargs then
      table.insert(buf, "...")
   end

   return buf
end

function Argument:_get_usage()
   local usage = table.concat(self:_get_argument_list(), " ")

   if self._default and self._defmode:find "u" then
      if self._maxargs > 1 or (self._minargs == 1 and not self._defmode:find "a") then
         usage = "[" .. usage .. "]"
      end
   end

   return usage
end

function Argument:_get_type()
   if self._maxcount == 1 then
      if self._maxargs == 0 then
         return "flag"
      elseif self._maxargs == 1 and (self._minargs == 1 or self._mincount == 1) then
         return "arg"
      else
         return "multiarg"
      end
   else
      if self._maxargs == 0 then
         return "counter"
      elseif self._maxargs == 1 and self._minargs == 1 then
         return "multicount"
      else
         return "twodimensional"
      end
   end
end

-- Returns placeholder for `narg`-th argument. 
function Argument:_get_argname(narg)
   local argname = self._argname or self:_get_default_argname()

   if type(argname) == "table" then
      return argname[narg]
   else
      return argname
   end
end

function Argument:_get_default_argname()
   return "<" .. self._name .. ">"
end

function Option:_get_default_argname()
   return "<" .. self:_get_default_target() .. ">"
end

-- Returns label to be shown in the help message. 
function Argument:_get_label()
   return self._name
end

function Option:_get_label()
   local variants = {}
   local argument_list = self:_get_argument_list()
   table.insert(argument_list, 1, nil)

   for _, alias in ipairs(self._aliases) do
      argument_list[1] = alias
      table.insert(variants, table.concat(argument_list, " "))
   end

   return table.concat(variants, ", ")
end

function Command:_get_label()
   return table.concat(self._aliases, ", ")
end

function Argument:_get_description()
   if self._default and self._show_default then
      if self._description then
         return ("%s (default: %s)"):format(self._description, self._default)
      else
         return ("default: %s"):format(self._default)
      end
   else
      return self._description or ""
   end
end

function Command:_get_description()
   return self._description or ""
end

function Option:_get_usage()
   local usage = self:_get_argument_list()
   table.insert(usage, 1, self._name)
   usage = table.concat(usage, " ")

   if self._mincount == 0 or self._default then
      usage = "[" .. usage .. "]"
   end

   return usage
end

function Option:_get_default_target()
   local res

   for _, alias in ipairs(self._aliases) do
      if alias:sub(1, 1) == alias:sub(2, 2) then
         res = alias:sub(3)
         break
      end
   end

   res = res or self._name:sub(2)
   return (res:gsub("-", "_"))
end

function Option:_is_vararg()
   return self._maxargs ~= self._minargs
end

function Parser:_get_fullname()
   local parent = self._parent
   local buf = {self._name}

   while parent do
      table.insert(buf, 1, parent._name)
      parent = parent._parent
   end

   return table.concat(buf, " ")
end

function Parser:_update_charset(charset)
   charset = charset or {}

   for _, command in ipairs(self._commands) do
      command:_update_charset(charset)
   end

   for _, option in ipairs(self._options) do
      for _, alias in ipairs(option._aliases) do
         charset[alias:sub(1, 1)] = true
      end
   end

   return charset
end

function Parser:argument(...)
   local argument = Argument(...)
   table.insert(self._arguments, argument)
   return argument
end

function Parser:option(...)
   local option = Option(...)

   if self._has_help then
      table.insert(self._options, #self._options, option)
   else
      table.insert(self._options, option)
   end

   return option
end

function Parser:flag(...)
   return self:option():args(0)(...)
end

function Parser:command(...)
   local command = Command():add_help(true)(...)
   command._parent = self
   table.insert(self._commands, command)
   return command
end

function Parser:mutex(...)
   local options = {...}

   for i, option in ipairs(options) do
      assert(getmetatable(option) == Option, ("bad argument #%d to 'mutex' (Option expected)"):format(i))
   end

   table.insert(self._mutexes, options)
   return self
end

local max_usage_width = 70
local usage_welcome = "Usage: "

function Parser:get_usage()
   if self._usage then
      return self._usage
   end

   local lines = {usage_welcome .. self:_get_fullname()}

   local function add(s)
      if #lines[#lines]+1+#s <= max_usage_width then
         lines[#lines] = lines[#lines] .. " " .. s
      else
         lines[#lines+1] = (" "):rep(#usage_welcome) .. s
      end
   end

   -- This can definitely be refactored into something cleaner
   local mutex_options = {}
   local vararg_mutexes = {}

   -- First, put mutexes which do not contain vararg options and remember those which do
   for _, mutex in ipairs(self._mutexes) do
      local buf = {}
      local is_vararg = false

      for _, option in ipairs(mutex) do
         if option:_is_vararg() then
            is_vararg = true
         end

         table.insert(buf, option:_get_usage())
         mutex_options[option] = true
      end

      local repr = "(" .. table.concat(buf, " | ") .. ")"

      if is_vararg then
         table.insert(vararg_mutexes, repr)
      else
         add(repr)
      end
   end

   -- Second, put regular options
   for _, option in ipairs(self._options) do
      if not mutex_options[option] and not option:_is_vararg() then
         add(option:_get_usage())
      end
   end

   -- Put positional arguments
   for _, argument in ipairs(self._arguments) do
      add(argument:_get_usage())
   end

   -- Put mutexes containing vararg options
   for _, mutex_repr in ipairs(vararg_mutexes) do
      add(mutex_repr)
   end

   for _, option in ipairs(self._options) do
      if not mutex_options[option] and option:_is_vararg() then
         add(option:_get_usage())
      end
   end

   if #self._commands > 0 then
      if self._require_command then
         add("<command>")
      else
         add("[<command>]")
      end

      add("...")
   end

   return table.concat(lines, "\n")
end

local margin_len = 3
local margin_len2 = 25
local margin = (" "):rep(margin_len)
local margin2 = (" "):rep(margin_len2)

local function make_two_columns(s1, s2)
   if s2 == "" then
      return margin .. s1
   end

   s2 = s2:gsub("\n", "\n" .. margin2)

   if #s1 < (margin_len2-margin_len) then
      return margin .. s1 .. (" "):rep(margin_len2-margin_len-#s1) .. s2
   else
      return margin .. s1 .. "\n" .. margin2 .. s2
   end
end

function Parser:get_help()
   if self._help then
      return self._help
   end

   local blocks = {self:get_usage()}
   
   if self._description then
      table.insert(blocks, self._description)
   end

   local labels = {"Arguments:", "Options:", "Commands:"}

   for i, elements in ipairs{self._arguments, self._options, self._commands} do
      if #elements > 0 then
         local buf = {labels[i]}

         for _, element in ipairs(elements) do
            table.insert(buf, make_two_columns(element:_get_label(), element:_get_description()))
         end

         table.insert(blocks, table.concat(buf, "\n"))
      end
   end

   if self._epilog then
      table.insert(blocks, self._epilog)
   end

   return table.concat(blocks, "\n\n")
end

local function get_tip(context, wrong_name)
   local context_pool = {}
   local possible_name
   local possible_names = {}

   for name in pairs(context) do
      for i=1, #name do
         possible_name = name:sub(1, i-1) .. name:sub(i+1)

         if not context_pool[possible_name] then
            context_pool[possible_name] = {}
         end

         table.insert(context_pool[possible_name], name)
      end
   end

   for i=1, #wrong_name+1 do
      possible_name = wrong_name:sub(1, i-1) .. wrong_name:sub(i+1)

      if context[possible_name] then
         possible_names[possible_name] = true
      elseif context_pool[possible_name] then
         for _, name in ipairs(context_pool[possible_name]) do
            possible_names[name] = true
         end
      end
   end

   local first = next(possible_names)
   if first then
      if next(possible_names, first) then
         local possible_names_arr = {}

         for name in pairs(possible_names) do
            table.insert(possible_names_arr, "'" .. name .. "'")
         end

         table.sort(possible_names_arr)
         return "\nDid you mean one of these: " .. table.concat(possible_names_arr, " ") .. "?"
      else
         return "\nDid you mean '" .. first .. "'?"
      end
   else
      return ""
   end
end

local function plural(x)
   if x == 1 then
      return ""
   end

   return "s"
end

-- Compatibility with strict.lua and other checkers:
local default_cmdline = rawget(_G, "arg") or {}

function Parser:_parse(args, errhandler)
   args = args or default_cmdline
   local parser
   local charset
   local options = {}
   local arguments = {}
   local commands
   local option_mutexes = {}
   local used_mutexes = {}
   local opt_context = {}
   local com_context
   local result = {}
   local invocations = {}
   local passed = {}
   local cur_option
   local cur_arg_i = 1
   local cur_arg
   local targets = {}
   local handle_options = true

   local function error_(fmt, ...)
      return errhandler(parser, fmt:format(...))
   end

   local function assert_(assertion, ...)
      return assertion or error_(...)
   end

   local function convert(element, data)
      if element._convert then
         local ok, err

         if type(element._convert) == "function" then
            ok, err = element._convert(data)
         else
            ok = element._convert[data]
         end

         assert_(ok ~= nil, "%s", err or "malformed argument '" .. data .. "'")
         data = ok
      end

      return data
   end

   local invoke, pass, close

   function invoke(element)
      local overwrite = false

      if invocations[element] == element._maxcount then
         if element._overwrite then
            overwrite = true
         else
            error_("option '%s' must be used at most %d time%s", element._name, element._maxcount, plural(element._maxcount))
         end
      else
         invocations[element] = invocations[element]+1
      end

      passed[element] = 0
      local type_ = element:_get_type()
      local target = targets[element]

      if type_ == "flag" then
         result[target] = true
      elseif type_ == "multiarg" then
         result[target] = {}
      elseif type_ == "counter" then
         if not overwrite then
            result[target] = result[target]+1
         end
      elseif type_ == "multicount" then
         if overwrite then
            table.remove(result[target], 1)
         end
      elseif type_ == "twodimensional" then
         table.insert(result[target], {})

         if overwrite then
            table.remove(result[target], 1)
         end
      end

      if element._maxargs == 0 then
         close(element)
      end
   end

   function pass(element, data)
      passed[element] = passed[element]+1
      data = convert(element, data)
      local type_ = element:_get_type()
      local target = targets[element]

      if type_ == "arg" then
         result[target] = data
      elseif type_ == "multiarg" or type_ == "multicount" then
         table.insert(result[target], data)
      elseif type_ == "twodimensional" then
         table.insert(result[target][#result[target]], data)
      end

      if passed[element] == element._maxargs then
         close(element)
      end
   end

   local function complete_invocation(element)
      while passed[element] < element._minargs do
         pass(element, element._default)
      end
   end

   function close(element)
      if passed[element] < element._minargs then
         if element._default and element._defmode:find "a" then
            complete_invocation(element)
         else
            error_("too few arguments")
         end
      else
         if element == cur_option then
            cur_option = nil
         elseif element == cur_arg then
            cur_arg_i = cur_arg_i+1
            cur_arg = arguments[cur_arg_i]
         end
      end
   end

   local function switch(p)
      parser = p

      for _, option in ipairs(parser._options) do
         table.insert(options, option)

         for _, alias in ipairs(option._aliases) do
            opt_context[alias] = option
         end

         local type_ = option:_get_type()
         targets[option] = option._target or option:_get_default_target()

         if type_ == "counter" then
            result[targets[option]] = 0
         elseif type_ == "multicount" or type_ == "twodimensional" then
            result[targets[option]] = {}
         end

         invocations[option] = 0
      end

      for _, mutex in ipairs(parser._mutexes) do
         for _, option in ipairs(mutex) do
            if not option_mutexes[option] then
               option_mutexes[option] = {mutex}
            else
               table.insert(option_mutexes[option], mutex)
            end
         end
      end

      for _, argument in ipairs(parser._arguments) do
         table.insert(arguments, argument)
         invocations[argument] = 0
         targets[argument] = argument._target or argument._name
         invoke(argument)
      end

      handle_options = parser._handle_options
      cur_arg = arguments[cur_arg_i]
      commands = parser._commands
      com_context = {}

      for _, command in ipairs(commands) do
         targets[command] = command._target or command._name

         for _, alias in ipairs(command._aliases) do
            com_context[alias] = command
         end
      end
   end

   local function get_option(name)
      return assert_(opt_context[name], "unknown option '%s'%s", name, get_tip(opt_context, name))
   end

   local function do_action(element)
      if element._action then
         element._action()
      end
   end

   local function handle_argument(data)
      if cur_option then
         pass(cur_option, data)
      elseif cur_arg then
         pass(cur_arg, data)
      else
         local com = com_context[data]

         if not com then
            if #commands > 0 then
               error_("unknown command '%s'%s", data, get_tip(com_context, data))
            else
               error_("too many arguments")
            end
         else
            result[targets[com]] = true
            do_action(com)
            switch(com)
         end
      end
   end

   local function handle_option(data)
      if cur_option then
         close(cur_option)
      end

      cur_option = opt_context[data]

      if option_mutexes[cur_option] then
         for _, mutex in ipairs(option_mutexes[cur_option]) do
            if used_mutexes[mutex] and used_mutexes[mutex] ~= cur_option then
               error_("option '%s' can not be used together with option '%s'", data, used_mutexes[mutex]._name)
            else
               used_mutexes[mutex] = cur_option
            end
         end
      end

      do_action(cur_option)
      invoke(cur_option)
   end

   local function mainloop()

      for _, data in ipairs(args) do
         local plain = true
         local first, name, option

         if handle_options then
            first = data:sub(1, 1)
            if charset[first] then
               if #data > 1 then
                  plain = false
                  if data:sub(2, 2) == first then
                     if #data == 2 then
                        if cur_option then
                           close(cur_option)
                        end

                        handle_options = false
                     else
                        local equal = data:find "="
                        if equal then
                           name = data:sub(1, equal-1)
                           option = get_option(name)
                           assert_(option._maxargs > 0, "option '%s' does not take arguments", name)

                           handle_option(data:sub(1, equal-1))
                           handle_argument(data:sub(equal+1))
                        else
                           get_option(data)
                           handle_option(data)
                        end
                     end
                  else
                     for i = 2, #data do
                        name = first .. data:sub(i, i)
                        option = get_option(name)
                        handle_option(name)

                        if i ~= #data and option._minargs > 0 then
                           handle_argument(data:sub(i+1))
                           break
                        end
                     end
                  end
               end
            end
         end

         if plain then
            handle_argument(data)
         end
      end
   end

   switch(self)
   charset = parser:_update_charset()
   mainloop()

   if cur_option then
      close(cur_option)
   end

   while cur_arg do
      if passed[cur_arg] == 0 and cur_arg._default and cur_arg._defmode:find "u" then
         complete_invocation(cur_arg)
      else
         close(cur_arg)
      end
   end

   if parser._require_command and #commands > 0 then
      error_("a command is required")
   end

   for _, option in ipairs(options) do
      if invocations[option] == 0 then
         if option._default and option._defmode:find "u" then
            invoke(option)
            complete_invocation(option)
            close(option)
         end
      end

      if invocations[option] < option._mincount then
         if option._default and option._defmode:find "a" then
            while invocations[option] < option._mincount do
               invoke(option)
               close(option)
            end
         else
            error_("option '%s' must be used at least %d time%s", option._name, option._mincount, plural(option._mincount))
         end
      end
   end

   return result
end

function Parser:error(msg)
   io.stderr:write(("%s\n\nError: %s\n"):format(self:get_usage(), msg))
   os.exit(1)
end

function Parser:parse(args)
   return self:_parse(args, Parser.error)
end

function Parser:pparse(args)
   local errmsg
   local ok, result = pcall(function()
      return self:_parse(args, function(_, err)
         errmsg = err
         return error()
      end)
   end)

   if ok then
      return true, result
   else
      assert(errmsg, result)
      return false, errmsg
   end
end

return function(...)
   return Parser(default_cmdline[0]):add_help(true)(...)
end
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck.cache"])sources["luacheck.cache"]=([===[-- <pack luacheck.cache> --
local utils = require "luacheck.utils"

local cache = {}

-- Cache file contains check results for n unique filenames.
-- Cache file consists of 3n+2 lines, the first line is empty and the second is cache format version.
-- The rest are contain file records, 3 lines per file.
-- For each file, first line is the filename, second is modification time,
-- third is check result in lua table format.
-- String fields are compressed into array indexes.

cache.format_version = 1

local fields = {
   "code", "name", "line", "column", "end_column", "prev_line", "prev_column", "secondary",
   "self", "func", "filtered", "top", "read_only", "global", "filtered_111", "filtered_121",
   "filtered_131", "filtered_112", "filtered_122", "filtered_113","definition", "in_module", "msg"
}

-- Converts table with fields into table with indexes.
local function compress(t)
   local res = {}

   for index, field in ipairs(fields) do
      res[index] = t[field]
   end

   return res
end

local function get_local_name(index)
   return string.char(index + (index > 26 and 70 or 64))
end

-- Serializes event into buffer.
-- strings is a table mapping string values to where they first occured or to name of local
-- variable used to represent it.
-- Array part contains representations of values saved into locals.
local function serialize_event(buffer, strings, event)
   event = compress(event)
   table.insert(buffer, "{")
   local is_sparse
   local put_one

   for i = 1, #fields do
      local value = event[i]

      if not value then
         is_sparse = true
      else
         if put_one then
            table.insert(buffer, ",")
         end

         put_one = true

         if is_sparse then
            table.insert(buffer, ("[%d]="):format(i))
         end

         if type(value) == "string" then
            local prev = strings[value]

            if type(prev) == "string" then
               -- There is a local with such value.
               table.insert(buffer, prev)
            elseif type(prev) == "number" and #strings < 52 then
               -- Value is used second time, put it into a local.
               table.insert(strings, ("%q"):format(value))
               local local_name = get_local_name(#strings)
               buffer[prev] = local_name
               table.insert(buffer, local_name)
               strings[value] = local_name
            else
               table.insert(buffer, ("%q"):format(value))
               strings[value] = #buffer
            end
         else
            table.insert(buffer, tostring(value))
         end
      end
   end

   table.insert(buffer, "}")
end

-- Serializes check result into a string.
function cache.serialize(events)
   local strings = {}
   local buffer = {"", "return {"}

   for i, event in ipairs(events) do
      if i > 1 then
         table.insert(buffer, ",")
      end

      serialize_event(buffer, strings, event)
   end

   table.insert(buffer, "}")

   if strings[1] then
      local names = {}

      for index in ipairs(strings) do
         table.insert(names, get_local_name(index))
      end

      buffer[1] = "local " .. table.concat(names, ",") .. "=" .. table.concat(strings, ",") .. ";"
   end

   return table.concat(buffer)
end

-- Returns array of triplets of lines from cache fh.
local function read_triplets(fh)
   local res = {}

   while true do
      local filename = fh:read()

      if filename then
         local mtime = fh:read() or ""
         local cached = fh:read() or ""
         table.insert(res, {filename, mtime, cached})
      else
         break
      end
   end

   return res
end

-- Writes cache triplets into fh.
local function write_triplets(fh, triplets)
   for _, triplet in ipairs(triplets) do
      fh:write(triplet[1], "\n")
      fh:write(triplet[2], "\n")
      fh:write(triplet[3], "\n")
   end
end

-- Converts table with indexes into table with fields.
local function decompress(t)
   local res = {}

   for index, field in ipairs(fields) do
      res[field] = t[index]
   end

   return res
end

-- Loads cached results from string, returns results or nil.
local function load_cached(cached)
   local func = utils.load(cached, {})

   if not func then
      return
   end

   local ok, res = pcall(func)

   if not ok then
      return
   end

   if type(res) ~= "table" then
      return
   end

   local decompressed = {}

   for i, event in ipairs(res) do
      if type(event) ~= "table" then
         return
      end

      decompressed[i] = decompress(event)
   end

   return decompressed
end

local function check_version_header(fh)
   return fh:read() == "" and tonumber(fh:read()) == cache.format_version
end

local function write_version_header(fh)
   fh:write("\n", tostring(cache.format_version), "\n")
end

-- Loads cache for filenames given mtimes from cache cache_filename.
-- Returns table mapping filenames to cached check results.
-- On corrupted cache returns nil, on version mismatch returns {}.
function cache.load(cache_filename, filenames, mtimes)
   local fh = io.open(cache_filename, "rb")

   if not fh then
      return {}
   end

   if not check_version_header(fh) then
      fh:close()
      return {}
   end

   local result = {}
   local not_yet_found = utils.array_to_set(filenames)

   while next(not_yet_found) do
      local filename = fh:read()

      if not filename then
         fh:close()
         return result
      end

      local mtime = fh:read()
      local cached = fh:read()

      if not mtime or not cached then
         fh:close()
         return
      end

      mtime = tonumber(mtime)

      if not mtime then
         fh:close()
         return
      end

      if not_yet_found[filename] then
         if mtimes[not_yet_found[filename]] == mtime then
            result[filename] = load_cached(cached)

            if result[filename] == nil then
               fh:close()
               return
            end
         end

         not_yet_found[filename] = nil
      end
   end

   fh:close()
   return result
end

-- Updates cache at cache_filename with results for filenames.
-- Returns success flag + whether update was append-only.
function cache.update(cache_filename, filenames, mtimes, results)
   local old_triplets = {}
   local can_append = false
   local fh = io.open(cache_filename, "rb")

   if fh then
      if check_version_header(fh) then
         old_triplets = read_triplets(fh)
         can_append = true
      end

      fh:close()
   end

   local filename_set = utils.array_to_set(filenames)
   local old_filename_set = {}

   -- Update old cache for files which got a new result.
   for i, triplet in ipairs(old_triplets) do
      old_filename_set[triplet[1]] = true
      local file_index = filename_set[triplet[1]]

      if file_index then
         can_append = false
         old_triplets[i][2] = mtimes[file_index]
         old_triplets[i][3] = cache.serialize(results[file_index])
      end
   end

   local new_triplets = {}

   for _, filename in ipairs(filenames) do
      -- Use unique index (there could be duplicate filenames).
      local file_index = filename_set[filename]

      if file_index and not old_filename_set[filename] then
         table.insert(new_triplets, {
            filename,
            mtimes[file_index],
            cache.serialize(results[file_index])
         })
         -- Do not save result for this filename again.
         filename_set[filename] = nil
      end
   end

   if can_append then
      if #new_triplets > 0 then
         fh = io.open(cache_filename, "ab")

         if not fh then
            return false
         end

         write_triplets(fh, new_triplets)
         fh:close()
      end
   else
      fh = io.open(cache_filename, "wb")

      if not fh then
         return false
      end

      write_version_header(fh)
      write_triplets(fh, old_triplets)
      write_triplets(fh, new_triplets)
      fh:close()
   end

   return true, can_append
end

return cache
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["luacheck"])sources["luacheck"]=([===[-- <pack luacheck> --
local check = require "luacheck.check"
local filter = require "luacheck.filter"
local options = require "luacheck.options"
local format = require "luacheck.format"
local utils = require "luacheck.utils"

local luacheck = {
   _VERSION = "0.11.1"
}

local function raw_validate_options(fname, opts)
   assert(opts == nil or type(opts) == "table",
      ("bad argument #2 to '%s' (table or nil expected, got %s)"):format(fname, type(opts))
   )

   local ok, invalid_field = options.validate(options.all_options, opts)

   if not ok then
      if invalid_field then
         error(("bad argument #2 to '%s' (invalid value of option '%s')"):format(fname, invalid_field))
      else
         error(("bad argument #2 to '%s'"):format(fname))
      end
   end
end

local function validate_options(fname, items, opts)
   raw_validate_options(fname, opts)

   if opts ~= nil then
      for i in ipairs(items) do
         raw_validate_options(fname, opts[i])

         if opts[i] ~= nil then
            for _, nested_opts in ipairs(opts[i]) do
               raw_validate_options(fname, nested_opts)
            end
         end
      end
   end
end

-- Returns report for a string. Report is an array of warnings and errors.
function luacheck.get_report(src)
   assert(type(src) == "string", ("bad argument #1 to 'luacheck.get_report' (string expected, got %s)"):format(type(src)))
   return check(src)
end

-- Applies options to reports. Reports with .fatal field are unchanged.
-- Options are applied to reports[i] in order: options, options[i], options[i][1], options[i][2], ...
-- Returns new array of reports, adds .warnings, .errors and .fatals fields to this array.
function luacheck.process_reports(reports, opts)
   assert(type(reports) == "table", ("bad argument #1 to 'luacheck.process_reports' (table expected, got %s)"):format(type(reports)))
   validate_options("luacheck.process_reports", reports, opts)
   local report = filter.filter(reports, opts)
   report.warnings = 0
   report.errors = 0
   report.fatals = 0

   for _, file_report in ipairs(report) do
      if file_report.fatal then
         report.fatals = report.fatals + 1
      else
         for _, event in ipairs(file_report) do
            if event.code:sub(1, 1) == "0" then
               report.errors = report.errors + 1
            else
               report.warnings = report.warnings + 1
            end
         end
      end
   end

   return report
end

-- Checks strings with options, returns report.
-- Tables with .fatal field are unchanged.
function luacheck.check_strings(srcs, opts)
   assert(type(srcs) == "table", ("bad argument #1 to 'luacheck.check_strings' (table expected, got %s)"):format(type(srcs)))

   for _, item in ipairs(srcs) do
      assert(type(item) == "string" or type(item) == "table", (
         "bad argument #1 to 'luacheck.check_strings' (array of strings or tables expected, got %s)"):format(type(item))
      )
   end

   validate_options("luacheck.check_strings", srcs, opts)

   local reports = {}

   for i, src in ipairs(srcs) do
      if type(src) == "table" and src.fatal then
         reports[i] = src
      else
         reports[i] = luacheck.get_report(src)
      end
   end

   return luacheck.process_reports(reports, opts)
end

function luacheck.check_files(files, opts)
   assert(type(files) == "table", ("bad argument #1 to 'luacheck.check_files' (table expected, got %s)"):format(type(files)))

   for _, item in ipairs(files) do
      assert(type(item) == "string" or io.type(item) == "file", (
         "bad argument #1 to 'luacheck.check_files' (array of paths or file handles expected, got %s)"):format(type(item))
      )
   end

   validate_options("luacheck.check_files", files, opts)

   local srcs = {}

   for i, file in ipairs(files) do
      srcs[i] = utils.read_file(file) or {fatal = "I/O"}
   end

   return luacheck.check_strings(srcs, opts)
end

function luacheck.get_message(issue)
   assert(type(issue) == "table", ("bad argument #1 to 'luacheck.get_message' (table expected, got %s)"):format(type(issue)))
   return format.get_message(issue)
end

setmetatable(luacheck, {__call = function(_, ...)
   return luacheck.check_files(...)
end})

return luacheck
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
local add
if not pcall(function() add = require"aioruntime".add end) then
        local loadstring=_G.loadstring or _G.load; local preload = require"package".preload
        add = function(name, rawcode)
		if not preload[name] then
		        preload[name] = function(...) return assert(loadstring(rawcode), "loadstring: "..name.." failed")(...) end
		else
			print("WARNING: overwrite "..name)
		end
        end
end
for name, rawcode in pairs(sources) do add(name, rawcode, priorities[name]) end
end;
require "luacheck.main"
