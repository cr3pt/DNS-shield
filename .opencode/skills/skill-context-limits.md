# CRITICAL RULE: CONTEXT LIMITS & FILE READING
You are FORBIDDEN from reading entire source files.
1. NEVER use generic "read file" commands without constraints.
2. FIRST, use `grep` or AST search tools to locate exact line numbers of the target methods, structs, or packet handlers.
3. SECOND, use file reading tools ONLY with explicit `start_line` and `end_line` parameters.
4. Read maximum 100-150 lines per request.
5. Execute the precise chunked read immediately without narrating your plan.
