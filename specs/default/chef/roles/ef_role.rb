name "ef_role"
description "Configure EF"
run_list("recipe[ef::nat]", "recipe[ef::dcv_licserv]")
