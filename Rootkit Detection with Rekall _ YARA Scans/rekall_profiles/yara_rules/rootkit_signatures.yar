rule Generic_Rootkit_Strings
{
    meta:
        description = "Generic rootkit string patterns"
        author = "Lab Exercise"
        
    strings:
        $hide1 = "hide_process"
        $hide2 = "rootkit"
        $hide3 = "backdoor"
        $syscall1 = "sys_call_table"
        $syscall2 = "original_sys_"
        $hook1 = "hook_"
        $hook2 = "unhook_"
        
    condition:
        any of them
}

rule Kernel_Module_Rootkit
{
    meta:
        description = "Suspicious kernel module patterns"
        
    strings:
        $mod1 = "init_module"
        $mod2 = "cleanup_module"
        $hide = { 48 89 ?? ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? }
        
    condition:
        all of ($mod*) and $hide
}

rule Process_Hiding_Rootkit
{
    meta:
        description = "Process hiding techniques"
        
    strings:
        $proc1 = "/proc/"
        $proc2 = "task_struct"
        $hide = "list_del"
        
    condition:
        all of them
}
