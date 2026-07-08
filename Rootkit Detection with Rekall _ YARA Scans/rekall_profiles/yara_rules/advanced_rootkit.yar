rule Network_Rootkit
{
    meta:
        description = "Network-based rootkit indicators"
        
    strings:
        $net1 = "netfilter_ops"
        $net2 = "packet_type"
        $net3 = "sk_buff"
        $hide = "NF_STOLEN"
        
    condition:
        2 of ($net*) and $hide
}

rule File_Hiding_Rootkit
{
    meta:
        description = "File system hiding rootkit"
        
    strings:
        $vfs1 = "vfs_readdir"
        $vfs2 = "filldir"
        $hide = "d_name"
        
    condition:
        all of them
}
