# Helper Functions · Helper 函数

在 `linux/bpf.h` 头文件中，每一个 helper function 都定义了一个枚举值。

``` c
#define __BPF_FUNC_MAPPER(FN)		\
	FN(unspec),			\
	FN(map_lookup_elem),		\
	FN(map_update_elem),		\
	FN(map_delete_elem),		\
	FN(probe_read),			\
	FN(ktime_get_ns),		\
	FN(trace_printk),		\
	FN(get_prandom_u32),		\
	FN(get_smp_processor_id),	\
	FN(skb_store_bytes),		\
	FN(l3_csum_replace),		\
	FN(l4_csum_replace),		\
	FN(tail_call),			\
	FN(clone_redirect),		\
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),		\
	FN(sock_ops_cb_flags_set),	\
	FN(msg_redirect_map),		\
	FN(msg_apply_bytes),		\
	FN(msg_cork_bytes),		\
	FN(msg_pull_data),		\
	FN(bind),			\
	FN(xdp_adjust_tail),		\
	FN(skb_get_xfrm_state),		\
	FN(get_stack),			\
	FN(skb_load_bytes_relative),	\
	FN(fib_lookup),			\
	FN(sock_hash_update),		\
	FN(msg_redirect_hash),		\
	FN(sk_redirect_hash),		\
	FN(lwt_push_encap),		\
	FN(lwt_seg6_store_bytes),	\
	FN(lwt_seg6_adjust_srh),	\
	FN(lwt_seg6_action),		\
	FN(rc_repeat),			\
	FN(rc_keydown),			\
	FN(skb_cgroup_id),		\
	FN(get_current_cgroup_id),	\
	FN(get_local_storage),		\
	FN(sk_select_reuseport),	\
	FN(skb_ancestor_cgroup_id),	\
	FN(sk_lookup_tcp),		\
	FN(sk_lookup_udp),		\
	FN(sk_release),			\
	FN(map_push_elem),		\
	FN(map_pop_elem),		\
	FN(map_peek_elem),		\
	FN(msg_push_data),		\
	FN(msg_pop_data),		\
	FN(rc_pointer_rel),		\
	FN(spin_lock),			\
	FN(spin_unlock),		\
	FN(sk_fullsock),		\
	FN(tcp_sock),			\
	FN(skb_ecn_set_ce),		\
	FN(get_listener_sock),		\
	FN(skc_lookup_tcp),		\
	FN(tcp_check_syncookie),	\
	FN(sysctl_get_name),		\
	FN(sysctl_get_current_value),	\
	FN(sysctl_get_new_value),	\
	FN(sysctl_set_new_value),	\
	FN(strtol),			\
	FN(strtoul),			\
	FN(sk_storage_get),		\
	FN(sk_storage_delete),		\
	FN(send_signal),		\
	FN(tcp_gen_syncookie),		\
	FN(skb_output),			\
	FN(probe_read_user),		\
	FN(probe_read_kernel),		\
	FN(probe_read_user_str),	\
	FN(probe_read_kernel_str),	\
	FN(tcp_send_ack),		\
	FN(send_signal_thread),		\
	FN(jiffies64),			\
	FN(read_branch_records),	\
	FN(get_ns_current_pid_tgid),	\
	FN(xdp_output),			\
	FN(get_netns_cookie),		\
	FN(get_current_ancestor_cgroup_id),	\
	FN(sk_assign),			\
	FN(ktime_get_boot_ns),		\
	FN(seq_printf),			\
	FN(seq_write),			\
	FN(sk_cgroup_id),		\
	FN(sk_ancestor_cgroup_id),	\
	FN(ringbuf_output),		\
	FN(ringbuf_reserve),		\
	FN(ringbuf_submit),		\
	FN(ringbuf_discard),		\
	FN(ringbuf_query),		\
	FN(csum_level),			\
	FN(skc_to_tcp6_sock),		\
	FN(skc_to_tcp_sock),		\
	FN(skc_to_tcp_timewait_sock),	\
	FN(skc_to_tcp_request_sock),	\
	FN(skc_to_udp6_sock),		\
	FN(get_task_stack),		\
	FN(load_hdr_opt),		\
	FN(store_hdr_opt),		\
	FN(reserve_hdr_opt),		\
	FN(inode_storage_get),		\
	FN(inode_storage_delete),	\
	FN(d_path),			\
	FN(copy_from_user),		\
	FN(snprintf_btf),		\
	FN(seq_printf_btf),		\
	FN(skb_cgroup_classid),		\
	FN(redirect_neigh),		\
	FN(per_cpu_ptr),		\
	FN(this_cpu_ptr),		\
	FN(redirect_peer),		\
	FN(task_storage_get),		\
	FN(task_storage_delete),	\
	FN(get_current_task_btf),	\
	FN(bprm_opts_set),		\
	FN(ktime_get_coarse_ns),	\
	FN(ima_inode_hash),		\
	FN(sock_from_file),		\
	FN(check_mtu),			\
	FN(for_each_map_elem),		\
	FN(snprintf),			\
	FN(sys_bpf),			\
	FN(btf_find_by_name_kind),	\
	FN(sys_close),			\
	FN(timer_init),			\
	FN(timer_set_callback),		\
	FN(timer_start),		\
	FN(timer_cancel),		\
	FN(get_func_ip),		\
	FN(get_attach_cookie),		\
	FN(task_pt_regs),		\
	FN(get_branch_snapshot),	\
	FN(trace_vprintk),		\
	FN(skc_to_unix_sock),		\
	FN(kallsyms_lookup_name),	\
	FN(find_vma),			\
	FN(loop),			\
	FN(strncmp),			\
	FN(get_func_arg),		\
	FN(get_func_ret),		\
	FN(get_func_arg_cnt),		\
	FN(get_retval),			\
	FN(set_retval),			\
	FN(xdp_get_buff_len),		\
	FN(xdp_load_bytes),		\
	FN(xdp_store_bytes),		\
	FN(copy_from_user_task),	\
	FN(skb_set_tstamp),		\
	FN(ima_file_hash),		\
	FN(kptr_xchg),			\
	FN(map_lookup_percpu_elem),     \
	FN(skc_to_mptcp_sock),		\
	FN(dynptr_from_mem),		\
	FN(ringbuf_reserve_dynptr),	\
	FN(ringbuf_submit_dynptr),	\
	FN(ringbuf_discard_dynptr),	\
	FN(dynptr_read),		\
	FN(dynptr_write),		\
	FN(dynptr_data),		\
	/* */

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
enum bpf_func_id {
	__BPF_FUNC_MAPPER(__BPF_ENUM_FN)
	__BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN
```

整理为如下表格：

|||
|-|-|
|0|unspec|
|1|map_lookup_elem|
|2|map_update_elem|
|3|map_delete_elem|
|4|probe_read|
|5|ktime_get_ns|
|6|trace_printk|
|7|get_prandom_u32|
|8|get_smp_processor_id|
|9|skb_store_bytes|
|10|l3_csum_replace|
|11|l4_csum_replace|
|12|tail_call|
|13|clone_redirect|
|14|get_current_pid_tgid|
|15|get_current_uid_gid|
|16|get_current_comm|
|17|get_cgroup_classid|
|18|skb_vlan_push|
|19|skb_vlan_pop|
|20|skb_get_tunnel_key|
|21|skb_set_tunnel_key|
|22|perf_event_read|
|23|redirect|
|24|get_route_realm|
|25|perf_event_output|
|26|skb_load_bytes|
|27|get_stackid|
|28|csum_diff|
|29|skb_get_tunnel_opt|
|30|skb_set_tunnel_opt|
|31|skb_change_proto|
|32|skb_change_type|
|33|skb_under_cgroup|
|34|get_hash_recalc|
|35|get_current_task|
|36|probe_write_user|
|37|current_task_under_cgroup|
|38|skb_change_tail|
|39|skb_pull_data|
|40|csum_update|
|41|set_hash_invalid|
|42|get_numa_node_id|
|43|skb_change_head|
|44|xdp_adjust_head|
|45|probe_read_str|
|46|get_socket_cookie|
|47|get_socket_uid|
|48|set_hash|
|49|setsockopt|
|50|skb_adjust_room|
|51|redirect_map|
|52|sk_redirect_map|
|53|sock_map_update|
|54|xdp_adjust_meta|
|55|perf_event_read_value|
|56|perf_prog_read_value|
|57|getsockopt|
|58|override_return|
|59|sock_ops_cb_flags_set|
|60|msg_redirect_map|
|61|msg_apply_bytes|
|62|msg_cork_bytes|
|63|msg_pull_data|
|64|bind|
|65|xdp_adjust_tail|
|66|skb_get_xfrm_state|
|67|get_stack|
|68|skb_load_bytes_relative|
|69|fib_lookup|
|70|sock_hash_update|
|71|msg_redirect_hash|
|72|sk_redirect_hash|
|73|lwt_push_encap|
|74|lwt_seg6_store_bytes|
|75|lwt_seg6_adjust_srh|
|76|lwt_seg6_action|
|77|rc_repeat|
|78|rc_keydown|
|79|skb_cgroup_id|
|80|get_current_cgroup_id|
|81|get_local_storage|
|82|sk_select_reuseport|
|83|skb_ancestor_cgroup_id|
|84|sk_lookup_tcp|
|85|sk_lookup_udp|
|86|sk_release|
|87|map_push_elem|
|88|map_pop_elem|
|89|map_peek_elem|
|90|msg_push_data|
|91|msg_pop_data|
|92|rc_pointer_rel|
|93|spin_lock|
|94|spin_unlock|
|95|sk_fullsock|
|96|tcp_sock|
|97|skb_ecn_set_ce|
|98|get_listener_sock|
|99|skc_lookup_tcp|
|100|tcp_check_syncookie|
|101|sysctl_get_name|
|102|sysctl_get_current_value|
|103|sysctl_get_new_value|
|104|sysctl_set_new_value|
|105|strtol|
|106|strtoul|
|107|sk_storage_get|
|108|sk_storage_delete|
|109|send_signal|
|110|tcp_gen_syncookie|
|111|skb_output|
|112|probe_read_user|
|113|probe_read_kernel|
|114|probe_read_user_str|
|115|probe_read_kernel_str|
|116|tcp_send_ack|
|117|send_signal_thread|
|118|jiffies64|
|119|read_branch_records|
|120|get_ns_current_pid_tgid|
|121|xdp_output|
|122|get_netns_cookie|
|123|get_current_ancestor_cgroup_id|
|124|sk_assign|
|125|ktime_get_boot_ns|
|126|seq_printf|
|127|seq_write|
|128|sk_cgroup_id|
|129|sk_ancestor_cgroup_id|
|130|ringbuf_output|
|131|ringbuf_reserve|
|132|ringbuf_submit|
|133|ringbuf_discard|
|134|ringbuf_query|
|135|csum_level|
|136|skc_to_tcp6_sock|
|137|skc_to_tcp_sock|
|138|skc_to_tcp_timewait_sock|
|139|skc_to_tcp_request_sock|
|140|skc_to_udp6_sock|
|141|get_task_stack|
|142|load_hdr_opt|
|143|store_hdr_opt|
|144|reserve_hdr_opt|
|145|inode_storage_get|
|146|inode_storage_delete|
|147|d_path|
|148|copy_from_user|
|149|snprintf_btf|
|150|seq_printf_btf|
|151|skb_cgroup_classid|
|152|redirect_neigh|
|153|per_cpu_ptr|
|154|this_cpu_ptr|
|155|redirect_peer|
|156|task_storage_get|
|157|task_storage_delete|
|158|get_current_task_btf|
|159|bprm_opts_set|
|160|ktime_get_coarse_ns|
|161|ima_inode_hash|
|162|sock_from_file|
|163|check_mtu|
|164|for_each_map_elem|
|165|snprintf|
|166|sys_bpf|
|167|btf_find_by_name_kind|
|168|sys_close|
|169|timer_init|
|170|timer_set_callback|
|171|timer_start|
|172|timer_cancel|
|173|get_func_ip|
|174|get_attach_cookie|
|175|task_pt_regs|
|176|get_branch_snapshot|
|177|trace_vprintk|
|178|skc_to_unix_sock|
|179|kallsyms_lookup_name|
|180|find_vma|
|181|loop|
|182|strncmp|
|183|get_func_arg|
|184|get_func_ret|
|185|get_func_arg_cnt|
|186|get_retval|
|187|set_retval|
|188|xdp_get_buff_len|
|189|xdp_load_bytes|
|190|xdp_store_bytes|
|191|copy_from_user_task|
|192|skb_set_tstamp|
|193|ima_file_hash|
|194|kptr_xchg|
|195|map_lookup_percpu_elem|
|196|skc_to_mptcp_sock|
|197|dynptr_from_mem|
|198|ringbuf_reserve_dynptr|
|199|ringbuf_submit_dynptr|
|200|ringbuf_discard_dynptr|
|201|dynptr_read|
|202|dynptr_write|
|203|dynptr_data|
