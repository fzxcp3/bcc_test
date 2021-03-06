from __future__ import print_function
from bcc import BPF
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import ctypes as ct
import re
import time
from collections import defaultdict
from struct import pack
from socket import inet_ntop, ntohs, AF_INET, AF_INET6



bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/fs.h>
#include <bcc/proto.h>
#include <uapi/linux/limits.h>


#define ARGSIZE  128
enum event_type {
    EVENT_ARG,
    EVENT_RET,
};
struct exec_data_t{
    char datatype[20];
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

struct connect_data_t{
    char datatype[20];
    u32 pid;
    u32 uid;
    int retval;
    u32 saddr;
    u32 daddr;
    u16 dport;
    char comm[TASK_COMM_LEN];
    unsigned __int128 saddr_6;
    unsigned __int128 daddr_6;
};

struct open_data_t{
    char datatype[20];
    u32 pid;
    u32 uid;
    int retval;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    int flags;
};


struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags;
};


BPF_PERF_OUTPUT(events);


static int __submit_arg(struct pt_regs *ctx, void *ptr, struct exec_data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct exec_data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct exec_data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct exec_data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;
    __submit_arg(ctx, (void *)filename, &data);
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

BPF_HASH(currsock, u32, struct sock *);


int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    currsock.update(&tid, &sk);
    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    struct connect_data_t data = {};
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;
    }
    if (ret != 0) {
        currsock.delete(&tid);
        return 0;
    }
    struct sock *skp = *skpp;
    u16 dport = skp->__sk_common.skc_dport;

    if (ipver == 4) {
        data.pid = pid;
        data.retval = ret;
        data.uid = bpf_get_current_uid_gid();
        data.saddr = skp->__sk_common.skc_rcv_saddr;
        data.daddr = skp->__sk_common.skc_daddr;
        data.dport = ntohs(dport);
        strcpy(data.datatype,"connect_v4");
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
    } else {
        data.pid = pid;
        data.retval = ret;
        data.uid = bpf_get_current_uid_gid();
        bpf_probe_read(&data.saddr_6, sizeof(data.saddr_6),skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data.daddr_6, sizeof(data.daddr_6),skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data.dport = ntohs(dport);
        strcpy(data.datatype,"connect_v6");
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
    }
    currsock.delete(&tid);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}
int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}


BPF_HASH(infotmp, u64, struct val_t);


int open_trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    u32 uid = bpf_get_current_uid_gid();
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }
    return 0;
};


int open_trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct open_data_t data = {};
    valp = infotmp.lookup(&id);
    if (valp == 0) {
        return 0;
    }
    strcpy(data.datatype,"open");
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.pid = valp->id >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}


"""
bpf_text = bpf_text.replace("MAXARG", "20")
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")



b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")


b.attach_kprobe(event="do_sys_open", fn_name="open_trace_entry")
b.attach_kretprobe(event="do_sys_open", fn_name="open_trace_return")




print("%-8s" % ("TIME(s)"), end="")
print("%-16s %-6s %-6s %3s %s" % ("PCOMM", "PID", "PPID", "RET", "ARGS"))
TASK_COMM_LEN = 16      # linux/sched.h
ARGSIZE = 128           # should match #define in C above


def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0
def print_event(cpu, data, size):
    event = b["events"].event(data)
    '''
    if event.datatype == "connect_v4":
        print(inet_ntop(AF_INET, pack('I', event.saddr)),inet_ntop(AF_INET, pack('I', event.daddr)),event.dport,event.comm,event.pid)
    if event.datatype == "connect_v6":
        print(inet_ntop(AF_INET6, pack('I', event.saddr_6)).encode(),inet_ntop(AF_INET6, pack('I', event.daddr_6)).encode(),event.dport,event.comm,event.pid)
    '''
    if event.datatype == "open":
        print(event.comm,event.fname,event.flag)



b["events"].open_perf_buffer(print_event,page_cnt=512)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


