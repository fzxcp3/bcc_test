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

BPF_PERF_OUTPUT(events);

struct exec_data_t{
    char datatype[20];
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char argv1[128];
    char argv2[128];
    char argv3[128];
    char argv4[128];
    char argv5[128];
    char argv6[128];
    char argv7[128];
    char argv8[128];
    char argv9[128];    
};


static int mystrlen(const char *str)
{
	int len;
    for(len=0;*str!=0;str++){
        len++;
    }
    return len;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct exec_data_t data = {};
    struct task_struct *task;
    strcpy(data.datatype,"exec");
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    char temp[100];
    bpf_probe_read(data.argv, sizeof(data.argv), (void *)filename);

    const char *argp;

    argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), (void *)&__argv[0]);
    if(argp){
        bpf_probe_read(data.argv0, sizeof(data.argv0), (void *)argp);
    }



    events.perf_submit(ctx, &data, sizeof(struct exec_data_t));
    return 0;
out:
    events.perf_submit(ctx, &data, sizeof(struct exec_data_t));
    return 0;
}

"""




bpf_text = bpf_text.replace("MAXARG", "20")
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(event.argv0)


b["events"].open_perf_buffer(print_event,page_cnt=512)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()



