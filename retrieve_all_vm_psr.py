#!/home/zhouheng/anaconda3/bin/python
# -*- encoding: utf-8 -*-
'''
@文件    :retrieve_all_vm_psr.py
@时间    :2024/08/19 15:10:46
@作者    :周恒
@版本    :1.0
@说明    :
'''

import signal
import time
from typing import *
from subprocess import Popen, PIPE
import json
from bs4 import BeautifulSoup, Tag
import threading
from collections import OrderedDict
import threading

ALL_VM_NAMES_CMD = "virsh list --name --state-running"
PSR_CMD_TEMPLATE = r"ps -mo pid,tid,%cpu,psr -p {pid}"
MEM_NUMA_STAT_CMD = "numastat -c qemu-kvm"
# MEM_NUMA_STAT_CMD = "numastat -c qemu-sys"
CPU_NUMA_STAT_CMD = "numactl -H"
# ALL_VM_NAMES = ["bclinux-{}".format(i) for i in range(1, 29)] + [
#     "bclinux_{}".format(i) for i in range(1, 29)
# ]

NEED_STOP_FALG = False

def signal_handler(signum,frame):
    if signum == signal.SIGTERM:
        NEED_STOP_FALG = True

signal.signal(signal.SIGTERM,signal_handler)

def get_all_vm_names():
    p = Popen(ALL_VM_NAMES_CMD.split(), stdout=PIPE)
    p.wait()
    p_output = p.stdout.read().decode()
    res:List[str]=[]
    lines=p_output.splitlines()
    for line in lines:
        name = line.strip()
        if len(name) > 0:
            res.append(name)
    return res
    
def get_all_cpu_numa_info():
    p = Popen(CPU_NUMA_STAT_CMD.split(), stdout=PIPE)
    p.wait()
    p_output = p.stdout.read().decode()
    cpu_to_node_idx: Dict[int, int] = {}
    node_distances: List[List[int]] = []
    lines = p_output.splitlines()
    """['available:', '8', 'nodes', '(0-7)']"""
    numa_count = int(lines[0].split()[1])
    node_distances = [[-1 for i in range(numa_count)] for j in range(numa_count)]
    for line in lines:
        if not "cpus" in line:
            continue
        """node 1 cpus: 8 9 10 11 12 13 14 15 72 73 74 75 76 77 78 79"""
        splited = line.split()
        """['node', '1', 'cpus:', '8', '9', '10', '11', '12', '13', '14', '15', '72', '73', '74', '75', '76', '77', '78', '79']"""
        node_idx = int(splited[1])
        i = 3
        while i < len(splited):
            cpu_idx = int(splited[i])
            cpu_to_node_idx[cpu_idx] = node_idx
            i += 1
    for i in range(len(lines)):
        if "distances" in lines[i]:
            break
    i += 2
    """
node   0   1   2   3   4   5   6   7
  0:  10  16  16  16  28  28  22  28
  1:  16  10  16  16  28  28  28  22
  2:  16  16  10  16  22  28  28  28
  3:  16  16  16  10  28  22  28  28
  4:  28  28  22  28  10  16  16  16
  5:  28  28  28  22  16  10  16  16
  6:  22  28  28  28  16  16  10  16
  7:  28  22  28  28  16  16  16  10
    """
    for j in range(numa_count):
        line = lines[i + j]
        splited = line.strip().split()
        """['0:', '10', '16', '16', '16', '28', '28', '22', '28']"""
        for k in range(numa_count):
            distance = int(splited[1 + k])
            node_distances[j][k] = distance
    return cpu_to_node_idx, node_distances


def get_all_vm_mem_numa_info():
    p = Popen(MEM_NUMA_STAT_CMD.split(), stdout=PIPE)
    p.wait()
    p_output = p.stdout.read().decode()
    """
Per-node process memory usage (in MBs)
PID              Node 0 Node 1 Node 2 Node 3 Node 4 Node 5 Node 6 Node 7  Total
---------------  ------ ------ ------ ------ ------ ------ ------ ------ ------
4440 (qemu-kvm)     175      0      3      9   3205    832      1      2   4226
4550 (qemu-kvm)    3437      0     15      0      2     44    648     82   4228
    """
    all_vm_mem_numa: Dict[int, Dict[str, Union[List[int], int]]] = {}
    lines = p_output.splitlines()
    line = ""
    i = 0
    while True:
        if line.startswith("PID"):
            break
        i += 1
        line = lines[i]
    i += 2
    line = lines[i]
    while True:
        if line.startswith("-"):
            break
        splited = line.strip().split()
        pid = int(splited[0])
        pid_total = int(splited[-1])
        pid_numa_data: Dict[str, Union[List[int], int]] = {
            "per_node": [],
            "total": pid_total,
        }
        j = 2
        while j < len(splited) - 1:
            pid_numa_data["per_node"].append(int(splited[j]))
            j += 1
        all_vm_mem_numa[pid] = pid_numa_data
        i += 1
        line = lines[i]

    return all_vm_mem_numa


class VmVcpuInfo(object):

    def __init__(self, vm_name: str) -> None:
        self.name: str = vm_name
        self.pid: int = 0
        self.vcpu_pids: List[int] = []
        
        self.vm_mem_numa: Dict[str, Union[List[int], int]] = None
        self.cpu_node_assigned_record: List[List[int]] = []
        self.cpu_memory_access_average_overhead: List[float] = []
        self.vcpu_average_overhead_record: List[List[float]] = []
        self.main_mem_node=-1
        self.cpu_to_numa_node:Dict[int, int]=[]
    def init(
        self,
        all_vm_mem_numa: Dict[int, Dict[str, Union[List[int], int]]],
        cpu_to_node_idx: Dict[int, int],
        node_distances: List[List[int]],
    ):
        self.cpu_to_numa_node = cpu_to_node_idx
        vm_xml = None
        with open("/var/run/libvirt/qemu/{0}.xml".format(self.name), "r") as f:
            vm_xml = f.read()
        bs = BeautifulSoup(vm_xml, "lxml")
        domstatus_tag: Tag = list(bs.find_all(name="domstatus"))[0]
        assert domstatus_tag["state"] == "running"
        self.pid = int(domstatus_tag["pid"])
        self.vm_mem_numa = all_vm_mem_numa[self.pid]
        vcpus_tags: List[Tag] = list(domstatus_tag.find_all(name="vcpu"))
        self.vcpu_pids = []
        self.cpu_node_assigned_record = []
        vcpu_count = len(vcpus_tags)
        numa_count = len(node_distances)
        cpu_count = len(cpu_to_node_idx)
        for vcpu_tag in vcpus_tags:
            try:
                # vcpu_id = int(vcpu_tag["id"])
                pid = int(vcpu_tag["pid"])
                self.vcpu_pids.append(pid)
                self.cpu_node_assigned_record.append([0 for i in range(numa_count)])
            except:
                pass
        
        self.cpu_memory_access_average_overhead = [0.0 for i in range(cpu_count)]
        total_mem = self.vm_mem_numa["total"]
        per_node_mem = self.vm_mem_numa["per_node"]
        for cpu in range(cpu_count):
            cpu_node = cpu_to_node_idx[cpu]
            total_overhead = 0
            """
Per-node process memory usage (in MBs)
PID              Node 0 Node 1 Node 2 Node 3 Node 4 Node 5 Node 6 Node 7  Total
---------------  ------ ------ ------ ------ ------ ------ ------ ------ ------
4440 (qemu-kvm)     175      0      3      9   3205    832      1      2   4226
4550 (qemu-kvm)    3437      0     15      0      2     44    648     82   4228
            """
            for mem_node in range(numa_count):
                distance = node_distances[cpu_node][mem_node]
                overhead = distance * per_node_mem[mem_node]
                total_overhead += overhead
            average_overhead = total_overhead / total_mem
            self.cpu_memory_access_average_overhead[cpu] = average_overhead
        self.vcpu_average_overhead_record = [[] for i in range(vcpu_count)]

        max_mem=0

        for i,mem in enumerate(self.vm_mem_numa["per_node"]):
            if mem > max_mem:
                self.main_mem_node = i
                max_mem = mem
    def _get_vcpu_index_by_pid(self, pid: int):
        for i in range(len(self.vcpu_pids)):
            if self.vcpu_pids[i] == pid:
                return i
        return -1

    def collect(self) -> Tuple[int,List[int],List[float]]:
        p = Popen(PSR_CMD_TEMPLATE.format_map({"pid": self.pid}).split(), stdout=PIPE)
        p.wait()
        p_output = p.stdout.read().decode()
        lines = p_output.splitlines()
        lines = lines[2:]
        current_overhead = [0.0 for i in range(len(self.vcpu_pids))]
        current_cpu_nodes=[-1 for i in range(len(self.vcpu_pids))]
        for line in lines:
            splited = line.strip().split()
            tid = int(splited[1].strip())
            psr = int(splited[-1].strip())
            vcpu_index = self._get_vcpu_index_by_pid(tid)
            if vcpu_index >= 0:
                self.cpu_node_assigned_record[vcpu_index][self.cpu_to_numa_node[psr]] += 1
                average_overhead = self.cpu_memory_access_average_overhead[psr]
                self.vcpu_average_overhead_record[vcpu_index].append(average_overhead)
                current_overhead[vcpu_index] = average_overhead
                current_cpu_nodes[vcpu_index] = self.cpu_to_numa_node[psr]
        return self.main_mem_node,current_cpu_nodes ,current_overhead

    def get_result(self):
        res=[-1]*len(self.vcpu_pids)
        for vcpu_idx in range(len(self.vcpu_pids)):
            # vcpu_arerage_overhead_sum=sum(self.vcpu_average_overhead_record[vcpu_idx])
            # res.append(vcpu_arerage_overhead_sum/len(self.vcpu_average_overhead_record[vcpu_idx]))
            max_assigned_node_count = 0
            for node_idx,node_count in enumerate(self.cpu_node_assigned_record[vcpu_idx]):
                if node_count > max_assigned_node_count:
                    max_assigned_node_count = node_count
                    res[vcpu_idx]=node_idx
            # for psr in self.cpu_assigned_record[vcpu_idx]:
                
        return res

def background_thread(vm_infos: Dict[str, VmVcpuInfo]):
    while True:
        for vm_name, vm_info in vm_infos.items():
            main_mem_node,current_cpu_nodes ,current_overhead = vm_info.collect()
            s=f"{vm_name}: main memory node {main_mem_node}\t current cpu nodes "
            for cpu_node in current_cpu_nodes:
                s+="{} ".format(cpu_node)
            s+="\toverhead "
            for overhead in current_overhead:
                s+="{:.2f} ".format(overhead)
            print(s)
        if NEED_STOP_FALG:
            break
        print("\ninput q to quit")
        time.sleep(1)


if __name__ == "__main__":
    all_vm_mem_numa = get_all_vm_mem_numa_info()
    cpu_to_node_idx, node_distances = get_all_cpu_numa_info()
    all_vm_names:List[str] = get_all_vm_names()
    vm_infos: Dict[str, VmVcpuInfo] = OrderedDict()
    for vm_name in all_vm_names:
        vm_info = VmVcpuInfo(vm_name)
        vm_info.init(all_vm_mem_numa,cpu_to_node_idx, node_distances)
        vm_infos[vm_name] = vm_info
    res:Dict[str,List[float]] = OrderedDict()
    need_stop = False
    bg_thread = threading.Thread(target=background_thread, args=[vm_infos])
    bg_thread.start()
    while True:
        try:
            key = input("input q or ctrl + c to quit")
            if key == "q":
                NEED_STOP_FALG = True
                bg_thread.join()
                break
        except KeyboardInterrupt as ex:
            print(ex)
            NEED_STOP_FALG = True
            bg_thread.join()
            break
    for vm_name in all_vm_names:
        res[vm_name] = vm_infos[vm_name].get_result()
    with open("all_vm_psr_data.json", "w") as f:
        json.dump(res, f, ensure_ascii=False, indent=4)
