# vim: ts=4:sw=4:expandtab
# -*- coding: UTF-8 -*-

# BleachBit
# Copyright (C) 2008-2018 Andrew Ziem
# https://www.bleachbit.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
Wipe memory
"""

from __future__ import absolute_import, print_function

from bleachbit import FileUtilities
from bleachbit import General

import logging
import os
import re
import subprocess
import sys
import traceback

logger = logging.getLogger(__name__)

#swap 메모리 사용건수를 반환하는 함수
def count_swap_linux():
    """Count the number of swap devices in use"""
    f = open("/proc/swaps") #리눅스의 swaps 파일 오픈
    count = 0
    for line in f: #파일을 읽어 swap 메모리 사용건수 저장
        if line[0] == '/':
            count += 1
    return count


def get_proc_swaps():
    """Return the output of 'swapon -s'"""
    # Usually 'swapon -s' is identical to '/proc/swaps'
    # Here is one exception:
    # https://bugs.launchpad.net/ubuntu/+source/bleachbit/+bug/1092792
    (rc, stdout, _) = General.run_external(['swapon', '-s']) #swapon -s 를 실행하는 익스터널 커맨드 실행
    if 0 == rc: #swap메모리를 사용하지 않는경우
        return stdout #빈값이 들어간 stdout 스트링 출력
    logger.debug('"swapoff -s" failed so falling back to /proc/swaps') #swap 메모리를 사용하는 경우 로그 기록
    return open("/proc/swaps").read() #swaps 파일을 열어 읽은 내용을 반환

#스왑오프의 출력을 파싱하고 장치의 이름을 반환
def parse_swapoff(swapoff):
    """Parse the output of swapoff and return the device name"""
    # English is 'swapoff on /dev/sda5' but German is 'swapoff für ...'
    # Example output in English with LVM and hyphen: 'swapoff on /dev/mapper/lubuntu-swap_1'
    # This matches swap devices and swap files
    ret = re.search('^swapoff (\w* )?(/[\w/.-]+)$', swapoff) #swapoff 정규식 표현 후 파싱
    if not ret: # 파싱값이 없는 경우
        # no matches
        return None
    return ret.group(2) #2번째 그룹에 서치된 문자열을 반환

#리눅스 스왑을 불가능하게 하고 디바이스 리스트를 리턴
def disable_swap_linux():
    """Disable Linux swap and return list of devices"""
    if 0 == count_swap_linux(): #만약 리눅스 swap을 한개도 사용하지 않으면 그냥 종료
        return
    logger.debug('disabling swap"') #로거 기록
    args = ["swapoff", "-a", "-v"] #인자값 저장
    (rc, stdout, stderr) = General.run_external(args) #args에 저장된 명령어를 실행하는 익스터널 커맨드 실행
    if 0 != rc: #만약 실행결과가 아무 리턴값을 반환하지 못했다면
        raise RuntimeError(stderr.replace("\n", "")) #런타임 예외 발생
    devices = [] #디바이스 리스트가 저장될 변수 초기화
    for line in stdout.split('\n'): #stdout에 저장된 데이터를 라인으로 구분하여 반복문 실행
        line = line.replace('\n', '') #\n 문자를 삭제하여 저장
        if '' == line: #라인이 빈경우 다음 라인으로
            continue
        ret = parse_swapoff(line) #라인의 데이터를 파라미터로 swapoff 함수 실행하여 딕셔너리를 리턴값으로 반환받음
        if ret is None: #ret이 비어있는 경우
            raise RuntimeError("Unexpected output:\nargs='%(args)s'\nstdout='%(stdout)s'\nstderr='%(stderr)s'"
                               % {'args': str(args), 'stdout': stdout, 'stderr': stderr}) #runtime 예외 발생
        devices.append(ret) #디바이스에 ret 딕셔너리 추가
    return devices

#swpa 기능을 가능하게
def enable_swap_linux():
    """Enable Linux swap"""
    logger.debug('re-enabling swap"') #swap enable 로거 메시지 추가
    args = ["swapon", "-a"] #명령어와 옵션값을 인자값에 인자 딕셔너리에 저장
    p = subprocess.Popen(args, stderr=subprocess.PIPE) #새 프로세스를 생성하고 입력 / 출력 / 오류 파이프에 연결하고 반환
    p.wait() #프로세스 대기
    outputs = p.communicate() #프로세스와 상호 작용 : 데이터를 stdin으로 보냅니다. 파일 끝에 도달 할 때까지 stdout 및 stderr에서 데이터를 읽음
    if 0 != p.returncode: #프로세스 명령이 완료되면 받는 returncode 가 비어있는 경우
        raise RuntimeError(outputs[1].replace("\n", "")) #프로세스가 정상 실행 되지 않았음으로 런타임 예외 발생


def make_self_oom_target_linux():
    """Make the current process the primary target for Linux out-of-memory killer"""
    # In Linux 2.6.36 the system changed from oom_adj to oom_score_adj
    path = '/proc/%d/oom_score_adj' % os.getpid() #현재 프로세스의 pid를 얻어 총 path를 변수에 저장
    if os.path.exists(path): #프로세스가 존재한다면
        open(path, 'w').write('1000') #path 파일을 쓰기로 열어서 1000 입력
    else:
        path = '/proc/%d/oomadj' % os.getpid() #현재 프로세스의 pid를 얻어 총 path를 변수에 저장
        if os.path.exists(path): #프로세스가 존재한다면
            open(path, 'w').write('15') #path 파일을 쓰기로 열어서 15 입력
    # OOM likes nice processes
    logger.debug('new nice value %d', os.nice(19))
    # OOM prefers non-privileged processes
    try:
        uid = General.getrealuid() #리눅스의 real uid를 변수에 저장
        if uid > 0: #만약 uid가 존재한다면
            logger.debug('dropping privileges of pid %d to uid %d', os.getpid(), uid) #로그작성
            os.seteuid(uid) #euid를 ruid로 세팅
    except:
        traceback.print_exc()

#할당되지 않은 메모리 채우는 함수
def fill_memory_linux():
    """Fill unallocated memory"""
    report_free() #비어있는 메모리를 레포트하는 함수
    allocbytes = int(physical_free() * 0.4) #시스템 운영체제에 따라 메모리량을 받아 할당 가능한 바이트 계산
    if allocbytes < 1024: #만약 1mb이하라면 할당 하지 않음
        return
    bytes_str = FileUtilities.bytes_to_human(allocbytes) #allocbytes의 바이트량을 사람이 보기 편한 표기형식으로 변경(예: kb, mb)
    logger.info('allocating and wiping %s (%d B) of memory', bytes_str, allocbytes)
    try:
        buf = '\x00' * allocbytes #버퍼 계산
    except MemoryError: #메모리 예외시
        pass
    else:
        fill_memory_linux() #할당되지 않은 메모리 채우는 함수실행(재귀)
        logger.debug('freeing %s of memory" % bytes_str')
        del buf
    report_free() #비어있는 메모리를 레포트하는 함수


def get_swap_size_linux(device, proc_swaps=None): #swap의 메모리 사이즈를 얻는 함수
    """Return the size of the partition in bytes"""
    if proc_swaps is None:
        proc_swaps = get_proc_swaps() #'swapon -s' 결과값을 리턴하여 할당
    line = proc_swaps.split('\n')[0] #첫줄의 라인을 변수에 저장
    if not re.search('Filename\s+Type\s+Size', line): #정규식 변환후 서치가 없다면
        raise RuntimeError("Unexpected first line in swap summary '%s'" % line) #런타임 예외 발생
    for line in proc_swaps.split('\n')[1:]: #2번째줄 라인 이후부터 반복문 실행
        ret = re.search("%s\s+\w+\s+([0-9]+)\s" % device, line) #정규식 변환
        if ret: #만약 정규식 변환되었다면
            return int(ret.group(1)) * 1024 #사이즈 계산 후 반환
    raise RuntimeError("error: cannot find size of swap device '%s'\n%s" %
                       (device, proc_swaps)) #런타임 에러시 에러 메시지 발생


def get_swap_uuid(device): #swap 디바이스의 uuid를 반환하는 함수
    """Find the UUID for the swap device"""
    uuid = None
    args = ['blkid', device, '-s', 'UUID'] #커맨드 명령어와 옵션을 딕셔너리 형태로 저장
    (_, stdout, _) = General.run_external(args) #args에 저장한 명령어를 실행하는 익스터널 커맨드 실행
    for line in stdout.split('\n'): #stdout을 라인으로 스플릿하고 반복문 실행
        # example: /dev/sda5: UUID="ee0e85f6-6e5c-42b9-902f-776531938bbf"
        ret = re.search("^%s: UUID=\"([a-z0-9-]+)\"" % device, line) #정규식 표현으로 변환ㄴ
        if ret is not None: #정규식 표현이 안된경우
            uuid = ret.group(1) #1번 그룹의 값을 uuid로
    logger.debug("uuid(%s)='%s'", device, uuid)
    return uuid #uuid 반환


def physical_free_darwin(run_vmstat=None):
    def parse_line(k, v): #파라미터로 k,v를 입력받고
        return k, int(v.strip(" .")) #k는 그대로 리턴, v는 양쪽 '.' 문자 삭제 후 숫자형으로 반환

    def get_page_size(line): #페이지 사이즈를 반환하는 함수
        m = re.match(
            r"Mach Virtual Memory Statistics: \(page size of (\d+) bytes\)",
            line) #정규식이 매치하는지 결과값을 변수에 대입
        if m is None: # 정규식이 매치하지 않는경우
            raise RuntimeError("Can't parse vm_stat output") #런타임 예외 발생
        return int(m.groups()[0]) #정규식 첫번째 그룹의 값을 정수형태로 반환
    if run_vmstat is None: #파라미터로 전달받은게 없는 경우
        def run_vmstat():
            return subprocess.check_output(["vm_stat"]) #새 프로세스를 생성하고 커맨드 라인 입력
    output = iter(run_vmstat().split("\n")) #라인 기준으로 이터레이터 값 할당
    page_size = get_page_size(next(output)) #페이지 사이즈 계산하여 값 할당
    vm_stat = dict(parse_line(*l.split(":")) for l in output if l != "")
    return vm_stat["Pages free"] * page_size

def physical_free_linux():
    """Return the physical free memory on Linux"""
    f = open("/proc/meminfo") #해당 파일 오픈하여 데이터 읽기
    free_bytes = 0
    for line in f: #반복문 실행
        line = line.replace("\n", "") #라인 제거
        ret = re.search('(MemFree|Cached):[ ]*([0-9]*) kB', line) #정규식 변환후 서치값 할당
        if ret is not None: #만약 서치한 값이 있다면
            kb = int(ret.group(2)) #정규식의 2번째 그룹을 정수형태로 kb변수에 저장
            free_bytes += kb * 1024 # free_bytes의 바이트값 설정
    if free_bytes > 0: # 만약 free_bytes의 바이트값이 0보다 크다면
        return free_bytes #free_bytes 반환
    else:
        raise Exception("unknown") #0보다 작으면 예외 발생


def physical_free_windows():
    """Return physical free memory on Windows"""

    from ctypes import c_long, c_ulonglong
    from ctypes.wintypes import Structure, sizeof, windll, byref

    class MEMORYSTATUSEX(Structure):
        _fields_ = [ #딕셔너리 선언
            ('dwLength', c_long),
            ('dwMemoryLoad', c_long),
            ('ullTotalPhys', c_ulonglong),
            ('ullAvailPhys', c_ulonglong),
            ('ullTotalPageFile', c_ulonglong),
            ('ullAvailPageFile', c_ulonglong),
            ('ullTotalVirtual', c_ulonglong),
            ('ullAvailVirtual', c_ulonglong),
            ('ullExtendedVirtual', c_ulonglong),
        ]

    def GlobalMemoryStatusEx():
        x = MEMORYSTATUSEX() #x변수에 MEMORYSTATUSEX 인스턴스 생성 후 할당
        x.dwLength = sizeof(x) #x의 사이즈 계산하여 값 할당
        windll.kernel32.GlobalMemoryStatusEx(byref(x))
        return x #x 인스턴스 반환

    z = GlobalMemoryStatusEx() #z에 GlobalMemoryStatusEx함수를 실행하여 반환받은 MEMORYSTATUSEX 인스턴스 할당
    print(z) #z출력
    return z.ullAvailPhys #사용가능 메모리 반환


def physical_free(): #시스템 플랫폼의 종류에 따라 함수 호출
    if sys.platform.startswith('linux'):
        return physical_free_linux()
    elif 'win32' == sys.platform:
        return physical_free_windows()
    elif 'darwin' == sys.platform:
        return physical_free_darwin()
    else:
        raise RuntimeError('unsupported platform for physical_free()')


def report_free(): #비어있는 메모리를 레포트하는 함수
    """Report free memory"""
    bytes_free = physical_free() #변수에  시스템 플랫폼에 따라 비어있는 바이트 사이즈를 저장
    bytes_str = FileUtilities.bytes_to_human(bytes_free) #사람이 읽기좋은 형태로 바이트 단위값 변경
    logger.debug('physical free: %s (%d B)', bytes_str, bytes_free) # 로거에 기록


def wipe_swap_linux(devices, proc_swaps):
    """Shred the Linux swap file and then reinitilize it"""
    if devices is None: #디바이스가 없는경우 함수 종료
        return
    if 0 < count_swap_linux(): #swap 메모리가 1개 이상인 경우
        raise RuntimeError('Cannot wipe swap while it is in use') #런타임 예외 발생
    for device in devices: #각 디바이스를 순회
        logger.info("wiping swap device '%s'", device) # 로그 입력
        safety_limit_bytes = 29 * 1024 ** 3  # 29 gibibytes #최대 제한 바이트 설정
        actual_size_bytes = get_swap_size_linux(device, proc_swaps) #실제 바이트 사이즈 계산
        if actual_size_bytes > safety_limit_bytes: # 만약 실제 사용 가능한 바이트가 최대 제한 바이트를 넘는경우
            raise RuntimeError( #런타임 예외 발생
                'swap device %s is larger (%d) than expected (%d)' %
                (device, actual_size_bytes, safety_limit_bytes))
        uuid = get_swap_uuid(device) #uuid 값 설정
        # wipe
        FileUtilities.wipe_contents(device, truncate=False) #디바이스의 메모리 삭제
        # reinitialize
        logger.debug('reinitializing swap device %s', device)
        args = ['mkswap', device] #딕셔너리 생성
        if uuid:
            args.append("-U") #uuid 옵션 추가
            args.append(uuid)
        (rc, _, stderr) = General.run_external(args) #args에 저장한 명령어를 실행하는 익스터널 커맨드 실행
        if 0 != rc: #익스터널 커맨드가 정상적으로 실행되지 못했다면 런타임 예외 발생
            raise RuntimeError(stderr.replace("\n", ""))


def wipe_memory(): #할당되지 않은 메모리 지움
    """Wipe unallocated memory"""
    # cache the file because 'swapoff' changes it
    proc_swaps = get_proc_swaps() #'swapon -s' 실행시 반환되는 반환값 할당
    devices = disable_swap_linux() #리눅스 스왑을 불가능하게 하고 디바이스 리스트를 리턴하여 리스트에 저장
    yield True  # process GTK+ idle loop
    logger.debug('detected swap devices: ' + str(devices)) #로그 작성
    wipe_swap_linux(devices, proc_swaps) #리눅스 스왑파일을 삭제 후 다시 초기화
    yield True
    child_pid = os.fork() #자식프로세스 생성 후 pid 값 변수에 할당
    if 0 == child_pid: #만약 자식프로세스가 생성되지 않았다면
        make_self_oom_target_linux() #현재 프로세스를 리눅스 메모리 부족 킬러 대상으로 선택
        fill_memory_linux() #할당되지 않은 메모리 채우는 함수 호출
        sys.exit(0) # 시스템 종료
    else:
        logger.debug('wipe_memory() pid %d waiting for child pid %d', os.getpid(), child_pid) #자식프로세스 id를 로그에 추가
        rc = os.waitpid(child_pid, 0)[1] #waitpid 리턴 시그널을 rc에 저장
        if 0 != rc: #waitpid 리턴을 정상적으로 받은 경우
            logger.warning('child process returned code %d', rc)
    enable_swap_linux() #리눅스 스왑을 가능하게 변경
    yield 0  # how much disk space was recovered
