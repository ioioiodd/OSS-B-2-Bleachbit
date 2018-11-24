# vim: ts=4:sw=4:expandtab

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
Functionality specific to Microsoft Windows

The Windows Registry terminology can be confusing. Take for example
the reference
* HKCU\\Software\\BleachBit
* CurrentVersion

These are the terms:
* 'HKCU' is an abbreviation for the hive HKEY_CURRENT_USER.
* 'HKCU\Software\BleachBit' is the key name.
* 'Software' is a sub-key of HCKU.
* 'BleachBit' is a sub-key of 'Software.'
* 'CurrentVersion' is the value name.
* '0.5.1' is the value data.


"""

from __future__ import absolute_import, print_function

import bleachbit
from bleachbit import Command, FileUtilities, General

import glob
import logging
import os
import re
import sys

from decimal import Decimal

if 'win32' == sys.platform: #운영체제가 win 32인 경우 윈도우에 필요한 유틸리티 임포트
    import _winreg
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32gui
    import win32process

    from ctypes import windll, c_ulong, c_buffer, byref, sizeof
    from win32com.shell import shell, shellcon

    psapi = windll.psapi #프로세스 api 모듈
    kernel = windll.kernel32 #커널 핸들링 모듈

logger = logging.getLogger(__name__) #로그기록


def browse_file(_, title): #
    """Ask the user to select a single file.  Return full path"""
    try: #gui 이용하여 파일을 선택하도록 폼 실행
        ret = win32gui.GetOpenFileNameW(None,
                                        Flags=win32con.OFN_EXPLORER
                                        | win32con.OFN_FILEMUSTEXIST
                                        | win32con.OFN_HIDEREADONLY,
                                        Title=title)
    except pywintypes.error as e: #에러의 종류가 pywintypes.error인 경우
        logger = logging.getLogger(__name__) #로그 기록
        if 0 == e.winerror: #e.winerror 에러넘버가 0인 경우
            logger.debug('browse_file(): user cancelled') #로그 디버그 추가
        else:
            logger.exception('exception in browse_file()') #로그 디버그 추가
        return None
    return ret[0] #ret 리스트중 0번째 인덱스의 값 반환


def browse_files(_, title):
    """Ask the user to select files.  Return full paths"""
    try:
        # The File parameter is a hack to increase the buffer length.
        ret = win32gui.GetOpenFileNameW(None, #gui 이용하여 다중 파일을 선택하도록 폼 실행
                                        File = '\x00' * 10240,
                                        Flags=win32con.OFN_ALLOWMULTISELECT
                                        | win32con.OFN_EXPLORER
                                        | win32con.OFN_FILEMUSTEXIST
                                        | win32con.OFN_HIDEREADONLY,
                                        Title=title)
    except pywintypes.error as e:  #에러의 종류가 pywintypes.error인 경우
        if 0 == e.winerror: #e.winerror 에러넘버가 0인 경우
            logger.debug('browse_files(): user cancelled') #로그 디버그 추가
        else:
            logger.exception('exception in browse_files()') #로그 디버그 추가
        return None
    _split = ret[0].split('\x00') #ret 리스트의 0번째 값을 '\x00' 문자 기준으로 스플릿
    if 1 == len(_split): #만약 선택한 파일이 한개라면
        # only one filename
        return _split #선택한 한개 파일 반환
    pathnames = [] #경로이름이 저장될 함수 초기화
    dirname = _split[0] # 최 상위 경로 저장
    for fname in _split[1:]: # 나머지 상세주소 순환
        pathnames.append(os.path.join(dirname, fname)) #pathnames에 선택한 파일의 절대주소값을 저장
    return pathnames #절대경로 주소 리스트 반환


def browse_folder(hwnd, title):
    """Ask the user to select a folder.  Return full path."""
    pidl = shell.SHBrowseForFolder(hwnd, None, title)[0] #폴더선택 쉘 인스턴스 할당
    if pidl is None: #만약 폴더선택 모듈이 정상적으로 생성되지 않았다면
        # user cancelled
        return None #함수 종료
    fullpath = shell.SHGetPathFromIDList(pidl) #선택한 폴더의 절대경로 저장
    return fullpath #절대경로 반환


def csidl_to_environ(varname, csidl):
    """Define an environment variable from a CSIDL for use in CleanerML and Winapp2.ini"""
    try:
        sppath = shell.SHGetSpecialFolderPath(None, csidl) #폴더경로를 가져와서 변수에 저장
    except: #예외 발생시
        logger.info('exception when getting special folder path for %s', varname) #로그 작성
        return
    # there is exception handling in set_environ()
    set_environ(varname, sppath) #위에서 저장한 폴더경로를 파라미터로 환경을 세팅하는 함수 호출


def delete_locked_file(pathname):
    """Delete a file that is currently in use"""
    if os.path.exists(pathname): #pathname 경로가 존재하는 파일인 경우
        MOVEFILE_DELAY_UNTIL_REBOOT = 4
        if 0 == windll.kernel32.MoveFileExW(pathname, None, MOVEFILE_DELAY_UNTIL_REBOOT): #파일 이동이 불가능한 경우(예: 실행중))
            from ctypes import WinError
            raise WinError() #윈도우 예외 발생


def delete_registry_value(key, value_name, really_delete):
    """Delete named value under the registry key.
    Return boolean indicating whether reference found and
    successful.  If really_delete is False (meaning preview),
    just check whether the value exists."""
    (hive, sub_key) = split_registry_key(key) #레지스트리 키를 최상위 경로와 하위 경로로 나는 함수 실행
    if really_delete: #만약 really_delete 값이 트루인 경우
        try:
            hkey = _winreg.OpenKey(hive, sub_key, 0, _winreg.KEY_SET_VALUE) #지정한 키를 열어 핸들객체 반환
            _winreg.DeleteValue(hkey, value_name) #value_name과 이름이 같은 레지스트리 삭제
        except WindowsError as e: #WindowsError 예외 발생시
            if e.winerror == 2:
                # 2 = 'file not found' means value does not exist
                return False
            raise
        else:
            return True
    try:
        hkey = _winreg.OpenKey(hive, sub_key) #지정한 키를 열어 핸들객체 반환
        _winreg.QueryValueEx(hkey, value_name) #열려있는 레지스트리 키와 연결된 지정된 값 이름의 형식과 데이터를 검색
    except WindowsError as e: #WindowsError 예외 발생시
        if e.winerror == 2: #e.winerror 가 2라면
            return False #펄스 반환
        raise
    else:
        return True #트루 반환
    raise RuntimeError('Unknown error in delete_registry_value') #런타임 예외 발생


def delete_registry_key(parent_key, really_delete):
    """Delete registry key including any values and sub-keys.
    Return boolean whether found and success.  If really
    delete is False (meaning preview), just check whether
    the key exists."""
    parent_key = str(parent_key)  # Unicode to byte string
    (hive, parent_sub_key) = split_registry_key(parent_key) #레지스트리 경로를 최상위와 그 하위 경로로 구분
    hkey = None
    try:
        hkey = _winreg.OpenKey(hive, parent_sub_key) #지정한 키를 열어 핸들객체 반환
    except WindowsError as e: #WindowsError 예외 발생시
        if e.winerror == 2: #e.winerror 가 2라면
            # 2 = 'file not found' happens when key does not exist
            return False #펄스 반환
    if not really_delete: #전달받은 really_delete 가 트루가 아닌경우
        return True #트루 반환
    if not hkey: #핸들러 객체를 정상적으로 반환 받지 못한경우(예: 해당 이름의 키가 없는 경우)
        # key not found
        return False #펄스 반환
    keys_size = _winreg.QueryInfoKey(hkey)[0] #키에 있는 하위 키 수 저장
    child_keys = []
    for i in range(keys_size): #하위 키수만큼 순환
        child_keys.append(parent_key + '\\' + _winreg.EnumKey(hkey, i)) #자식키로서 하위 키 추가
    for child_key in child_keys: #하위키 순환
        delete_registry_key(child_key, True) #하위의 키를 순환하며 파라미터와 동일한 키값이면 키 삭제
    _winreg.DeleteKey(hive, parent_sub_key) #하위키 모두 검색이 끝난 후 최상위 키 삭제
    return True #트루 반환


def delete_updates():
    """Returns commands for deleting Windows Updates files"""
    windir = bleachbit.expandvars('$windir') #블리츠비트 환경변수 확장
    dirs = glob.glob(os.path.join(windir, '$NtUninstallKB*')) #$NtUninstallKB* 파일이 있는지 windir 경로를 하위폴더까지 모두 검색
    dirs += [bleachbit.expandvars('$windir\\SoftwareDistribution\\Download')] #세부 경로 설정
    dirs += [bleachbit.expandvars('$windir\\ie7updates')]
    dirs += [bleachbit.expandvars('$windir\\ie8updates')]
    if not dirs: #만약 하위폴더에 파라미터로 지정했던 이름의 업데이트 파일이 존재하지 않는다면
        # if nothing to delete, then also do not restart service
        return #함수 종료

    import win32serviceutil
    wu_running = win32serviceutil.QueryServiceStatus('wuauserv')[1] == 4 #wuauserv 서비스의 윈도우 업데이트 에러코드 저장

    args = ['net', 'stop', 'wuauserv'] #익스터널 커맨드에 사용할 명령어 인자값 저장

    def wu_service():
        General.run_external(args) #익스터널 커맨드 명령어 실행
        return 0
    if wu_running: #wuauserv 윈도우 업데이트 에러코드가 있다면
        yield Command.Function(None, wu_service, " ".join(args)) #커멘드를 이용하여 서비스 실행

    for path1 in dirs: #하위경로 순환
        for path2 in FileUtilities.children_in_directory(path1, True):#하위의 모든 경로 전부 순환
            yield Command.Delete(path2) #path2 경로 삭제
        if os.path.exists(path1): #만약 path1 경로가 존재한다면
            yield Command.Delete(path1) #path1 경로 삭제

    args = ['net', 'start', 'wuauserv'] #익스터널 커맨드에 사용할 명령어 인자값 저장
    if wu_running: #블리츠비트 환경변수가 존재한다면
        yield Command.Function(None, wu_service, " ".join(args)) #커멘드를 이용하여 서비스 실행


def detect_registry_key(parent_key): #레지스트리 키 존재여부 확인
    """Detect whether registry key exists"""
    parent_key = str(parent_key)  # Unicode to byte string
    (hive, parent_sub_key) = split_registry_key(parent_key) #레지스트리 경로를 최상위와 그 하위 경로로 구분
    hkey = None
    try:
        hkey = _winreg.OpenKey(hive, parent_sub_key) #지정한 키를 열어 핸들객체 반환
    except WindowsError as e: #WindowsError 예외 발생시
        if e.winerror == 2: #e.winerror 가 2라면
            # 2 = 'file not found' happens when key does not exist
            return False #펄스 반환
    if not hkey: #만약 최상위 key가 없다면
        # key not found
        return False #펄스 반환
    return True #트루 반환


def elevate_privileges(): #관리자 권한 얻는 함수
    """On Windows Vista and later, try to get administrator
    privileges.  If successful, return True (so original process
    can exit).  If failed or not applicable, return False."""

    if parse_windows_build() < 6: #윈도우 비스타 이하 버전인 경우
        # Windows XP does not have the UAC.
        # Vista is the first version Windows that has the UAC.
        # 5.1 = Windows XP
        # 6.0 = Vista
        # 6.1 = 7
        # 6.2 = 8
        # 10 = 10
        return False #관리자 권한을 얻을 필요가 없어 함수종료

    if shell.IsUserAnAdmin(): #사용자가 관리자 권한을 가지고 있는 경우
        logger.debug('already an admin (UAC not required)') #로그 추가
        return False #펄스 반환

    if hasattr(sys, 'frozen'): #cxFreeze를 이용하여 파이선 실행파일을 실행하기위한 함수
        # running frozen in py2exe
        exe = sys.executable.decode(sys.getfilesystemencoding()) #유니코드 파일명과 바이트 파일명을 변환하여 반환
        parameters = "--gui --no-uac"
    else:
        # __file__ is absolute path to bleachbit/Windows.py
        pydir = os.path.dirname(__file__.decode(sys.getfilesystemencoding())) #유니코드 파일명과 바이트 파일명을 변환하여 반환
        pyfile = os.path.join(pydir, 'GUI.py') #GUI.py의 전체경로 지정
        # If the Python file is on a network drive, do not offer the UAC because
        # the administrator may not have privileges and user will not be
        # prompted.
        if len(pyfile) > 0 and path_on_network(pyfile): #GUI_py의 경로가 정상적으로 설정되고 경로가 네트워크 드라이브인 경우
            logger.debug("debug: skipping UAC because '%s' is on network", pyfile) #로그 추가
            return False #펄스 반환
        parameters = '"%s" --gui --no-uac' % pyfile #파라미터 변수에 경로 추가
        exe = sys.executable #exe 파일이 실행할 수 있는 파일로 설정

    # add any command line parameters such as --debug-log
    parameters = "%s %s" % (parameters, ' '.join(sys.argv[1:]))

    logger.debug('elevate_privileges() exe=%s, parameters=%s', exe, parameters) #로그추가

    rc = None
    try: #사용자 계정 설정을 할수 있는 핸들러 저장
        rc = shell.ShellExecuteEx(lpVerb='runas',
                                  lpFile=exe,
                                  lpParameters=parameters,
                                  nShow=win32con.SW_SHOW)
    except pywintypes.error as e: #만약 pywintypes 예외가 발생한 경우
        if 1223 == e.winerror: #e.winerror가 1223인경우
            logger.debug('user denied the UAC dialog') #로그 추가
            return False #펄스 반환
        raise

    logger.debug('ShellExecuteEx=%s', rc) ##사용자 계정 설정을 할수 있는 핸들러를 로그에 추가

    if isinstance(rc, dict): #사용자 계정 핸들러 인스턴스 생성
        return True #트루 반환

    return False #펄스 반환


def empty_recycle_bin(path, really_delete): #휴지통 비우기 함수
    """Empty the recycle bin or preview its size.

    If the recycle bin is empty, it is not emptied again to avoid an error.

    Keyword arguments:
    path          -- A drive, folder or None.  None refers to all recycle bins.
    really_delete -- If True, then delete.  If False, then just preview.
    """
    (bytes_used, num_files) = shell.SHQueryRecycleBin(path) #지정한 드라이브의 휴지통에있는 총 크기 및 항목 수를 검색
    if really_delete and num_files > 0: #만약 really_delete 파라미터가 참이고 휴지통에 파일이 1개 이상인 경우
        # Trying to delete an empty Recycle Bin on Vista/7 causes a
        # 'catastrophic failure'
        flags = shellcon.SHERB_NOSOUND | shellcon.SHERB_NOCONFIRMATION | shellcon.SHERB_NOPROGRESSUI #사운드없이, 확인창 없이, 진행 없이 설정
        shell.SHEmptyRecycleBin(None, path, flags) #휴지통 비우기
    return bytes_used #삭제한 파일의 총 사이즈 반환


def get_autostart_path(): #블리치비트 바로가기 아이콘 위치 경로 반환
    """Return the path of the BleachBit shortcut in the user's startup folder"""
    try: #바로가기 경로 찾기
        startupdir = shell.SHGetSpecialFolderPath(None, shellcon.CSIDL_STARTUP)
    except: #예외 발생시
        # example of failure
        # https://www.bleachbit.org/forum/error-windows-7-x64-bleachbit-091
        logger.exception('exception in get_autostart_path()') #로그 추가
        msg = 'Error finding user startup folder: %s ' % (
            str(sys.exc_info()[1])) #바로가기 폴더를 찾을 수 없다는 메시지 문구 지정
        from bleachbit import GuiBasic
        GuiBasic.message_dialog(None, msg) #메시지 다이얼로그 실행
        # as a fallback, guess
        # Windows XP: C:\Documents and Settings\(username)\Start Menu\Programs\Startup
        # Windows 7:
        # C:\Users\(username)\AppData\Roaming\Microsoft\Windows\Start
        # Menu\Programs\Startup
        startupdir = bleachbit.expandvars('$USERPROFILE\\Start Menu\\Programs\\Startup') #시작프로그램 경로 설정
        if not os.path.exists(startupdir): #만약 시작 프로그램 경로가 존재하지 안으면
            startupdir = bleachbit.expandvars('$APPDATA\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup') #appdata 경로의 시작프로그램 경로를 지정
    return os.path.join(startupdir, 'bleachbit.lnk') #시작프로그램 경로와 블리치비트 바로가기 .ink파일을 합쳐서 절대경로를 반환


def get_clipboard_paths(): #클립보드 경로를 찾는 함수
    """Return a tuple of Unicode pathnames from the clipboard"""
    import win32clipboard
    win32clipboard.OpenClipboard() #클립보드 오픈
    path_list = ()
    try:
        path_list = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP) #클립보드의 경로 리스트를 저장
    except TypeError: #예외 발생시
        pass
    finally:
        win32clipboard.CloseClipboard() #클립보드 종료
    return path_list #클립보드 리스트 반환

def get_fixed_drives(): #외부 저장소를 찾는 함수
    """Yield each fixed drive"""
    for drive in win32api.GetLogicalDriveStrings().split('\x00'): #윈도우 api를 이용하여 드라이브 순환
        if win32file.GetDriveType(drive) == win32file.DRIVE_FIXED: #드라이브의 종류가 fixed인 경우
            # Microsoft Office 2010 Starter creates a virtual drive that
            # looks much like a fixed disk but isdir() returns false
            # and free_space() returns access denied.
            # https://bugs.launchpad.net/bleachbit/+bug/1474848
            if os.path.isdir(drive): #드라이브가 존재하는 경우
                yield unicode(drive) #드라이브를 유니코드로 반환


def get_known_folder_path(folder_name):
    """Return the path of a folder by its Folder ID

    Requires Windows Vista, Server 2008, or later

    Based on the code Michael Kropat (mkropat) from
    <https://gist.github.com/mkropat/7550097>
    licensed  under the GNU GPL"""
    import ctypes
    from ctypes import wintypes
    from uuid import UUID

    class GUID(ctypes.Structure):
        _fields_ = [ #데이터 타입을 딕셔너리화
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", wintypes.BYTE * 8)
        ]

        def __init__(self, uuid_):
            ctypes.Structure.__init__(self) #ctype 구조체 생성
            self.Data1, self.Data2, self.Data3, self.Data4[
                0], self.Data4[1], rest = uuid_.fields
            for i in range(2, 8):
                self.Data4[i] = rest >> (8 - i - 1) * 8 & 0xff

    class FOLDERID:
        LocalAppDataLow = UUID(
            '{A520A1A4-1780-4FF6-BD18-167343C5AF16}')

    class UserHandle:
        current = wintypes.HANDLE(0)

    _CoTaskMemFree = windll.ole32.CoTaskMemFree
    _CoTaskMemFree.restype = None
    _CoTaskMemFree.argtypes = [ctypes.c_void_p]

    try:
        _SHGetKnownFolderPath = windll.shell32.SHGetKnownFolderPath
    except AttributeError:
        # Not supported on Windows XP
        return None
    _SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(
            ctypes.c_wchar_p)
    ]

    class PathNotFoundException(Exception):
        pass

    folderid = getattr(FOLDERID, folder_name)
    fid = GUID(folderid)
    pPath = ctypes.c_wchar_p()
    S_OK = 0
    if _SHGetKnownFolderPath(ctypes.byref(fid), 0, UserHandle.current, ctypes.byref(pPath)) != S_OK:
        raise PathNotFoundException(folder_name)
    path = pPath.value
    _CoTaskMemFree(pPath)
    return path


def get_recycle_bin(): #휴지통 폴더안의 파일의 리스트를 반환
    """Yield a list of files in the recycle bin"""
    pidl = shell.SHGetSpecialFolderLocation(0, shellcon.CSIDL_BITBUCKET) #폴더에 해당되는 shell 개체에 대한 pidl로 반환받음
    desktop = shell.SHGetDesktopFolder() #데스크탑 폴더 핸들러
    h = desktop.BindToObject(pidl, None, shell.IID_IShellFolder) #데스크탑 핸들러와 pidl 바인딩하여 h리스트에 저장
    for item in h: #아이템들을 순환
        path = h.GetDisplayNameOf(item, shellcon.SHGDN_FORPARSING) #바탕화면의 아이콘 개체의 리스트를 저장
        if os.path.isdir(path): #만약 바탕화면에 아이콘이 1개라도 존재한다면
            for child in FileUtilities.children_in_directory(path, True): #아이콘 순환
                yield child #아이콘 정보 표시
            yield path
        else:
            yield path


def get_windows_version(): #윈도우 버전 확인
    """Get the Windows major and minor version in a decimal like 10.0"""
    v = win32api.GetVersionEx(0) #api를 이용하여 윈도우 버전 취득
    vstr = '%d.%d' % (v[0], v[1])
    return Decimal(vstr) #윈도우 버전을 10진수로 변환하여 반환


def is_process_running(name): #파라미터의 프로세스가 실행 중인지를 체크
    """Return boolean whether process (like firefox.exe) is running"""

    if parse_windows_build() >= 6: #만약 윈도우 비스타 이상인 경우
        return is_process_running_psutil(name) #비스타 이상에서 프로세스가 실행중인지 확인하는 함수 실행
    else:
        # psutil does not support XP, so fall back
        # https://github.com/giampaolo/psutil/issues/348
        return is_process_running_win32(name) #비스타 이하 32bit 에서 프로세스가 실행중인지 확인하는 함수 실행


def is_process_running_win32(name): #비스타 이하에서 프로세스 실행 여부 확인
    """Return boolean whether process (like firefox.exe) is running

    Does not work on 64-bit Windows

    Originally by Eric Koome
    license GPL
    http://code.activestate.com/recipes/305279/
    """

    hModule = c_ulong()
    count = c_ulong()
    modname = c_buffer(30)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    for pid in win32process.EnumProcesses(): #시스템의 현재 프로세스 순환

        # Get handle to the process based on PID
        hProcess = kernel.OpenProcess( #커널을 이용하여 프로세스 핸들러 설정
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False, pid)
        if hProcess: #만약 핸들러를 정상적으로 받았다면
            psapi.EnumProcessModules( #dll 파일 접근하여 프로세스 모듈 핸들링
                hProcess, byref(hModule), sizeof(hModule), byref(count))
            psapi.GetModuleBaseNameA(
                hProcess, hModule.value, modname, sizeof(modname))
            clean_modname = "".join(
                [i for i in modname if i != '\x00']).lower()

            # Clean up
            for i in range(modname._length_): #모듈이름 길이만큼 순환
                modname[i] = '\x00' #각 모듈이름 리스트에 0으로 초기화

            kernel.CloseHandle(hProcess) #hProcess 핸들러 종료

            if len(clean_modname) > 0 and '?' != clean_modname: #만약 종료할 프로세스의 이름이 있다면
                # Filter out non-ASCII characters which we don't need
                # and which may cause display warnings
                clean_modname2 = re.sub( #정규표현식으로 변환
                    r'[^a-z.]', '_', clean_modname.lower())
                if clean_modname2 == name.lower(): #만약 정규표현식으로 변환한 값과 프로세스명이 같다면
                    return True #트루 반환

    return False #펄스 반환


def is_process_running_psutil(name): #비스타 이후 버전에서 프로세스 실행 여부 확인
    """Return boolean whether process (like firefox.exe) is running

    Works on Windows Vista or later, but on Windows XP gives an ImportError
    """

    import psutil
    name = name.lower() #파라미터를 소문자로 변환
    for proc in psutil.process_iter(): #실행중인 프로세스 목록을 순환
        try:
            if proc.name().lower() == name: #소문자로 변환한 프로세스명과 파라미터로 받은 프로세스이름이 같은 경우
                return True #트루 반환
        except psutil.NoSuchProcess: #예외 발생시 순환 취소
            pass
    return False #펄스 반환


def move_to_recycle_bin(path): #파일을 휴지통으로 이동
    """Move 'path' into recycle bin"""
    shell.SHFileOperation( #shell 명령어를 이용하여 전달받은 경로의 파일을 휴지통으로 이동하는데 별도의 알람없이 이동
        (0, shellcon.FO_DELETE, path, None, shellcon.FOF_ALLOWUNDO | shellcon.FOF_NOCONFIRMATION))


def parse_windows_build(build=None):
    """
    Parse build string like 1.2.3 or 1.2 to numeric,
    ignoring the third part, if present.
    """
    if not build: #전달받은 빌드가 없는 경우
        # If not given, default to current system's version
        return get_windows_version() #윈도우 버전을 반환하는 함수를 실행
    return Decimal('.'.join(build.split('.')[0:2])) #필요한 버전 부분만 스플릿하여 반환


def path_on_network(path): #전달받은 경로가 네트워크 드라이브인지 확인
    """Check whether 'path' is on a network drive"""
        if len(os.path.splitunc(path)[0]) > 0: #전달받은 드라이브의 최상위 경로가 존재하는 경우
        return True
    drive = os.path.splitdrive(path)[0] + '\\' #C\\ 형식으로 변환
    return win32file.GetDriveType(drive) == win32file.DRIVE_REMOTE #드라이브 타입이 네트워크 드라이브라면 트루 반환


def shell_change_notify(): #윈도우 쉘 업데이트를 확인하는 함수
    """Notify the Windows shell of update.

    Used in windows_explorer.xml."""
    shell.SHChangeNotify(shellcon.SHCNE_ASSOCCHANGED, shellcon.SHCNF_IDLIST,
                         None, None)
    return 0

def set_environ(varname, path):
    """Define an environment variable for use in CleanerML and Winapp2.ini"""
    if not path: #만약 path가 없다면 함수 종료
        return
    if varname in os.environ: #os 환경값에 varname이 존재하는 경우
        #logger.debug('set_environ(%s, %s): skipping because environment variable is already defined', varname, path)
        if 'nt' == os.name: #nt 버전의 윈도우인 경우
            os.environ[varname] = bleachbit.expandvars(u'%%%s%%' % varname).encode('utf-8') #utf-8 인코딩으로 환경 변수 설정
        # Do not redefine the environment variable when it already exists
        # But re-encode them with utf-8 instead of mbcs
        return #함수 종료
    try:
        if not os.path.exists(path): #만약 path 경로의 파일이 존재하지 않는 경우
            raise RuntimeError('Variable %s points to a non-existent path %s' % (varname, path)) #런타임 예외 발생
        os.environ[varname] = path.encode('utf8') #utf-8 인코딩
    except: #예외 발생시 로그그 추가
        logger.exception('set_environ(%s, %s): exception when setting environment variable', varname, path)


def setup_environment():
    """Define any extra environment variables for use in CleanerML and Winapp2.ini"""
    csidl_to_environ('commonappdata', shellcon.CSIDL_COMMON_APPDATA) #각 환경값들을 정의
    csidl_to_environ('documents', shellcon.CSIDL_PERSONAL)
    # Windows XP does not define localappdata, but Windows Vista and 7 do
    csidl_to_environ('localappdata', shellcon.CSIDL_LOCAL_APPDATA)
    csidl_to_environ('music', shellcon.CSIDL_MYMUSIC)
    csidl_to_environ('pictures', shellcon.CSIDL_MYPICTURES)
    csidl_to_environ('video', shellcon.CSIDL_MYVIDEO)
    # LocalLowAppData does not have a CSIDL for use with
    # SHGetSpecialFolderPath. Instead, it is identified using
    # SHGetKnownFolderPath in Windows Vista and later
    try:
        path = get_known_folder_path('LocalAppDataLow') #파라미터의 절대경로를 찾아 반환
    except: #예외 발생시 로그 기록
        logger.exception('exception identifying LocalAppDataLow')
    else:
        set_environ('LocalAppDataLow', path) #LocalAppDataLow의 절대경로를 지정
    # %cd% can be helpful for cleaning portable applications when
    # BleachBit is portable. It is the same variable name as defined by
    # cmd.exe .
    set_environ('cd', os.getcwd()) #현재 작업 디렉토리의 이름을 파라미터로 환경설정


def split_registry_key(full_key):
    r"""Given a key like HKLM\Software split into tuple (hive, key).
    Used internally."""
    assert len(full_key) >= 6 #파라미터의 길이가 6 이상인 경우
    [k1, k2] = full_key.split("\\", 1) #최상위 경로와 그 하위경로를 나눔
    hive_map = { #레지스트리 최상위 키를 맵으로 지정
        'HKCR': _winreg.HKEY_CLASSES_ROOT,
        'HKCU': _winreg.HKEY_CURRENT_USER,
        'HKLM': _winreg.HKEY_LOCAL_MACHINE,
        'HKU': _winreg.HKEY_USERS}
    if k1 not in hive_map: #각 맵을 돌며 full_key의 최상위 경로가 존재하지 않는 다면
        raise RuntimeError("Invalid Windows registry hive '%s'" % k1) #런타임 예외 발생
    return hive_map[k1], k2 #나눈 경로를 반환


def start_with_computer(enabled):
    """If enabled, create shortcut to start application with computer.
    If disabled, then delete the shortcut."""
    autostart_path = get_autostart_path() #바로가기 아이콘 경로 지정
    if not enabled: #만약 파라미터가 enable 되지 않은 경우
        if os.path.lexists(autostart_path): #바로가기 아이콘이 존재한다면
            FileUtilities.delete(autostart_path) #바로가기 아이콘 삭제
        return #함수 종료
    if os.path.lexists(autostart_path): #만약 바로가기 아이콘이 존재한다면
        return #함수 종료
    import winshell
    winshell.CreateShortcut(Path=autostart_path, #블리치비트 실행파일의 바로가기 아이콘 생성
                            Target=os.path.join(bleachbit.bleachbit_exe_path, 'bleachbit.exe'))

    # import win32com.client
    # wscript_shell = win32com.client.Dispatch('WScript.Shell')
    # shortcut = wscript_shell.CreateShortCut(autostart_path)
    # shortcut.TargetPath = os.path.join(
    #     Common.bleachbit_exe_path, 'bleachbit.exe')
    # shortcut.save()


def start_with_computer_check():
    """Return boolean whether BleachBit will start with the computer"""
    return os.path.lexists(get_autostart_path()) #바로가기 아이콘이 존재여부 반환
