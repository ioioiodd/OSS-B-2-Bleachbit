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
Command design pattern implementation for cleaning
"""

from __future__ import absolute_import, print_function

from bleachbit import _
from bleachbit import FileUtilities

import logging
import os
import types

from sqlite3 import DatabaseError

#window nt 인 경우를 판단하여 import 변경
if 'nt' == os.name:
    import bleachbit.Windows
else:
    from bleachbit.General import WindowsError

#화이트 리스트를 추가하고 정보를 리턴하는 함수
def whitelist(path):
    """Return information that this file was whitelisted"""
    ret = {
        # TRANSLATORS: This is the label in the log indicating was
        # skipped because it matches the whitelist
        'label': _('Skip'),
        'n_deleted': 0,
        'n_special': 0,
        'path': path,
        'size': 0}
    return ret


class Delete:

    """Delete a single file or directory.  Obey the user
    preference regarding shredding."""

    #삭제할 파일이나 디렉토리 정보를 저장하는 초기 실행함수
    def __init__(self, path):
        """Create a Delete instance to delete 'path'"""
        self.path = path
        self.shred = False

    def __str__(self):
        return 'Command to %s %s' % \ #self에 저장된 shred, path 정보를 이용하여 커맨드 라인에 작성할 스트링값 리턴
            ('shred' if self.shred else 'delete', self.path)

    def execute(self, really_delete):
        """Make changes and return results"""
        if FileUtilities.whitelisted(self.path): #화이트리스트에 self의 경로를 비교
            yield whitelist(self.path) #화이트리스트 함수를 이터레이터로 사용하기 위해 설정
            return
        ret = {         #리턴할 딕셔너리에 self 파라미터의 path, 파일 사이즈 값 저장
            # TRANSLATORS: This is the label in the log indicating will be
            # deleted (for previews) or was actually deleted
            'label': _('Delete'),
            'n_deleted': 1,
            'n_special': 0,
            'path': self.path,
            'size': FileUtilities.getsize(self.path)}
        if really_delete: #만약 정말 삭제할 경우
            try:
                FileUtilities.delete(self.path, self.shred) #설정된 경로의 파일 또는 디렉토리를 삭제
            except WindowsError as e: #만약 예외상황이 발생한다면
                # WindowsError: [Error 32] The process cannot access the file because it is being
                # used by another process: u'C:\\Documents and
                # Settings\\username\\Cookies\\index.dat'
                if 32 != e.winerror and 5 != e.winerror:
                    raise
                try:
                    bleachbit.Windows.delete_locked_file(self.path) #lock 상태의 파일을 삭제하는 함수 실행
                except:
                    raise
                else:
                    if self.shred: #다른 프로세스에서 사용중인 파일이 있는경우 종료하거나 리붓후 삭제됨을 안내
                        import warnings
                        warnings.warn(
                            _('At least one file was locked by another process, so its contents could not be overwritten. It will be marked for deletion upon system reboot.'))
                    # TRANSLATORS: The file will be deleted when the
                    # system reboots
                    ret['label'] = _('Mark for deletion') #return 딕셔너리에 삭제한 이력을 추가
        yield ret


class Function:

    """Execute a simple Python function"""

    def __init__(self, path, func, label):
        """Path is a pathname that exists or None.  If
        it exists, func takes the pathname.  Otherwise,
        function returns the size."""
        self.path = path #파라미터로 전달받은 매개변수를 self의 정보로 초기화
        self.func = func
        self.label = label
        try:
            assert isinstance(func, types.FunctionType) #vector 인스턴스 생성
        except AssertionError: #vector 인스턴스 생성 오류시
            raise AssertionError('Expected MethodType but got %s' % type(func)) #AssertionError 에러 발생

    def __str__(self): #self의 label, path의 정보를 전달받는 함수
        if self.path: #self 의 path값이 존재하는 경우"""
            return 'Function: %s: %s' % (self.label, self.path)
        else:
            return 'Function: %s' % (self.label)

    def execute(self, really_delete):

        #self.path 가 존재하고 FileUtilities의 화이트리스트에 존재하는 경우
        if self.path is not None and FileUtilities.whitelisted(self.path):
            yield whitelist(self.path) #화이트 리스트에 추가
            return

        ret = {  #리턴 딕셔너리 추가
            'label': self.label,
            'n_deleted': 0,
            'n_special': 1,
            'path': self.path,
            'size': None}

        if really_delete: #만약 really_delete가 트루인경우
            if self.path is None: #만약 self.path 가 존재하지 않는 경우 사이즈 리턴
                # Function takes no path.  It returns the size.
                func_ret = self.func()  #function을 리턴할 함수에 self.func()값 할당
                if isinstance(func_ret, types.GeneratorType): #func_ret 변수의 타입이 제너레이터 타입인 경우
                    # function returned generator
                    for func_ret in self.func(): # 제너레이터 순환
                        if True == func_ret or isinstance(func_ret, tuple): #인스턴스가 정상적으로 할댕되었다면
                            # Return control to GTK idle loop.
                            # If tuple, then display progress.
                            yield func_ret #funct_ret 실행
                # either way, func_ret should be an integer
                assert isinstance(func_ret, (int, long)) #vector 인스턴스 생성
                ret['size'] = func_ret #ret 딕셔너리에 사이즈값 추가
            else: #만약 self.path 가 존재한다면
                if os.path.isdir(self.path): #실제 운영체제 내부 디렉토리가 있는지 체크
                    raise RuntimeError('Attempting to run file function %s on directory %s' %
                                       (self.func.func_name, self.path)) #디렉토리가 복잡하여 시간이 오래걸릴경우 런타임 에러 발생
                # Function takes a path.  We check the size.
                oldsize = FileUtilities.getsize(self.path) #파일의 사이즈값 변수에 저장
                try:
                    self.func(self.path) #path값을 파라미터로 self에 저장된 함수 실행
                except DatabaseError as e: #에러발생시 처리 구문
                    if -1 == e.message.find('file is encrypted or is not a database') and \
                       -1 == e.message.find('or missing database'):
                        raise
                    logging.getLogger(__name__).exception(e.message) #databaseerror 발생시 로그에 예외처리 기록
                    return
                try:
                    newsize = FileUtilities.getsize(self.path) #파일의 사이즈값 변수에 저장
                except OSError as e: #운영체제 관련 오류 발생시
                    from errno import ENOENT
                    if e.errno == ENOENT: #만약 파일 자체가 존재하지 않으면
                        # file does not exist
                        newsize = 0 #파일 사이즈는 0
                    else:
                        raise
                ret['size'] = oldsize - newsize #사이즈값 저장
        yield ret


class Ini:

    """Remove sections or parameters from a .ini file"""

    #전달받은 파라미터를 기준으로 초기화
    def __init__(self, path, section, parameter):
        """Create the instance"""
        self.path = path
        self.section = section
        self.parameter = parameter

    #_init_ 함수로 전달받은 초기값들을 이용하여 커맨드 라인에 사용할 명령어 값 반환
    def __str__(self):
        return 'Command to clean .ini path=%s, section=-%s, parameter=%s ' % \
            (self.path, self.section, self.parameter)

    def execute(self, really_delete):
        """Make changes and return results"""

        if FileUtilities.whitelisted(self.path): #self.path 가 존재하고 FileUtilities의 화이트리스트에 존재하는 경우
            yield whitelist(self.path) #화이트 리스트에 추가
            return

        ret = { #리턴 딕셔너리 추가
            # TRANSLATORS: Parts of this file will be deleted
            'label': _('Clean file'),
            'n_deleted': 0,
            'n_special': 1,
            'path': self.path,
            'size': None}
        if really_delete: #만약 really_delete가 트루인경우
            oldsize = FileUtilities.getsize(self.path) #파일의 사이즈값 변수에 저장
            FileUtilities.clean_ini(self.path, self.section, self.parameter) #파일안의 섹션과 파라미터 삭제
            newsize = FileUtilities.getsize(self.path) #파일의 변경된 사이즈값 변수에 저장
            ret['size'] = oldsize - newsize #사이즈 변화값 저장
        yield ret

#json 파일 클래스
class Json:

    """Remove a key from a JSON configuration file"""

    #전달받은 파라미터를 기준으로 초기화
    def __init__(self, path, address):
        """Create the instance"""
        self.path = path
        self.address = address

    #_init_ 함수로 전달받은 초기값들을 이용하여 커맨드 라인에 사용할 명령어 값 반환
    def __str__(self):
        return 'Command to clean JSON file, path=%s, address=%s ' % \
            (self.path, self.address)

    def execute(self, really_delete):
        """Make changes and return results"""

        if FileUtilities.whitelisted(self.path): #self.path 가 존재하고 FileUtilities의 화이트리스트에 존재하는 경우
            yield whitelist(self.path) #화이트 리스트에 추가
            return

        ret = { #리턴 딕셔너리 추가
            'label': _('Clean file'),
            'n_deleted': 0,
            'n_special': 1,
            'path': self.path,
            'size': None}
        if really_delete: #만약 really_delete가 트루인경우
            oldsize = FileUtilities.getsize(self.path) #파일의 사이즈값 변수에 저장
            FileUtilities.clean_json(self.path, self.address) #jason 파일안의 주소 삭제
            newsize = FileUtilities.getsize(self.path) #파일의 변경된 사이즈값 변수에 저장
            ret['size'] = oldsize - newsize #사이즈 변화값 저장
        yield ret


class Shred(Delete):

    """Shred a single file"""

    def __init__(self, path): #전달받은 파라미터를 기준으로 초기화
        """Create an instance to shred 'path'"""
        Delete.__init__(self, path) #path 파일 삭제
        self.shred = True #동기화 여부를 체크하는 .shred 값 트루로 변경

    def __str__(self): #_init_ 함수로 전달받은 초기값들을 이용하여 커맨드 라인에 사용할 명령어 값 반환
        return 'Command to shred %s' % self.path


class Truncate(Delete):

    """Truncate a single file"""

    #_init_ 함수로 전달받은 초기값들을 이용하여 커맨드 라인에 사용할 명령어 값 반환
    def __str__(self):
        return 'Command to truncate %s' % self.path

    def execute(self, really_delete):
        """Make changes and return results"""

        if FileUtilities.whitelisted(self.path): #self.path 가 존재하고 FileUtilities의 화이트리스트에 존재하는 경우
            yield whitelist(self.path) #화이트 리스트에 추가
            return

        ret = { #리턴 딕셔너리 추가
            # TRANSLATORS: The file will be truncated to 0 bytes in length
            'label': _('Truncate'),
            'n_deleted': 1,
            'n_special': 0,
            'path': self.path,
            'size': FileUtilities.getsize(self.path)}
        if really_delete: #만약 really_delete가 트루인경우
            f = open(self.path, 'wb') #경로의 파일을 쓰기 모드로 열람
            f.truncate(0) #내용 삭제
        yield ret


class Winreg:

    """Clean Windows registry"""

    #전달받은 파라미터를 기준으로 초기화
    def __init__(self, keyname, valuename):
        """Create the Windows registry cleaner"""
        self.keyname = keyname
        self.valuename = valuename

    def __str__(self): #_init_ 함수로 전달받은 초기값들을 이용하여 커맨드 라인에 사용할 명령어 값 반환
        return 'Command to clean registry, key=%s, value=%s ' % (self.keyname, self.valuename)

    def execute(self, really_delete):
        """Execute the Windows registry cleaner"""
        if 'nt' != os.name: #window 버전이 nt 가 아닌경우
            raise StopIteration #StopIteration 예외발생
        _str = None  # string representation
        ret = None  # return value meaning 'deleted' or 'delete-able'
        if self.valuename: #vlauename 이 존재 한다면
            _str = '%s<%s>' % (self.keyname, self.valuename) #_str 변수에 self의 keyname과 valuename 을 포함한 스트링값 저장
            ret = bleachbit.Windows.delete_registry_value(self.keyname, #윈도우 레지스트리 밸류를 삭제하는 함수 실행
                                                self.valuename, really_delete)
        else:
            ret = bleachbit.Windows.delete_registry_key(self.keyname, really_delete) #윈도우 레지스트리키를 삭제하는 함수 실행
            _str = self.keyname #key이름 저장
        if not ret: #삭제할 레지스트리가 없다면
            # Nothing to delete or nothing was deleted.  This return
            # makes the auto-hide feature work nicely.
            raise StopIteration #StopIteration 예외 발생

        ret = { #리턴 딕셔너리 추가
            'label': _('Delete registry key'),
            'n_deleted': 0,
            'n_special': 1,
            'path': _str,
            'size': 0}

        yield ret
