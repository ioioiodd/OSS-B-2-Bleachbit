#!/usr/bin/env python
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
Command line interface
"""

from __future__ import absolute_import, print_function

from bleachbit.Cleaner import backends, create_simple_cleaner, register_cleaners
from bleachbit import _, APP_VERSION, encoding
from bleachbit import Diagnostic, Options, Worker

import logging
import optparse
import os
import sys

logger = logging.getLogger(__name__)


class CliCallback:
    """Command line's callback passed to Worker"""

    """인코딩 형식 파라미터를 전달받아 encoding 또는 UTF8로 형식 지정"""
    def __init__(self):
        """Initialize CliCallback"""
        self.encoding = encoding if encoding else 'UTF8'

    def append_text(self, msg, tag=None):
        """Write text to the terminal"""
        # If the encoding is not explicitly handled on a non-UTF-8
        # system, then special Latin-1 characters such as umlauts may
        # raise an exception as an encoding error.
        """ 기존 메시지에 추가 메시지를 추가하는 함수로 encoding 형식이 다를경우 _init_함수에서 설정한
        encoding 형식으로 변환 후 메시지를 합친다. """
        print(msg.strip('\n').encode(self.encoding, 'replace'))

    def update_progress_bar(self, status):
        """Not used"""
        pass

    def update_total_size(self, size):
        """Not used"""
        pass

    def update_item_size(self, op, opid, size):
        """Not used"""
        pass

    def worker_done(self, worker, really_delete):
        """Not used"""
        pass


def cleaners_list():
    """Yield each cleaner-option pair"""
    register_cleaners() """Cleaner 파일의 모든 클리너를 추가하는 register_cleaners 함수 호출"""
    """Cleaner 파일에서 clear 쌍이 저장되어 있는 전역변수 backends 리스트 변수를 호출하여 정렬
     후 반복문 실행"""
    for key in sorted(backends):
        c_id = backends[key].get_id()
        """클리너 아이디와 옵션 값을 쌍으로 저장하여 리스트화"""
        for (o_id, o_name) in backends[key].get_options():
            yield "%s.%s" % (c_id, o_id)

def list_cleaners():
    """Display available cleaners"""
    """cleaners_list 함수를 호출하여 반환되는 클리너들의 종류를 보여주는 함수"""
    for cleaner in cleaners_list():
        print (cleaner)


def preview_or_clean(operations, really_clean):
    """Preview deletes and other changes"""
    cb = CliCallback() """CliCallback 인스턴스 생성"""
    worker = Worker.Worker(cb, really_clean, operations).run() """비동기 작업을 진행할 worker에 오퍼레이션을 할당"""
    while worker.next(): """worker 리스트에 저장된 worker가 있는지 순환 실행""""
        pass


"""인수를 읽고 작업목록을 반환하는 함수"""
def args_to_operations(args, preset):
    """Read arguments and return list of operations"""
    register_cleaners() ""Cleaner 파일의 모든 클리너를 추가하는 register_cleaners 함수 호출"""
    operations = {} """리스트 변수 선언"""
    if preset:
        # restore presets from the GUI
        for key in sorted(backends): """Cleaner 파일에서 clear 쌍이 저장되어 있는 전역변수 backends 리스트 변수를 호출하여 정렬
         후 반복문 실행"""
            c_id = backends[key].get_id()
            """클리너 아이디와 옵션 값을 쌍으로 저장하여 리스트화"""
            for (o_id, o_name) in backends[key].get_options():
                """오퍼레이션 인수값과 클리너들을 '.' 기호로 구분하여 머지한 후 저장"""
                if Options.options.get_tree(c_id, o_id):
                    args.append('.'.join([c_id, o_id]))
    for arg in args: """인수값들 반복문 실행"""
        if 2 != len(arg.split('.')): """인수에 대한 클리너가 없는 경우"""
            logger.warning(_("not a valid cleaner: %s"), arg) """로그에 유효한 클리너가 없다는 메시지 추가"""
            continue
        (cleaner_id, option_id) = arg.split('.') """인수에 대한 클리너가 없는 경우 . 기호를 구분자로 클리너id, 옵션id key-value로 저장"""
        # enable all options (for example, firefox.*)
        if '*' == option_id: """만약 옵션id가 모든 옵션(웹브라우져)를 사용하는 경우"""
            if cleaner_id in operations: """기존의 오퍼레이션 리스트의 값을 전부 지움"""
                del operations[cleaner_id]
            operations[cleaner_id] = [] """초기화"""
            for (option_id2, o_name) in backends[cleaner_id].get_options(): """옵션id2와 옵션 이름으로 key-value 후 반복문 실행"""
                operations[cleaner_id].append(option_id2) """오퍼레이션 리스트 변수에 option_id2 추가"""
            continue
        # add the specified option
        if cleaner_id not in operations: """만약 클리너id가 포함된 오퍼레이션 리스트가 없다면 초기화"""
            operations[cleaner_id] = []
        if option_id not in operations[cleaner_id]: """만약 오퍼레이션 리스트에 오퍼레이션 아이디가 없다면 추가"""
            operations[cleaner_id].append(option_id)
    for (k, v) in operations.items(): """오퍼레시연 리스트 정렬 후 저장"""
        operations[k] = sorted(v)
    return operations """작업목록 오퍼레이션 반환"""

"""사용자로 부터 커맨드 라인 명령문을 입력받아 이를 파싱하고 작업을 실행하는 함수"""
""" 윈도우에선 bleachbit_console.exe 실행하여 커맨드라인 입력, 리눅스에선 블리치비트 실행 후 입력"""
def process_cmd_line():
    """Parse the command line and execute given commands."""
    # TRANSLATORS: This is the command line usage.  Don't translate
    # %prog, but do translate usage, options, cleaner, and option.
    # More information about the command line is here
    # https://www.bleachbit.org/documentation/command-line
    """usage : 프로그램 사용법을 설명하는 문자열 (기본값: 파서에 추가된 인자로부터 만들어지는 값)"""
    usage = _("usage: %prog [options] cleaner.option1 cleaner.option2")
    parser = optparse.OptionParser(usage)  """파서변수 선언 후 초기화"""
    """사용자로 부터 입력받는 명령어의 옵션값과 실제 실행될 함수, 그리고 도움말 정보를 저장"""
    parser.add_option("-l", "--list-cleaners", action="store_true",
                      help=_("list cleaners"))
    parser.add_option("-c", "--clean", action="store_true",
                      # TRANSLATORS: predefined cleaners are for applications, such as Firefox and Flash.
                      # This is different than cleaning an arbitrary file, such as a
                      # spreadsheet on the desktop.
                      help=_("run cleaners to delete files and make other permanent changes"))
    parser.add_option('--debug-log', help='log debug messages to file')
    parser.add_option("-s", "--shred", action="store_true",
                      help=_("shred specific files or folders"))
    parser.add_option("--sysinfo", action="store_true",
                      help=_("show system information"))
    parser.add_option("--gui", action="store_true",
                      help=_("launch the graphical interface"))
    parser.add_option('--exit', action='store_true',
                      help=optparse.SUPPRESS_HELP)
    """window nt 버전 관리자권한(uac) 묻지 않음"""
    if 'nt' == os.name:
        uac_help = _("do not prompt for administrator privileges")
    else: """nt 버전 이외의 윈도우 환경에서는 uac 권한 필요"""
        uac_help = optparse.SUPPRESS_HELP
    parser.add_option("--no-uac", action="store_true", help=uac_help)
    parser.add_option("-p", "--preview", action="store_true",
                      help=_("preview files to be deleted and other changes"))
    parser.add_option('--pot', action='store_true',
                      help=optparse.SUPPRESS_HELP)
    parser.add_option("--preset", action="store_true",
                      help=_("use options set in the graphical interface"))
    if 'nt' == os.name: """nt 버전에서의 추가 명령어 옵션 설정"""
        parser.add_option("--update-winapp2", action="store_true",
                          help=_("update winapp2.ini, if a new version is available"))
    parser.add_option("-v", "--version", action="store_true",
                      help=_("output version information and exit"))
    parser.add_option('-o', '--overwrite', action='store_true',
                      help=_('overwrite files to hide contents'))
    (options, args) = parser.parse_args() """ 명령어 옵션 리스트 추가"""
    did_something = False
    """블리치비트의 디버그 로그를 확인하여 현재 빌리치 비트버전을 로그에 추가"""
    if options.debug_log:
        logger.addHandler(logging.FileHandler(options.debug_log))
        logger.info('BleachBit version %s', APP_VERSION)
        logger.info(Diagnostic.diagnostic_info())
        """블리치비트 프로그램의 정보와 현재 버전을 출력"""
    if options.version:
        print("""
BleachBit version %s
Copyright (C) 2008-2018 Andrew Ziem.  All rights reserved.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.""" % APP_VERSION)
        sys.exit(0)
    """만약 윈도우nt 버전이거나 winapp2.ini 파일이 존재하는 경우 서버에서 winapp2.ini 파일 업데이트"""
    if 'nt' == os.name and options.update_winapp2:
        from bleachbit import Update
        logger.info("Checking online for updates to winapp2.ini")
        Update.check_updates(False, True,
                             lambda x: sys.stdout.write("%s\n" % x),
                             lambda: None)
        # updates can be combined with --list, --preview, --clean
        did_something = True """업데이트 했다는 이력을 변수에 체크"""
    if options.list_cleaners: """만약 클리너 리스트에 값들이 존재하면 리스트의 클리너들을 실행하고 종료"""
        list_cleaners()
        sys.exit(0)
    if options.pot: """만약 .pot 확장자를 사용할 수 있다면 cleanerML 파일에 정의된 .pot 파일에 로그를 기록하는 함수 실행"""
        from bleachbit.CleanerML import create_pot
        create_pot()
        sys.exit(0)
    if options.preview or options.clean: """만약 미리보기 또는 청소하기를 실행한 경우"""
        operations = args_to_operations(args, options.preset) """오퍼레이션 인자들을 함수에 저장"""
        if not operations: """만약 오퍼레이션 인자가 없다면"""
            logger.error('No work to do. Specify options.') """미리보기 또는 청소하기를 눌렀지만 인자는 선택하지 않았음을 로그에 기록"""
            sys.exit(1)
    if options.preview: """만약 미리보기를 선택했다면 preview_or_clean 함수 실행"""
        preview_or_clean(operations, False)
        sys.exit(0)
    if options.overwrite: """overwrite와 clean을 함께 사용하지 않았다면 함께 사용해야함을 알리는 메시지를 로그에 추가"""
        if not options.clean or options.shred:
            logger.warning('--overwrite is intended only for use with --clean')
        Options.options.set('shred', True, commit=False)
    if options.clean: """청소하기(clean) 명령어를 입력한 경우 preview_or_clean 함수 실행"""
        preview_or_clean(operations, True)
        sys.exit(0)
    if options.gui: """gui 명령어 옵션을 입력한 경우"""
        import gtk
        from bleachbit import GUI """블리치 비트 gui 파일의 함수 사용"""
        shred_paths = args if options.shred else None """파일 파기 옵션을 선택한 경우 파일의 경로 지정"""
        GUI.GUI(uac=not options.no_uac, """사용자 권한설정, 파기파일 경로, 종료 옵션값 설정"""
                shred_paths=shred_paths, exit=options.exit)
        gtk.main()
        if options.exit:
            # For automated testing of Windows build
            print('Success')
        sys.exit(0)
    if options.shred: """shred 옵션을 선택한 경우"""
        # delete arbitrary files without GUI
        # create a temporary cleaner object
        backends['_gui'] = create_simple_cleaner(args) """새로운 클리너 리스트를 만들고 backends 전역리스트에 저장"""
        operations = {'_gui': ['files']} """오퍼레이션 값 설정"""
        preview_or_clean(operations, True) """preview_or_clean 함수 실행"""
        sys.exit(0)
    if options.sysinfo: """sysinfo 옵션을 선택한 경우"""
        print(Diagnostic.diagnostic_info()) """특이사항 출력"""
        sys.exit(0)
    if not did_something:
        parser.print_help()


if __name__ == '__main__': """로그의 _name_ 이 __main_인 경우 process_cmd_line() 호출"""
    process_cmd_line()
