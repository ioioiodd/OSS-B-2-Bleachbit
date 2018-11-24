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
Check for updates via the Internet
"""

from __future__ import absolute_import, print_function

import bleachbit
from bleachbit import _

import hashlib
import logging
import os
import os.path
import platform
import socket
import sys
if sys.version >= (3, 0): #업데이트가 3이상 이하인지 확인하여 import를 다르게 함
    from urllib.request import build_opener
    from urllib.error import URLError
else:
    from urllib2 import build_opener, URLError

import xml.dom.minidom

logger = logging.getLogger(__name__) #로그 기록


def update_winapp2(url, hash_expected, append_text, cb_success):
    """Download latest winapp2.ini file.  Hash is sha512 or None to disable checks"""
    # first, determine whether an update is necessary
    from bleachbit import personal_cleaners_dir
    #해당 OS 형식에 맞도록 입력 받은 경로를 연결합니다. (입력 중간에 절대경로가 나오면 이전에 취합된 경로는 제거하고 다시 연결합니다)
    fn = os.path.join(personal_cleaners_dir, 'winapp2.ini')
    delete_current = False #delete_current 기본값을 false
    if os.path.exists(fn): #파라미터의 주소값이 존재하는지 체크
        f = open(fn, 'r') #fn 주소값이 존재하면 읽기로 열람
        hash_current = hashlib.sha512(f.read()).hexdigest() #sha512 해쉬 알고리즘을 이용하여 해쉬결과값을 hash_current 변수에 저장
        if not hash_expected or hash_current == hash_expected: #해쉬값이 존재하지 않거나 해쉬 예상값과 결과값이 같은 경우
            # update is same as current
            return
        f.close() #열람한 파일 종료
        delete_current = True ##delete_current 기본값을 true
    # download update
    opener = build_opener() #인증데이터나 쿠키데이터를 사용하기 위한 핸들러 설정
    opener.addheaders = [('User-Agent', user_agent())] #user_agent() 반환값을 opener 해더값에 추가
    doc = opener.open(fullurl=url, timeout=20).read() #url 종류와 타임아웃 설정값을 지정하고 url 연결
    # verify hash
    hash_actual = hashlib.sha512(doc).hexdigest() #sha512 해쉬 알고리즘을 이용하여 url 해쉬값을 저장
    if hash_expected and not hash_actual == hash_expected: #해쉬값이 존재하지 않거나 해쉬 예상값과 결과값이 같은 경우
        raise RuntimeError("hash for %s actually %s instead of %s" % #런타임 예외 발생
                           (url, hash_actual, hash_expected))
    # delete current
    if delete_current: #delete_current 값이 true인 경우 = 파라미터 주소값이 존재하지 않고 해쉬가 없거나 해쉬 예상값이 틀린경우
        from bleachbit.FileUtilities import delete
        delete(fn, True) #fn 주소값의 파일을 삭제
    # write file
    if not os.path.exists(personal_cleaners_dir): #personal_cleaners_dir 주소의 파일이 존재하지 않는 경우
        os.mkdir(personal_cleaners_dir) #personal_cleaners_dir 경로의 파일을 새로 생성
    f = open(fn, 'w') #fn 주소의 파일을 쓰기로 열람
    f.write(doc) #doc 내용을 fn 주소의 파일 내용으로 작성
    append_text(_('New winapp2.ini was downloaded.')) #다운로드 되었다는 메시지 추가
    cb_success()


def user_agent(): #사용자의 agent를 문자열로 반환하는 함수
    """Return the user agent string"""
    __platform = platform.system()  # Linux or Windows
    __os = platform.uname()[2]  # e.g., 2.6.28-12-generic or XP
    if sys.platform == "win32":
        # misleading: Python 2.5.4 shows uname()[2] as Vista on Windows 7
        __os = platform.uname()[3][
            0:3]  # 5.1 = Windows XP, 6.0 = Vista, 6.1 = 7
    elif sys.platform.startswith('linux'):
        dist = platform.dist() #리눅스 플랫폼의 정보를 dist에 저장
        # example: ('fedora', '11', 'Leonidas')
        # example: ('', '', '') for Arch Linux
        if 0 < len(dist[0]): #만약 dist에 저장된 값이 있다면
            __os = dist[0] + '/' + dist[1] + '-' + dist[2] #형식을 재지정하여 저장
    elif sys.platform[:6] == 'netbsd': #만약 프로세스 이름을 판별할수 없는 경우(netbsd 값인 경우)
        __sys = platform.system() #시스템, 머신, 릴리즈 정보를 직접 플래폼에서 얻어 저장
        mach = platform.machine()
        rel = platform.release()
        __os = __sys + '/' + mach + ' ' + rel #형식을 재지정하여 저장
    __locale = ""
    try:
        import locale
        __locale = locale.getdefaultlocale()[0]  # e.g., en_US #플랫폼의 기본 언어정보를 가져와 저장
    except: #예외 발생시 메시지 로그 저장
        logger.exception('Exception when getting default locale')

    try:
        import gtk
        gtkver = '; GTK %s' % '.'.join([str(x) for x in gtk.gtk_version]) #gtk 버전을 확인하여 변수에 저장
    except:
        gtkver = "" #예외시 아무값도 입력하지 않음

    #블리치비트 앱버전, 플랫폼 종류, os버전, 언어환경, gtk 버전정보를 포맷에 맞게 변수에 저장
    agent = "BleachBit/%s (%s; %s; %s%s)" % (bleachbit.APP_VERSION,
                                             __platform, __os, __locale, gtkver)
    return agent #agent 정보 반환


def update_dialog(parent, updates):
    """Updates contains the version numbers and URLs"""
    import gtk
    from bleachbit.GuiBasic import open_url
    dlg = gtk.Dialog(title=_("Update BleachBit"), #gtk 대화상자의 설정값을 지정하고 저장
                     parent=parent,
                     flags=gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT)
    dlg.set_default_size(250, 125) #gtk 대화상자의 기본 사이즈 설정

    label = gtk.Label(_("A new version is available.")) #gtk 대화상자의 라벨값 지정
    dlg.vbox.pack_start(label) #수직으로 박스를 포장하도록 설정 vertical

    for update in updates: #버전 정보와 url 값이 저장된 updates들을 순환
        ver = update[0] #버전정보 저장
        url = update[1] #url 정보 저장
        box_update = gtk.HBox() #수평 박스값 저장
        # TRANSLATORS: %s expands to version such as '0.8.4' or '0.8.5beta' or
        # similar
        button_stable = gtk.Button(_("Update to version %s") % ver) #gtk 버튼의 텍스트 지정
        button_stable.connect( #버튼 클릭시 url이 열리도록 커넥션
            'clicked', lambda dummy: open_url(url, parent, False))
        button_stable.connect('clicked', lambda dummy: dlg.response(0)) #버튼 클릭후 response 값은 받지 않음
        box_update.pack_start(button_stable, False, padding=10) #패딩의 값을 10으로 버튼 간격 설정
        dlg.vbox.pack_start(box_update, False) #수직으로 박스를 포장하도록 설정

    dlg.add_button(gtk.STOCK_CLOSE, gtk.RESPONSE_CLOSE) #대화상자에 버튼 추가

    dlg.show_all() #대화상자 모두 show
    dlg.run() #대화상자 실행
    dlg.destroy() #대화상자 삭제

    return False


def check_updates(check_beta, check_winapp2, append_text, cb_success):
    """Check for updates via the Internet"""
    opener = build_opener() #인증데이터나 쿠키데이터를 사용하기 위한 핸들러 설정
    socket.setdefaulttimeout(bleachbit.socket_timeout) #인터넷 세션 연결 타임은 블리치비트에서 정한 timeout 값으로 설정
    opener.addheaders = [('User-Agent', user_agent())] #user_agent() 반환값을 opener 해더값에 추가
    try:
        handle = opener.open(bleachbit.update_check_url) #블리치비트 업데이트 url을 오픈하여 핸들러에 할당
    except URLError: #예외 발생시 로그 기록
        logger.exception(
            _('Error when opening a network connection to %s to check for updates. Please verify the network is working.' %
                bleachbit.update_check_url))
        return () #함수 종료
    doc = handle.read() #핸들러를 읽어 doc 변수에 저장
    try:
        dom = xml.dom.minidom.parseString(doc) #xml 형태로 doc 파싱
    except: #예외 발생시 로그 기록
        logger.exception('The update information does not parse: %s', doc)
        return () #함수 종료

    def parse_updates(element): #파라미터를 전달받아 버전과 url 정보를 반환
        if element: #파라미터가 유효값이면
            ver = element[0].getAttribute('ver') #버전정보 저장
            url = element[0].firstChild.data #url 정보 저장
            return ver, url #정보 리턴
        return ()

    #xml형태로 파싱한 데이터에서 태그이름이 stable인 대상의 버전,url정보 값 저장
    stable = parse_updates(dom.getElementsByTagName("stable"))
    #xml형태로 파싱한 데이터에서 태그이름이 beta인 대상의 버전,url정보 값 저장
    beta = parse_updates(dom.getElementsByTagName("beta"))

    #xml형태로 파싱한 데이터에서 태그이름이 winapp2인 대상의 버전,url정보 값 저장
    wa_element = dom.getElementsByTagName('winapp2')
    if check_winapp2 and wa_element: # check_winapp2와 wa_element가 존재한다면
        wa_sha512 = wa_element[0].getAttribute('sha512') #wa_element의 해쉬값 저장
        wa_url = wa_element[0].getAttribute('url') #wa_element의 url값 저장
        #위에서 얻은 정보를 파라미터로 winapp2를 업데이트 하는 함수 실행
        update_winapp2(wa_url, wa_sha512, append_text, cb_success)

    dom.unlink() #url 세션 연결 종료

    if stable and beta and check_beta: #체크 여부를 확인하여 체크한 대상을 리턴
        return stable, beta
    if stable:
        return stable,
    if beta and check_beta:
        return beta,
    return ()
