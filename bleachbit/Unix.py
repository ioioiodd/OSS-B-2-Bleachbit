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
Integration specific to Unix-like operating systems
"""

from __future__ import absolute_import, print_function

import bleachbit
from bleachbit import FileUtilities, General
from bleachbit import _

import glob
import logging
import os
import re
import shlex
import subprocess
import sys

logger = logging.getLogger(__name__)


class LocaleCleanerPath:
    """This represents a path with either a specific folder name or a folder name pattern.
    It also may contain several compiled regex patterns for localization items (folders or files)
    and additional LocaleCleanerPaths that get traversed when asked to supply a list of localization
    items"""

    def __init__(self, location):
        if location is None: #파라미터로 전달받은 로케이션 값이 없다면
            raise RuntimeError("location is none") #런타임 예외 발생
        self.pattern = location #전달받은 파라미터에 location 추가
        self.children = []  #하위 경로는 일단 빈값으로 저장

    def add_child(self, child):
        """Adds a child LocaleCleanerPath"""
        self.children.append(child) #파라미터로 전달받은 self의 자식으로 child 파라미터를 추가
        return child #child 변수 리턴

    def add_path_filter(self, pre, post):
        """Adds a filter consisting of a prefix and a postfix
        (e.g. 'foobar_' and '\.qm' to match 'foobar_en_US.utf-8.qm)"""
        try: #정규식 형식으로 변환
            regex = re.compile('^' + pre + Locales.localepattern + post + '$')
        except Exception as errormsg: #오류 발생시 예외 발생
            raise RuntimeError("Malformed regex '%s' or '%s': %s" % (pre, post, errormsg))
        self.add_child(regex) #자식 경로 추가

    def get_subpaths(self, basepath):
        """Returns direct subpaths for this object, i.e. either the named subfolder or all
        subfolders matching the pattern"""
        if isinstance(self.pattern, re._pattern_type): #인스턴스 생성
            return (os.path.join(basepath, p) for p in os.listdir(basepath) #basepath 리스트 순환
                    #p가 self의 패턴과 맞는지 비교하고 해당 경로가 실제 존재하는지 체크
                    if self.pattern.match(p) and os.path.isdir(os.path.join(basepath, p)))
        else:
            path = os.path.join(basepath, self.pattern) #해당 OS 형식에 맞도록 입력 받은 경로를 연결
            return [path] if os.path.isdir(path) else [] #만약 path 경로가 존재한다면 path 반환

    def get_localizations(self, basepath):
        """Returns all localization items for this object and all descendant objects"""
        for path in self.get_subpaths(basepath): #basepath의 하위 path 순환
            for child in self.children: #self의 하위 자식들 순환
                if isinstance(child, LocaleCleanerPath): #child, LocaleCleanerPath 인스턴스가 생성된다면
                    for res in child.get_localizations(path): #child에서 재귀함수 실행
                        yield res
                elif isinstance(child, re._pattern_type): #정규표현식으로 인스턴스 생성
                    for element in os.listdir(path): #path 경로의 리스트 순환
                        match = child.match(element) #child와 elemnt가 매치되는지 체크
                        if match is not None: # 만약 child와 elemnt가 됬다면
                            yield (match.group('locale'), os.path.join(path, element)) #그룹화하고 경로간 조인


class Locales:
    """Find languages and localization files"""

    # The regular expression to match locale strings and extract the langcode.
    # See test_locale_regex() in tests/TestUnix.py for examples
    # This doesn't match all possible valid locale strings to avoid
    # matching filenames you might want to keep, e.g. the regex
    # to match jp.eucJP might also match jp.importantfileextension
    localepattern =\ #정규표현식 설정
        r'(?P<locale>[a-z]{2,3})' \
        r'(?:[_-][A-Z]{2,4}(?:\.[\w]+[\d-]+|@\w+)?)?' \
        r'(?P<encoding>[.-_](?:(?:ISO|iso|UTF|utf)[\d-]+|(?:euc|EUC)[A-Z]+))?'

    native_locale_names = \ #지원되는 언어 딕셔너리화
        {'aa': 'Afaraf',
         'ab': 'аҧсуа бызшәа',
         'ach': 'Acoli',
         'ae': 'avesta',
         'af': 'Afrikaans',
         'ak': 'Akan',
         'am': 'አማርኛ',
         'an': 'aragonés',
         'ang': 'Old English',
         'ar': 'العربية',
         'as': 'অসমীয়া',
         'ast': 'Asturianu',
         'av': 'авар мацӀ',
         'ay': 'aymar aru',
         'az': 'azərbaycan dili',
         'ba': 'башҡорт теле',
         'bal': 'Baluchi',
         'be': 'Беларуская мова',
         'bg': 'български език',
         'bh': 'भोजपुरी',
         'bi': 'Bislama',
         'bm': 'bamanankan',
         'bn': 'বাংলা',
         'bo': 'བོད་ཡིག',
         'br': 'brezhoneg',
         'bs': 'босански',
         'byn': 'Bilin',
         'ca': 'català',
         'ce': 'нохчийн мотт',
         'cgg': 'Chiga',
         'ch': 'Chamoru',
         'ckb': 'Central Kurdish',
         'co': 'corsu',
         'cr': 'ᓀᐦᐃᔭᐍᐏᐣ',
         'crh': 'Crimean Tatar',
         'cs': 'česky',
         'csb': 'Cashubian',
         'cu': 'ѩзыкъ словѣньскъ',
         'cv': 'чӑваш чӗлхи',
         'cy': 'Cymraeg',
         'da': 'dansk',
         'de': 'Deutsch',
         'dv': 'ދިވެހި',
         'dz': 'རྫོང་ཁ',
         'ee': 'Eʋegbe',
         'el': 'Ελληνικά',
         'en': 'English',
         'en_AU': 'Australian English',
         'en_CA': 'Canadian English',
         'en_GB': 'British English',
         'eo': 'Esperanto',
         'es': 'Español',
         'et': 'eesti',
         'eu': 'euskara',
         'fa': 'فارسی',
         'ff': 'Fulfulde',
         'fi': 'suomen kieli',
         'fj': 'vosa Vakaviti',
         'fo': 'føroyskt',
         'fr': 'Français',
         'fur': 'Frilian',
         'fy': 'Frysk',
         'ga': 'Gaeilge',
         'gd': 'Gàidhlig',
         'gez': 'Geez',
         'gl': 'galego',
         'gn': 'Avañeẽ',
         'gu': 'Gujarati',
         'gv': 'Gaelg',
         'ha': 'هَوُسَ',
         'haw': 'Hawaiian',
         'he': 'עברית',
         'hi': 'हिन्दी',
         'hne': 'Chhattisgarhi',
         'ho': 'Hiri Motu',
         'hr': 'Hrvatski',
         'hsb': 'Upper Sorbian',
         'ht': 'Kreyòl ayisyen',
         'hu': 'Magyar',
         'hy': 'Հայերեն',
         'hz': 'Otjiherero',
         'ia': 'Interlingua',
         'id': 'Indonesian',
         'ig': 'Asụsụ Igbo',
         'ii': 'ꆈꌠ꒿',
         'ik': 'Iñupiaq',
         'io': 'Ido',
         'is': 'Íslenska',
         'it': 'Italiano',
         'iu': 'ᐃᓄᒃᑎᑐᑦ',
         'iw': 'עברית',
         'ja': '日本語',
         'jv': 'basa Jawa',
         'ka': 'ქართული',
         'kg': 'Kikongo',
         'ki': 'Gĩkũyũ',
         'kj': 'Kuanyama',
         'kk': 'қазақ тілі',
         'kl': 'kalaallisut',
         'km': 'ខ្មែរ',
         'kn': 'ಕನ್ನಡ',
         'ko': '한국어',
         'kok': 'Konkani',
         'kr': 'Kanuri',
         'ks': 'कश्मीरी',
         'ku': 'Kurdî',
         'kv': 'коми кыв',
         'kw': 'Kernewek',
         'ky': 'Кыргызча',
         'la': 'latine',
         'lb': 'Lëtzebuergesch',
         'lg': 'Luganda',
         'li': 'Limburgs',
         'ln': 'Lingála',
         'lo': 'ພາສາລາວ',
         'lt': 'lietuvių kalba',
         'lu': 'Tshiluba',
         'lv': 'latviešu valoda',
         'mai': 'Maithili',
         'mg': 'fiteny malagasy',
         'mh': 'Kajin M̧ajeļ',
         'mhr': 'Eastern Mari',
         'mi': 'te reo Māori',
         'mk': 'македонски јазик',
         'ml': 'മലയാളം',
         'mn': 'монгол',
         'mr': 'मराठी',
         'ms': 'بهاس ملايو',
         'mt': 'Malti',
         'my': 'ဗမာစာ',
         'na': 'Ekakairũ Naoero',
         'nb': 'Bokmål',
         'nd': 'isiNdebele',
         'nds': 'Plattdüütsch',
         'ne': 'नेपाली',
         'ng': 'Owambo',
         'nl': 'Nederlands',
         'nn': 'Norsk nynorsk',
         'no': 'Norsk',
         'nr': 'isiNdebele',
         'nso': 'Pedi',
         'nv': 'Diné bizaad',
         'ny': 'chiCheŵa',
         'oc': 'occitan',
         'oj': 'ᐊᓂᔑᓈᐯᒧᐎᓐ',
         'om': 'Afaan Oromoo',
         'or': 'ଓଡ଼ିଆ',
         'os': 'ирон æвзаг',
         'pa': 'ਪੰਜਾਬੀ',
         'pi': 'पाऴि',
         'pl': 'polski',
         'ps': 'پښتو',
         'pt': 'Português',
         'pt_BR': 'Português do Brasil',
         'qu': 'Runa Simi',
         'rm': 'rumantsch grischun',
         'rn': 'Ikirundi',
         'ro': 'română',
         'ru': 'Pусский',
         'rw': 'Ikinyarwanda',
         'sa': 'संस्कृतम्',
         'sc': 'sardu',
         'sd': 'सिन्धी',
         'se': 'Davvisámegiella',
         'sg': 'yângâ tî sängö',
         'shn': 'Shan',
         'si': 'සිංහල',
         'sk': 'slovenčina',
         'sl': 'slovenščina',
         'sm': 'gagana faa Samoa',
         'sn': 'chiShona',
         'so': 'Soomaaliga',
         'sq': 'Shqip',
         'sr': 'Српски',
         'ss': 'SiSwati',
         'st': 'Sesotho',
         'su': 'Basa Sunda',
         'sv': 'svenska',
         'sw': 'Kiswahili',
         'ta': 'தமிழ்',
         'te': 'తెలుగు',
         'tet': 'Tetum',
         'tg': 'тоҷикӣ',
         'th': 'ไทย',
         'ti': 'ትግርኛ',
         'tig': 'Tigre',
         'tk': 'Türkmen',
         'tl': 'ᜏᜒᜃᜅ᜔ ᜆᜄᜎᜓᜄ᜔',
         'tn': 'Setswana',
         'to': 'faka Tonga',
         'tr': 'Türkçe',
         'ts': 'Xitsonga',
         'tt': 'татар теле',
         'tw': 'Twi',
         'ty': 'Reo Tahiti',
         'ug': 'Uyghur',
         'uk': 'Українська',
         'ur': 'اردو',
         'uz': 'Ўзбек',
         've': 'Tshivenḓa',
         'vi': 'Tiếng Việt',
         'vo': 'Volapük',
         'wa': 'walon',
         'wae': 'Walser',
         'wal': 'Wolaytta',
         'wo': 'Wollof',
         'xh': 'isiXhosa',
         'yi': 'ייִדיש',
         'yo': 'Yorùbá',
         'za': 'Saɯ cueŋƅ',
         'zh': '中文',
         'zh_CN': '中文',
         'zh_TW': '中文',
         'zu': 'isiZulu'}

    def __init__(self): #홈디렉토리의 path 저장
        self._paths = LocaleCleanerPath(location='/')

    def add_xml(self, xml_node, parent=None):
        """Parses the xml data and adds nodes to the LocaleCleanerPath-tree"""

        if parent is None: #parent 가 none 인 경우
            parent = self._paths #self에 저장된 path가 parent
        if xml_node.ELEMENT_NODE != xml_node.nodeType: #xml의 요소 노드와 노드타입이 다르다면 함수 종료
            return

        # if a pattern is supplied, we recurse into all matching subdirectories
        if 'regexfilter' == xml_node.nodeName: #xml의 노드이름이 regexfilter 인경우
            pre = xml_node.getAttribute('prefix') or '' #xml 속성이 prefix 이거나 공백인경우 이를 변수에 할당
            post = xml_node.getAttribute('postfix') or '' #xml 속성이 postfix 이거나 공백인경우 이를 변수에 할당
            parent.add_path_filter(pre, post) #prefix, postfix를 연결하는 함수 실행
        elif 'path' == xml_node.nodeName: #만약 xml 노드이름이 path인 경우
            if xml_node.hasAttribute('directoryregex'): #xml이 directoryregex 속성을 가지고 있는 경우
                pattern = xml_node.getAttribute('directoryregex') #directoryregex 속성값을 변수에 할당
                if '/' in pattern: #pattern에 / 문자가 존재하는 경우 (즉 하위 디렉토리가 있는 경우)
                    raise RuntimeError('directoryregex may not contain slashes.') #런타임 예외 발생
                pattern = re.compile(pattern) #정규표현식으로 변경
                parent = parent.add_child(LocaleCleanerPath(pattern)) #parent의 자식으로 pattern 추가

            # a combination of directoryregex and filter could be too much
            else:
                if xml_node.hasAttribute("location"): #xml이 location속성을 가지고 있는 경우
                    # if there's a filter attribute, it should apply to this path
                    parent = parent.add_child(LocaleCleanerPath(xml_node.getAttribute('location')))

                if xml_node.hasAttribute('filter'): #xml이 filter속성을 가지고 있는 경우
                    userfilter = xml_node.getAttribute('filter') #filter속성값을 변수에 할당
                    if 1 != userfilter.count('*'): # userfilter 개수가 1이 아닌 경우
                        raise RuntimeError( #런타임 예외 발생
                            "Filter string '%s' must contain the placeholder * exactly once" % userfilter)

                    # we can't use re.escape, because it escapes too much
                    (pre, post) = (re.sub(r'([\[\]()^$.])', r'\\\1', p) #userfilter의 값을 prefix, postfix로 구분하고 정규표현식으로 표현
                                   for p in userfilter.split('*'))
                    parent.add_path_filter(pre, post) #분리한 prepost, postfix를 patrent의 필터에 추가
        else:
            raise RuntimeError( #런타임 예외 발생
                "Invalid node '%s', expected '<path>' or '<regexfilter>'" % xml_node.nodeName)

        # handle child nodes
        for child_xml in xml_node.childNodes: #xml의 자식 노드를 순환
            self.add_xml(child_xml, parent) #child_xml을 self의 xml로 추가

    def localization_paths(self, locales_to_keep):
        """Returns all localization items matching the previously added xml configuration"""
        if not locales_to_keep: #locales_to_keep 이 null 인 경우
            raise RuntimeError('Found no locales to keep') #런타임 예외 발생
        purgeable_locales = frozenset((locale for locale in Locales.native_locale_names.keys()
                                       if locale not in locales_to_keep)) #변경할수 없는 frozenset 집합 생성

        for (locale, path) in self._paths.get_localizations('/'): #self._paths의 데이터를 / 구분하고 순환
            if locale in purgeable_locales: #purgeable_locales에 locale이 존재한다면
                yield path


def __is_broken_xdg_desktop_application(config, desktop_pathname):
    """Returns boolean whether application deskop entry file is broken"""
    if not config.has_option('Desktop Entry', 'Exec'): #config의 옵션을 체크
        logger.info("is_broken_xdg_menu: missing required option 'Exec': '%s'", desktop_pathname) #로그 추가
        return True #트루 반환
    exe = config.get('Desktop Entry', 'Exec').split(" ")[0] #config 옵션값을 빈칸을 기준으로 분리하여 할당
    if not FileUtilities.exe_exists(exe): #만약 exe 실행파일이 존재 하지 않는다면
        logger.info("is_broken_xdg_menu: executable '%s' does not exist '%s'", exe, desktop_pathname) #로그추가
        return True #트루 반환
    if 'env' == exe: #만약 exe가 env 라면
        # Wine v1.0 creates .desktop files like this
        # Exec=env WINEPREFIX="/home/z/.wine" wine "C:\\Program
        # Files\\foo\\foo.exe"
        execs = shlex.split(config.get('Desktop Entry', 'Exec')) #config의 옵션값을 가져와 분할한 값을 저장
        wineprefix = None
        del execs[0] #execs의 0번째값 삭제
        while True: #반복문 실행
            if 0 <= execs[0].find("="): #만약 execs 0번째 값에서 = 문자가 포함되어 있다면
                (name, value) = execs[0].split("=") # '=' 문자 기준으로 구분하여 저장
                if 'WINEPREFIX' == name: #이름이 WINEPREFIX인 경우
                    wineprefix = value #wineprefix 와 value는 같게 지정
                del execs[0] #execs의 0번째값 삭제
            else:
                break # 반복문 종료
        if not FileUtilities.exe_exists(execs[0]): # execs 0번째 값이 존재하지 않는다면
            logger.info("is_broken_xdg_menu: executable '%s' does not exist '%s'", execs[0], desktop_pathname) #로그 기록
            return True #트루 반환
        # check the Windows executable exists
        if wineprefix: #wineprefix가 존재한다면
            windows_exe = wine_to_linux_path(wineprefix, execs[1]) #windows_exe변수에 wineprefix 경로를 저장
            if not os.path.exists(windows_exe): #windows_exe의 경로가 존재하지 않는다면
                logger.info("is_broken_xdg_menu: Windows executable '%s' does not exist '%s'",
                            windows_exe, desktop_pathname) #로그 추가
                return True #트루 반환
    return False # 펄스 반환


def is_unregistered_mime(mimetype):
    """Returns True if the MIME type is known to be unregistered. If
    registered or unknown, conservatively returns False."""
    try:
        from gi.repository import Gio
        if 0 == len(Gio.app_info_get_all_for_type(mimetype)): #mimetype의 컨텐츠 타입에 대한 GIO.Appinfo 타입의 길이가 0인경우
            return True #트루 반환
    except ImportError: #예외 발생시 로그 기록
        logger.warning('error calling gio.app_info_get_all_for_type(%s)', mimetype)
    return False # 펄스 반환


def is_broken_xdg_desktop(pathname):
    """Returns boolean whether the given XDG desktop entry file is broken.
    Reference: http://standards.freedesktop.org/desktop-entry-spec/latest/"""
    config = bleachbit.RawConfigParser() #블리치비트의 기본구성 객체 생성
    config.read(pathname) #파일 이름목록을 읽고 구문분석하고 파싱된 이름 목록을 반환
    if not config.has_section('Desktop Entry'): #명명된 섹션이 구성에 없다면
        logger.info("is_broken_xdg_menu: missing required section 'Desktop Entry': '%s'", pathname) #로그 기록
        return True # 트루 반환
    if not config.has_option('Desktop Entry', 'Type'): #명명된 섹션이 구성에 없다면
        logger.info("is_broken_xdg_menu: missing required option 'Type': '%s'", pathname)#로그 기록
        return True # 트루 반환
    file_type = config.get('Desktop Entry', 'Type').strip().lower() #명명된 섹션의 공백값을 삭제하고 소문자로 변경한 값을 변수에 저장
    if 'link' == file_type: #만약 파일의 타입이 link인 경우
        if not config.has_option('Desktop Entry', 'URL') and \ ##명명된 섹션이 구성에 없다면
                not config.has_option('Desktop Entry', 'URL[$e]'):
            logger.info("is_broken_xdg_menu: missing required option 'URL': '%s'", pathname) # 로그기록
            return True # 트루반환
        return False # 펄스 반환
    if 'mimetype' == file_type: #만약 파일의 타입이 mimetype인 경우
        if not config.has_option('Desktop Entry', 'MimeType'): ##명명된 섹션이 구성에 없다면
            logger.info("is_broken_xdg_menu: missing required option 'MimeType': '%s'", pathname)# 로그기록
            return True # 트루반환
        mimetype = config.get('Desktop Entry', 'MimeType').strip().lower() #명명된 섹션의 공백값을 삭제하고 소문자로 변경한 값을 변수에 저장
        if is_unregistered_mime(mimetype): #등록되지 않은 mimetype 이라면
            logger.info("is_broken_xdg_menu: MimeType '%s' not registered '%s'", mimetype, pathname) #로그기록
            return True # 트루반환
        return False # 펄스 반환
    if 'application' != file_type: #만약 파일의 타입이 application이 아닌 경우
        logger.warning("unhandled type '%s': file '%s'", file_type, pathname) # 로그 기록
        return False # 펄스 반환
    if __is_broken_xdg_desktop_application(config, pathname): #만약 xdg가 손상되었다면
        return True # 트루 반환
    return False # 펄스 반환


def is_running_darwin(exename, run_ps=None):
    if run_ps is None: #run_ps 파라미터가 none 인 경우
        def run_ps():
            return subprocess.check_output(["ps", "aux", "-c"]) #해당 명령어로 새로운 프로세스 실행
    try:
        processess = (re.split(r"\s+", p, 10)[10] for p in run_ps().split("\n") if p != "") #정규표현식으로 프로세스 명령어 설정
        next(processess)  # drop the header #프로세스들을 하나씩 순차적으로 실행
        return exename in processess #만약 프로세스들 중 exename과 같은 프로세스가 있다면 이를 반환
    except IndexError: #인덱스 예외사항이 발생한경우
        raise RuntimeError("Unexpected output from ps") #런타임 에러 발생


def is_running_linux(exename):
    """Check whether exename is running"""
    for filename in glob.iglob("/proc/*/exe"): #해당경로 하위에 실행중인 프로세스 순환
        try:
            target = os.path.realpath(filename) #실행중인 프로세스의 실제 실행파일을 타겟으로 지정
        except TypeError: #에외발생시 다음 프로세스로 이동
            # happens, for example, when link points to
            # '/etc/password\x00 (deleted)'
            continue
        except OSError: #만약 os 예외 발생시
            # 13 = permission denied
            continue # 다음 프로세스로 이동
        if exename == os.path.basename(target): #실행중인 실행파일이 저장된 절대경로 주소와 exename이 일치하는 경우
            return True # 트루 반환
    return False # 펄스 반환


def is_running(exename): #파마리터로 받은 실행파일이 실행중인지 체크
    """Check whether exename is running"""
    if sys.platform.startswith('linux'): #만약 os가 리눅스라면
        return is_running_linux(exename) #리눅스에서 파라미터의 실행파일이 실행중인지 체크하여 boolean 값 반환
    elif ('darwin' == sys.platform or #만약 darwin, openbsd, freebsd 를 사용한다면
          sys.platform.startswith('openbsd') or
          sys.platform.startswith('freebsd')):
        return is_running_darwin(exename) #파라미터의 실행파일이 실행중인지 체크하여 boolean 값 반환
    else:
        raise RuntimeError('unsupported platform for physical_free()') # 런타임예외 발생


def rotated_logs():
    """Yield a list of rotated (i.e., old) logs in /var/log/"""
    # Ubuntu 9.04
    # /var/log/dmesg.0
    # /var/log/dmesg.1.gz
    # Fedora 10
    # /var/log/messages-20090118
    globpaths = ('/var/log/*.[0-9]',   #로그 목록들을 저장
                 '/var/log/*/*.[0-9]',
                 '/var/log/*.gz',
                 '/var/log/*/*gz',
                 '/var/log/*/*.old',
                 '/var/log/*.old')
    for globpath in globpaths: #로그 목록 순환
        for path in glob.iglob(globpath): #해당경로 하위에 실행중인 프로세스 순환
            yield path
    regex = '-[0-9]{8}$' #정규표현식 저장
    globpaths = ('/var/log/*-*', '/var/log/*/*-*') #로그가 저장되는 경로 지정
    for path in FileUtilities.globex(globpaths, regex): #로그가 저장되는 경로에 정규표현식과 맞는 경로명들을 순환
        whitelist_re = '^/var/log/(removed_)?(packages|scripts)' #화이트 리스트 정규표현식 저장
        if re.match(whitelist_re, path) is None:  # for Slackware, Launchpad #367575
            yield path


def start_with_computer(enabled): #바로가기 생성, 삭제
    """If enabled, create shortcut to start application with computer.
    If disabled, then delete the shortcut."""
    if not enabled: #만약 enabled 되어있지 않다면
        # User requests to not automatically start BleachBit
        if os.path.lexists(bleachbit.autostart_path): #블리치비트 기본 시작 경로에 파일이 존재한다면
            # Delete the shortcut
            FileUtilities.delete(bleachbit.autostart_path) #해당 파일 삭제
        return # 함수 종료
    # User requests to automatically start BleachBit
    if os.path.lexists(bleachbit.autostart_path): #블리치비트 기본 시작 경로에 파일이 존재한다면
        # Already automatic, so exit
        return #아무 작업을 하지않고 함수 종료
    if not os.path.exists(bleachbit.launcher_path):#블리치비트 기본 시작 경로에 파일이 존재하지 않는다면
        logger.error('%s does not exist: ', bleachbit.launcher_path) # 로그 기록
        return # 함수 종료
    autostart_dir = os.path.dirname(bleachbit.autostart_path) #블리치비트 기본 시작 경로의 절대주소를 변수에 저장
    if not os.path.exists(autostart_dir): # 만약 경로값이 존재하지 않는다면
        General.makedirs(autostart_dir) # 해당 경로에 파일 생성
    import shutil #디렉토리 작업에 필요한 셀 유틸리티 임포트
    shutil.copy(bleachbit.launcher_path, bleachbit.autostart_path) #블리치 비트의 런치파일을 복사하여 바로가기 파일을 만듬
    os.chmod(bleachbit.autostart_path, 0o755) #바로가기 파일 권한 설정
    if General.sudo_mode(): #만약 수도 모드로 되어있는 경우
        General.chownself(bleachbit.autostart_path) #바로가기 파일 권한 설정


def start_with_computer_check():
    """Return boolean whether BleachBit will start with the computer"""
    return os.path.lexists(bleachbit.autostart_path) # 바로가기 파일이 있는지 여부 반환


def wine_to_linux_path(wineprefix, windows_pathname):
    """Return a Linux pathname from an absolute Windows pathname and Wine prefix"""
    drive_letter = windows_pathname[0] #window_pathname 에서 드라이브 문자명 할당(예: C 또는 D 드라이브)
    windows_pathname = windows_pathname.replace(drive_letter + ":", #소문자로 치환
                                                "drive_" + drive_letter.lower())
    windows_pathname = windows_pathname.replace("\\", "/") #윈도우 형식에 맞게 디렉토리간 구분 문자 변경
    return os.path.join(wineprefix, windows_pathname) #prefix 형식으로 경로명 변경


def run_cleaner_cmd(cmd, args, freed_space_regex=r'[\d.]+[kMGTE]?B?', error_line_regexes=None):
    """Runs a specified command and returns how much space was (reportedly) freed.
    The subprocess shouldn't need any user input and the user should have the
    necessary rights.
    freed_space_regex gets applied to every output line, if the re matches,
    add values captured by the single group in the regex"""
    if not FileUtilities.exe_exists(cmd): #파라미터의 경로에 파일이 존재하지 않는 경우
        raise RuntimeError(_('Executable not found: %s') % cmd) #런타임 예외 발생
    freed_space_regex = re.compile(freed_space_regex) #파라미터의 정규표현식으로 컴파일한 값 할당
    error_line_regexes = [re.compile(regex) for regex in error_line_regexes or []] #error_line_regexes에 포함된 regex 정규표현식으로 컴파일

    env = {'LC_ALL': 'C', 'PATH': os.getenv('PATH')} #환경 설정값을 딕셔너리 형태로 저장
    output = subprocess.check_output([cmd] + args, stderr=subprocess.STDOUT, #서브 프로세스 실행
                                     universal_newlines=True, env=env)
    freed_space = 0
    for line in output.split('\n'): #output 값을 행 기준으로 순환
        m = freed_space_regex.match(line) #파라미터의 값과 freed_space_regex 정규표현식이 맞는지 여부를 할당
        if m is not None: #만약 m이 존재한다면
            freed_space += FileUtilities.human_to_bytes(m.group(1)) #m을 사람이 보기 좋은 형태 byte 기준으로 값 치환
        for error_re in error_line_regexes: #에러 형식의 정규표현식을 순환
            if error_re.search(line): #만약 파라미터의 값이 에러형식이라면
                raise RuntimeError('Invalid output from %s: %s' % (cmd, line)) #런타임 예외 발생

    return freed_space


def journald_clean():
    """Clean the system journals"""
    freed_space_regex = '^Vacuuming done, freed ([\d.]+[KMGT]?) of archived journals on disk.$' #정규표현식 지정
    return run_cleaner_cmd('journalctl', ['--vacuum-size=1'], freed_space_regex) #시스템 저널정리 함수 호출


def apt_autoremove():
    """Run 'apt-get autoremove' and return the size (un-rounded, in bytes) of freed space"""

    args = ['--yes', 'autoremove'] #명령어 옵션 인자값 저장
    # After this operation, 74.7MB disk space will be freed.
    freed_space_regex = r', ([\d.]+[a-zA-Z]{2}) disk space will be freed' #정규 표현식 저장
    try:
        return run_cleaner_cmd('apt-get', args, freed_space_regex, ['^E: ']) #cmd 실행 함수 호출
    except subprocess.CalledProcessError as e: #서브 프로세스 콜 예외 발생시
        raise RuntimeError("Error calling '%s':\n%s" % (' '.join(e.cmd), e.output)) # 런타임 예외 발생


def apt_autoclean():
    """Run 'apt-get autoclean' and return the size (un-rounded, in bytes) of freed space"""
    try:
        return run_cleaner_cmd('apt-get', ['autoclean'], r'^Del .*\[([\d.]+[a-zA-Z]{2})}]', ['^E: ']) #cmd 실행 함수 호출
    except subprocess.CalledProcessError as e: #서브 프로세스 콜 예외 발생시
        raise RuntimeError("Error calling '%s':\n%s" % (' '.join(e.cmd), e.output)) # 런타임 예외 발생


def apt_clean():
    """Run 'apt-get clean' and return the size in bytes of freed space"""
    old_size = get_apt_size() #apt 사이즈 저장
    try:
        run_cleaner_cmd('apt-get', ['clean'], '^unused regex$', ['^E: ']) #cmd 실행 함수 호출
    except subprocess.CalledProcessError as e: #서브 프로세스 콜 예외 발생시
        raise RuntimeError("Error calling '%s':\n%s" % # 런타임 예외 발생
                           (' '.join(e.cmd), e.output))
    new_size = get_apt_size() #apt 사이즈 다시 호출 후 저장
    return old_size - new_size #변경된 사이즈 값 반환


def get_apt_size():
    """Return the size of the apt cache (in bytes)"""
    (rc, stdout, stderr) = General.run_external(['apt-get', '-s', 'clean']) #익스터널 커맨드 실행
    paths = re.findall('/[/a-z\.\*]+', stdout) #stdout에서 첫번쨰 파라미터 정규형식에 부합하는 path를 찾아 리스트저장
    return get_globs_size(paths) #파라미터의 사이즈를 반환하는 함수 호출


def get_globs_size(paths):
    """Get the cumulative size (in bytes) of a list of globs"""
    total_size = 0
    for path in paths: #각 paths를 순환
        from glob import iglob
        for p in iglob(path):
            total_size += FileUtilities.getsize(p) #path의 사이즈를 합산
    return total_size #총 사이즈 반환


def yum_clean():
    """Run 'yum clean all' and return size in bytes recovered"""
    if os.path.exists('/var/run/yum.pid'): # 경로의 파일이 존재하는지 체크
        msg = _( #메시지 문자열 지정
            "%s cannot be cleaned because it is currently running.  Close it, and try again.") % "Yum"
        raise RuntimeError(msg) #런타임 예외 발생

    old_size = FileUtilities.getsizedir('/var/cache/yum') #경로의 사이즈값 저장
    args = ['--enablerepo=*', 'clean', 'all'] #명렁어 옵션 인자값 저장
    invalid = ['You need to be root', 'Cannot remove rpmdb file'] #invalid시 알림할 메시지 저장
    run_cleaner_cmd('yum', args, '^unused regex$', invalid) #cmd 실행하여 명령어 실행하는 함수 실행
    new_size = FileUtilities.getsizedir('/var/cache/yum') # 경로의 사이즈값 재 산정 후 저장
    return old_size - new_size #변한 사이즈값을 반환


locales = Locales() #운영체제의 언어값을 변수에 저장
