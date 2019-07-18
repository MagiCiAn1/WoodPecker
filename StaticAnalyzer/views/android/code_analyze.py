# coding:utf-8
import logging
import re
import base64

from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from .string_rules import *
from .ins_analyze import InstructionAnalyze
from .analyzer_helper import *
from StaticAnalyzer.views.helper import Helper


class CodeAnalyze(object):
    def __init__(self, apk):
        self.__dvm = dvm.DalvikVMFormat(apk.get_dex())
        self.__string_rules = RULES
        self.__vmx = analysis.VMAnalysis(self.__dvm)

    def find_class_and_method_by_string(self, string_list):
        method_by_string = {}
        class_manager = self.__dvm.get_class_manager()
        for class_name in self.__dvm.get_classes_names():
            methods = self.__dvm.get_methods_class(class_name)
            for method in methods:
                method_info = method.get_class_name() + '->' + method.get_name() + method.get_descriptor()
                for i in method.get_instructions():  # method.get_instructions(): Instruction
                    if (i.get_op_value() == 0x1A) or (
                            i.get_op_value() == 0x1B):  # 0x1A = "const-string", 0x1B = "const-string/jumbo"
                        probably_string = class_manager.get_string(i.get_ref_kind())
                        if probably_string in string_list:
                            method_by_string[method_info] = probably_string
        return method_by_string

    # ssss= ssss+ 1
    # if ssss == 20:
    # 	break

    def string_regex(self):
        print "get possible strings"
        dict_string_value_to_idx_from_file_mapping = {}
        # self.find_class_and_method_by_string([])
        for rule in self.__string_rules:
            if rule['enable'] == 'true':
                list_strings_to_find = []
                for s in self.__dvm.get_string_data_item():
                    # dict_string_value_to_idx_from_file_mapping[s.get_unicode] = s.get_off()
                    # print(s.get_unicode())
                    tmp = s.get()
                    if re.search(rule['regex1'], tmp):
                        list_strings_to_find.append(tmp)
                if len(list_strings_to_find) > 0:
                    self.find_class_and_method_by_string(list_strings_to_find)
            # break

    # all_string = self.__dvm.get_strings_unicode()
    # findings = []
    # for string in all_string:
    # 	for rule in self.__string_rules:
    # 		if rule["input_case"] == "lower":
    # 			tmp_data = string.lower()
    # 		elif rule["input_case"] == "upper":
    # 			tmp_data = string.upper()
    # 		elif rule["input_case"] == "exact":
    # 			tmp_data = string
    # 		if rule["type"] == "regex":
    # 			if rule["match"] == 'single_regex':
    # 				if re.search(rule["regex1"], tmp_data):
    # 					print(tmp_data)
    # 			elif rule["match"] == 'regex_and':
    # 				and_match_rgx = True
    # 				match_list = get_list_match_items(rule)
    # 				for match in match_list:
    # 					if bool(re.search(match, tmp_data)) is False:
    # 						and_match_rgx = False
    # 						break
    # 				if and_match_rgx:
    # 					print(tmp_data)
    # 			elif rule["match"] == 'regex_or':
    # 				match_list = get_list_match_items(rule)
    # 				for match in match_list:
    # 					if re.search(match, tmp_data):
    # 						print(tmp_data)
    # 						break
    # 			else:
    # 				print("\n[ERROR] Code Regex Rule Match Error\n" + rule)

    def base64_regex(self):
        print "get possible base64"
        list_base64_success_decoded_string_to_original_mapping = {}
        list_base64_excluded_original_string = ["endsWith", "allCells", "fillList", "endNanos", "cityList", "cloudid=",
                                                "Liouciou"]  # exclusion list
        list_string_to_find = []
        for s in self.__dvm.get_string_data_item():
            # dict_string_value_to_idx_from_file_mapping[s.get_unicode] = s.get_off()
            # print(s.get_unicode())
            tmp = s.get()
            if re.match('^[A-Za-z0-9+/]+[=]{0,2}$', tmp) and len(tmp) > 3:
                try:
                    decoded_string = base64.b64decode(tmp)
                    if re.match('^[A-Za-z0-9\\\:\;\/\-\.\,\?\=\<\>\+\_\(\)\[\]\{\}\|\"\'\~\`\*]+$', decoded_string):
                        if len(decoded_string) > 3:
                            if tmp not in list_base64_success_decoded_string_to_original_mapping and decoded_string not \
                                    in list_base64_excluded_original_string:
                                list_base64_success_decoded_string_to_original_mapping[tmp] = decoded_string
                                list_string_to_find.append(tmp)
                except:
                    pass
        result = self.find_class_and_method_by_string(list_string_to_find)
        for m, tmp in result.items():
            print(m + ' ?' + list_base64_success_decoded_string_to_original_mapping[tmp])

    # for tmp, decoded_string in list_base64_success_decoded_string_to_original_mapping.items():
    # 	print(tmp+':'+decoded_string+str(self.find_class_and_method_by_string([tmp])))

    def security_method(self):
        security_method_list = []
        regexGerneralRestricted = ".*(config|setting|constant).*"
        regexSecurityRestricted = ".*(encrypt|decrypt|encod|decod|aes|sha1|sha256|sha512|md5).*"
        prog = re.compile(regexGerneralRestricted, re.I)
        prog_sec = re.compile(regexSecurityRestricted, re.I)
        for class_name in self.__dvm.get_classes_names():
            methods = self.__dvm.get_methods_class(class_name)
            for method in methods:
                if prog.match(method.get_name()) or prog_sec.match(method.get_name()):
                    if (method.get_name() != 'onConfigurationChanged') and (
                            method.get_descriptor() != '(Landroid/content/res/Configuration;)V'):
                        security_method_list.append(method.get_name())
        print(security_method_list)

    def exec_search(self):
        print "search exec and su "
        su_exec_method_list = []
        exec_method_list = []
        path_Runtime_exec = self.__vmx.get_tainted_packages().search_class_method_exact_match("Ljava/lang/Runtime;",
                                                                                              "exec",
                                                                                              "(Ljava/lang/String;)Ljava/lang/Process;")
        for path in path_Runtime_exec:
            ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
            ins_analyze.analyze_pathp_inner_method()
            stack = ins_analyze.get_stack()
            last_line = stack.get(0)  # [26, [(0, 4), (257, 48591, "'sh'")]]
            if 0x12 <= last_line[0] <= 0x1c:
                if last_line[1][0][0] == dvm.OPERAND_REGISTER:
                    const_string = last_line[1][1][2]
                    if Helper.strip_string(const_string) == 'su':
                        su_exec_method_list.append(ins_analyze.get_src_dst())
                    else:
                        exec_method_list.append(ins_analyze.get_src_dst())
            else:
                exec_method_list.append(ins_analyze.get_src_dst())
        return exec_method_list, su_exec_method_list

    def has_signature_check(self):
        print "search where has signature check"
        list_packageInfo_signatures = []
        filed_packageInfo_signatures = self.__vmx.get_tainted_field(
            "Landroid/content/pm/PackageInfo;", "signatures",
            "[Landroid/content/pm/Signature;")  # [Landroid/content/pm/Signature
        # path_PackageInfo_signatures = self.__vmx.get_tainted_fields()
        if filed_packageInfo_signatures is not None:
            path_package_info_signatures = filed_packageInfo_signatures.get_paths()
            for path in path_package_info_signatures:
                access, idx = path[0]
                m_idx = path[1]
                method = self.__dvm.get_cm_method(m_idx)
                inner_method = self.__dvm.get_method_descriptor(method[0], method[1], method[2][0] + method[2][1])
                if inner_method is not None:
                    ins_analyze = InstructionAnalyze(inner_method, self.__dvm, idx)
                    ins_analyze.analyze_method()
                    stack = ins_analyze.get_stack()
                    last_line = stack.get(0)
                    if last_line[0] == 84 and last_line[1][0][
                        0] == dvm.OPERAND_REGISTER:  # iget-object v2, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;
                        list_packageInfo_signatures.append(ins_analyze.get_src_dst())
            # print ins_analyze.get_src_dst()
        return list_packageInfo_signatures

    def has_debug_check(self):
        logging.info("search where has debug check")
        list_detected_FLAG_DEBUGGABLE_path = []
        field_ApplicationInfo_flags_debuggable = self.__vmx.get_tainted_field("Landroid/content/pm/ApplicationInfo;",
                                                                              "flags", "I")
        if field_ApplicationInfo_flags_debuggable is not None:
            field_ApplicationInfo_flags_debuggable_paths = field_ApplicationInfo_flags_debuggable.get_paths()
            for path in field_ApplicationInfo_flags_debuggable_paths:
                access, idx = path[0]
                m_idx = path[1]
                method = self.__dvm.get_cm_method(m_idx)
                inner_method = self.__dvm.get_method_descriptor(method[0], method[1], method[2][0] + method[2][1])
                if inner_method is not None:
                    ins_analyze = InstructionAnalyze(inner_method, self.__dvm, idx)
                    ins_analyze.analyze_method(extra_offset=1)
                    stack = ins_analyze.get_stack()
                    last_one_ins = stack.get(0)
                    last_two_ins = stack.get(1)
                    try:
                        if (last_one_ins[0] == 0xDD) and (last_two_ins[1][0][1] == last_one_ins[1][1][1]) and (
                                last_one_ins[1][2][1] == 2):  # and-int/lit8 vx,vy,lit8
                            list_detected_FLAG_DEBUGGABLE_path.append(ins_analyze.get_src_dst())
                        """
                            Example 1:
                                last_two_ins => [82, [(0, 1), (0, 1), (258, 16, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
                                last_one_ins => [221, [(0, 1), (0, 1), (1, 2)]]
    
                            Example 2:
                                last_two_ins => [82, [(0, 2), (0, 0), (258, 896, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
                                last_one_ins => [221, [(0, 2), (0, 2), (1, 2)]]
    
                            Java code:
                                stack.show()
                                print(last_one_ins)
                                print(last_two_ins)
                        """
                    except:
                        pass

        return list_detected_FLAG_DEBUGGABLE_path

    def webview_xss_check(self):
        logging.info("webview xss check")
        """
        const/4 v1, 0x1
        invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
        """
        list_setJavaScriptEnabled_XSS = []
        path_setJavaScriptEnabled_XSS = self.__vmx.get_tainted_packages().search_class_method_exact_match(
            "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V")
        for path in path_setJavaScriptEnabled_XSS:
            ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
            ins_analyze.analyze_pathp_inner_method()
            stack = ins_analyze.get_stack()
            last_one_line = stack.get(0)
            stack_len = stack.length()
            if last_one_line[0] == 0x6E:
                for i in range(1, stack_len):
                    line = stack.get(i)
                    if line[0] == 0x12:  # const/4
                        if last_one_line[1][1][1] == line[1][0][1] and line[1][1][1] == 1:
                            list_setJavaScriptEnabled_XSS.append(ins_analyze.get_src_dst())
                            break
        return list_setJavaScriptEnabled_XSS

    def webview_file_access_check(self):
        logging.info("webview file access check")
        """
        const/4 v1, 0x1
        invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
        const/4 v1, 0x1
        invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
        """
        package_webview_websetting = self.__vmx.get_tainted_packages().search_packages("Landroid/webkit/WebSettings;")
        possible_method_info_by_file_access = []
        possible_method_info_by_js_able = []
        impossible_method_info_by_file_access = []
        list_file_access = []
        cm = self.__dvm.get_class_manager()
        for path in package_webview_websetting:
            dst_class_name, dst_method_name, dst_descriptor = path.get_dst(cm)  # 根据path获取包含的method
            src_class_name, src_method_name, src_descriptor = path.get_src(cm)
            if dst_method_name + dst_descriptor == 'setAllowFileAccess(Z)V':
                ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
                ins_analyze.analyze_pathp_inner_method()
                stack = ins_analyze.get_stack()
                last_one_line = stack.get(0)
                stack_len = stack.length()
                if last_one_line[0] == 0x6E:
                    for i in range(1, stack_len):
                        line = stack.get(i)
                        if line[0] == 0x12:  # const/4
                            if last_one_line[1][1][1] == line[1][0][1]:
                                if line[1][1][1] == 1:
                                    method_info = src_class_name + src_method_name + src_descriptor
                                    if method_info in possible_method_info_by_js_able:
                                        list_file_access.append(method_info)
                                        possible_method_info_by_js_able.remove(method_info)
                                    else:
                                        possible_method_info_by_file_access.append(method_info)
                                    break
                                elif line[1][1][1] == 0:
                                    method_info = src_class_name + src_method_name + src_descriptor
                                    if method_info in possible_method_info_by_js_able:
                                        possible_method_info_by_js_able.remove(method_info)
                                    else:
                                        impossible_method_info_by_file_access.append(method_info)
                continue
            if dst_method_name + dst_descriptor == 'setJavaScriptEnabled(Z)V':
                ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
                ins_analyze.analyze_pathp_inner_method()
                stack = ins_analyze.get_stack()
                last_one_line = stack.get(0)
                stack_len = stack.length()
                if last_one_line[0] == 0x6E:
                    for i in range(1, stack_len):
                        line = stack.get(i)
                        if line[0] == 0x12:  # const/4
                            if last_one_line[1][1][1] == line[1][0][1]:
                                if line[1][1][1] == 1:
                                    method_info = src_class_name + src_method_name + src_descriptor
                                    if method_info in possible_method_info_by_file_access:
                                        list_file_access.append(method_info)
                                        possible_method_info_by_file_access.remove(method_info)
                                    elif method_info in impossible_method_info_by_file_access:
                                        possible_method_info_by_js_able.remove(method_info)
                                    else:
                                        possible_method_info_by_js_able.append(method_info)
                                    break
        if len(possible_method_info_by_js_able) > 0:
            list_file_access.extend(possible_method_info_by_js_able)
        return list_file_access

    def webview_save_password_check(self):
        logging.info("webview save password check")
        list_set_save_password = []
        path_set_save_password = self.__vmx.get_tainted_packages().search_class_method_exact_match(
            "Landroid/webkit/WebSettings;", "setSavePassword", "(Z)V")
        for path in path_set_save_password:
            ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
            ins_analyze.analyze_pathp_inner_method()
            stack = ins_analyze.get_stack()
            last_one_line = stack.get(0)
            stack_len = stack.length()
            if last_one_line[0] == 0x6E:
                for i in range(1, stack_len):
                    line = stack.get(i)
                    if line[0] == 0x12:  # const/4
                        if last_one_line[1][1][1] == line[1][0][1]:
                            if line[1][1][1] == 1:
                                list_set_save_password.append(ins_analyze.get_src_dst())
                            break
        return list_set_save_password

    def webview_ssl_error_proceed(self):
        logging.info("check for webview ssl error proceed")
        path_ssl_error_proceed = self.__vmx.get_tainted_packages().search_class_method_exact_match(
            "Landroid/webkit/SslErrorHandler;", "proceed", "()V")
        list_ssl_error_proceed = []
        for path in path_ssl_error_proceed:
            list_ssl_error_proceed.append(path.get_src(self.__dvm.get_class_manager()))
        return list_ssl_error_proceed

    def webview_check_server_trusted(self):
        logging.info("check server trusted")
        """
        sslContext.init(null, new TrustManager[]{
                        new X509TrustManager() {
                            @Override
                            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                            }
                            @Override
                            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                               }
                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return new X509Certificate[0];
                            }
                        }
                }, null);
        :return:
        """
        interface_method_dic = get_interface_method_by_desc(
            self.__dvm, ["Ljavax/net/ssl/X509TrustManager;"],
            ["checkClientTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"])
        no_check_server_trusted_list = check_have_override(interface_method_dic)
        return no_check_server_trusted_list

    def not_verify_hostname(self):
        logging.info("check for allow all hostname verifier")
        """
        1.在自定义实现HostnameVerifier时，没有在verify中进行严格证书校验
        2. 在setHostnameVerifier方法中使用ALLOW_ALL_HOSTNAME_VERIFIER，信任了所有Hostname
        """
        hostname_verify_interface_method = get_interface_method_by_desc(
            self.__dvm, ["Ljavax/net/ssl/HostnameVerifier;"],
            ["verify(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"])
        not_verify_hostname = check_have_override(hostname_verify_interface_method)
        filed_hostname_verifier = self.__vmx.get_tainted_field(
            'Lorg/apache/http/conn/ssl/SSLSocketFactory;', 'ALLOW_ALL_HOSTNAME_VERIFIER',
            'Lorg/apache/http/conn/ssl/X509HostnameVerifier;')
        if filed_hostname_verifier is not None:
            filed_hostname_verifier_paths = filed_hostname_verifier.get_paths()
            for path in filed_hostname_verifier_paths:
                access, idx = path[0]
                m_idx = path[1]
                method = self.__dvm.get_cm_method(m_idx)
                inner_method = self.__dvm.get_method_descriptor(method[0], method[1], method[2][0] + method[2][1])
                if inner_method is not None:
                    ins_analyze = InstructionAnalyze(inner_method, self.__dvm, idx)
                    ins_analyze.analyze_method()
                    stack = ins_analyze.get_stack()
                    last_line = stack.get(0)
                    if last_line[0] == 98 and last_line[1][0][0] == dvm.OPERAND_REGISTER:
                        not_verify_hostname.append(method[0] + method[1] + method[2][0] + method[2][1])
        return not_verify_hostname

    def webview_debuggable_check(self):
        logging.info("check webview debuggable")
        """
         const/4 v3, 0x1
        invoke-static {v3}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
        :return:
        """
        webview_debug_list = []
        path_webview_debuggable = self.__vmx.get_tainted_packages().search_class_method_exact_match(
            "Landroid/webkit/WebView;", "setWebContentsDebuggingEnabled", "(Z)V")
        for path in path_webview_debuggable:
            ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
            ins_analyze.analyze_pathp_inner_method()
            stack = ins_analyze.get_stack()
            last_one_line = stack.get(0)
            print last_one_line
            stack_len = stack.length()
            if last_one_line[0] == 0x71:  # invoke-static
                for i in range(1, stack_len):
                    line = stack.get(i)
                    if line[0] == 0x12:  # const/4
                        if last_one_line[1][0][1] == line[1][0][1] and line[1][1][1] == 1:  # 相同的寄存器 且值为1
                            webview_debug_list.append(ins_analyze.get_src_dst())
                            break
        return webview_debug_list

    def weak_encryption(self):
        logging.info("check weak encryption")
        weak_list = []
        """
        (1)
        const-string v4, "AES/CBC/PKCS5Padding"
            invoke-direct {v2, v3, v4}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
        (2)
        const-string v3, "AES/CBC/PKCS5Padding"
        invoke-static {v3}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
        """
        path_ciper = self.__vmx.get_tainted_packages().search_class_method_exact_match("Ljavax/crypto/Cipher;",
                                                                                       "getInstance",
                                                                                       "(Ljava/lang/String;)Ljavax/crypto/Cipher;")
        for path in path_ciper:
            ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
            ins_analyze.analyze_pathp_inner_method()
            stack = ins_analyze.get_stack()
            last_one_line = stack.get(0)
            stack_len = stack.length()
            if last_one_line[0] == 0x71:  # invoke-static
                now_register = last_one_line[1][0][1]
                for i in range(1, stack_len):
                    line = stack.get(i)
                    if now_register == line[1][0][1] and line[0] == 0x1A:  # 相同的寄存器
                        if str(line[1][1][2]).find('ECB') != -1:  # 如果为const-string 且值包含ECB
                            weak_list.append(ins_analyze.get_src_dst())
                            break
                    if line[0] == 0x01 and now_register == line[1][0][1]:
                        now_register = line[1][1][1]  # 猜测 需验证
        path_secret_key_spec = self.__vmx.get_tainted_packages().search_class_method_exact_match(
            "Ljavax/crypto/spec/SecretKeySpec;",
            "<init>",
            "([B Ljava/lang/String;)V")
        for path in path_secret_key_spec:
            ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
            ins_analyze.analyze_pathp_inner_method()
            stack = ins_analyze.get_stack()
            last_one_line = stack.get(0)
            stack_len = stack.length()
            if last_one_line[0] == 0x70:  # invoke-direct
                now_register = last_one_line[1][2][1]
                for i in range(1, stack_len):
                    line = stack.get(i)
                    if now_register == line[1][0][1] and line[0] == 0x1A:  # 相同的寄存器
                        if str(line[1][1][2]).find('ECB') != -1:  # 如果为const-string 且值包含ECB
                            weak_list.append(ins_analyze.get_src_dst())
                            break
                    if line[0] == 0x01 and now_register == line[1][0][1]:
                        now_register = line[1][1][1]  # 猜测 需验证
        return weak_list

    def check_init_IV(self):
        init_iv_list = []
        """
        invoke-virtual {v4}, Ljava/lang/String;->getBytes()[B
        move-result-object v5
        invoke-direct {v4, v5}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V
        """
        path_init_iv = self.__vmx.get_tainted_packages().search_class_method_exact_match(
            "Ljavax/crypto/spec/IvParameterSpec;",
            "<init>",
            "([B)V")
        for path in path_init_iv:
            ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
            ins_analyze.analyze_pathp_inner_method()
            stack = ins_analyze.get_stack()
            last_one_line = stack.get(0)
            stack_len = stack.length()
            print last_one_line
            if last_one_line[0] == 0x70:  # invoke-direct
                now_register = last_one_line[1][1][1]
                for i in range(1, stack_len):
                    line = stack.get(i)
                    if now_register == line[1][0][1] and line[0] == 0xC:  # 相同的寄存器
                        for j in range(i, stack_len):
                            now_line = stack.get(j)
                            print now_line
                            if now_line[0] == 0x6E and now_line[1][1][2] == 'Ljava/lang/String;->getBytes()[B':
                                init_iv_list.append(ins_analyze.get_src_dst())
                                break
                        break
                    return init_iv_list

    def file_world_read(self):
        """
        （1）
        const/4 v3, 0x3
        invoke-virtual {p0, v2, v3}, Lcom/example/a13251/bugssouce/MainActivity;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
        （2）
        const/4 v3, 0x1

    invoke-virtual {p0, v2, v3}, Lcom/example/a13251/bugssouce/MainActivity;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
        """
        world_read_write_list = []
        path_openFileOutput = self.__vmx.get_tainted_packages().get_method('openFileOutput',
                                                                           '(Ljava/lang/String; I)Ljava/io/FileOutputStream;')
        path_sharedPrefer = self.__vmx.get_tainted_packages().get_method('getSharedPreferences',
                                                                         '(Ljava/lang/String; I)Landroid/content/SharedPreferences;')
        paths = []
        paths.extend(path_openFileOutput)
        paths.extend(path_sharedPrefer)
        for path in paths:
            ins_analyze = InstructionAnalyze(path, self.__dvm, path.get_idx())
            ins_analyze.analyze_pathp_inner_method()
            stack = ins_analyze.get_stack()
            last_one_line = stack.get(0)
            stack_len = stack.length()
            print last_one_line
            if last_one_line[0] == 0x6E:  # invoke-virtual
                now_register = last_one_line[1][2][1]
                for i in range(1, stack_len):
                    line = stack.get(i)
                    if line[0] == 0x12:  # 相同的寄存器 const/4
                        if now_register == line[1][0][1]:
                            if line[1][1][1] == 0x1 or line[1][1][1] == 0x2 or line[1][1][1] == 0x3:
                                world_read_write_list.append(ins_analyze.get_src_dst())
                                break
        return world_read_write_list

    def dex_class_loder(self):
        """
        invoke-direct {v3, v4, v5, v6, v7}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V
        :return:
        """
        lode_list = []
        path_class_loder = self.__vmx.get_tainted_packages().search_class_method_exact_match(
            "Ldalvik/system/DexClassLoader;",
            "<init>",
            "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Ljava/lang/ClassLoader;)V")
        for path in path_class_loder:
            cm = self.__dvm.get_class_manager()
            src_class_name, src_method_name, src_descriptor = path.get_src(cm)
            lode_list.append([src_class_name, src_method_name, src_descriptor])
        return lode_list
