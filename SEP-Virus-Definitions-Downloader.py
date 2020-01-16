import hashlib
import os
import requests
import time
from bs4 import BeautifulSoup
from tqdm import tqdm
from urllib.request import urlopen

# SEP 定義ファイルのダウンロードリンク

print("SEP 定義ファイルのダウンロードリンクを分析しています…")

link_savce = requests.get(
    'https://www.symantec.com/ja/jp/security_response/definitions/download/detail.jsp?gid=savce'
)
link_ips = requests.get(
    'https://www.symantec.com/ja/jp/security_response/definitions/download/detail.jsp?gid=ips'
)
link_sonar = requests.get(
    'https://www.symantec.com/ja/jp/security_response/definitions/download/detail.jsp?gid=sonar'
)

# 定義ファイルの HTML コードを取集
# 取集した savce 定義ファイルに関する HTML コードの状態を確認
if link_savce.status_code == requests.codes['ok']:
    # BeautifulSoup を使って HTML コードを分析
    soup = BeautifulSoup(link_savce.text, 'html.parser')
    # CSS Selector で各ダウンロードリンクを取集
    v5i32 = soup.select(
        'div.imgMrgnTopMD:nth-child(3) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(1) > strong:nth-child(1) > a:nth-child(1)'
    )
    v5i64 = soup.select(
        'div.imgMrgnTopMD:nth-child(5) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(1) > strong:nth-child(1) > a:nth-child(1)'
    )
    jdb = soup.select(
        'div.imgMrgnTopMD:nth-child(7) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(1) > strong:nth-child(1) > a:nth-child(1)'
    )
    # CSS Selector で各ファイルの MD5 情報取集
    v5i32_MD5 = soup.select(
        'div.imgMrgnTopMD:nth-child(3) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(5)'
    )
    v5i64_MD5 = soup.select(
        'div.imgMrgnTopMD:nth-child(5) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(5)'
    )
    jdb_MD5 = soup.select(
        'div.imgMrgnTopMD:nth-child(7) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(5)'
    )

# 取集した ips 定義ファイルに関する HTML コードの状態を確認
if link_ips.status_code == requests.codes['ok']:
    # BeautifulSoup を使って HTML コードを分析
    soup = BeautifulSoup(link_ips.text, 'html.parser')
    # CSS Selector で各ダウンロードリンクを取集
    ips_exe = soup.select(
        'div.imgMrgnTopMD:nth-child(3) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(1) > strong:nth-child(1) > a:nth-child(1)'
    )
    ips_jdb = soup.select(
        'div.imgMrgnTopMD:nth-child(5) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(1) > strong:nth-child(1) > a:nth-child(1)'
    )
    # CSS Selector で各ファイルの MD5 情報取集
    ips_exe_MD5 = soup.select(
        'div.imgMrgnTopMD:nth-child(3) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(5)'
    )
    ips_jdb_MD5 = soup.select(
        'div.imgMrgnTopMD:nth-child(5) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(5)'
    )

# 取集した sonar 定義ファイルに関する HTML コードの状態を確認
if link_sonar.status_code == requests.codes['ok']:
    # BeautifulSoup を使って HTML コードを分析
    soup = BeautifulSoup(link_sonar.text, 'html.parser')
    # CSS Selector で各ダウンロードリンクを取集
    sonar_exe = soup.select(
        'div.imgMrgnTopMD:nth-child(3) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(1) > strong:nth-child(1) > a:nth-child(1)'
    )
    sonar_jdb = soup.select(
        'div.imgMrgnTopMD:nth-child(5) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(1) > strong:nth-child(1) > a:nth-child(1)'
    )
    # CSS Selector で各ファイルの MD5 情報取集
    sonar_exe_MD5 = soup.select(
        'div.imgMrgnTopMD:nth-child(3) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(5)'
    )
    sonar_jdb_MD5 = soup.select(
        'div.imgMrgnTopMD:nth-child(5) > div:nth-child(1) > table:nth-child(1) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(5)'
    )

# List で取集したリンク・ファイル名・ファイル MD5 情報を格納
link_list = [
    v5i32[0].get('href'), v5i64[0].get('href'), jdb[0].get('href'),
    ips_exe[0].get('href'), ips_jdb[0].get('href'), sonar_exe[0].get('href'),
    sonar_jdb[0].get('href')
]

filename_list = [
    v5i32[0].text, v5i64[0].text, jdb[0].text, ips_exe[0].text,
    ips_jdb[0].text, sonar_exe[0].text, sonar_jdb[0].text
]

MD5_list = [
    v5i32_MD5[0].text, v5i64_MD5[0].text, jdb_MD5[0].text, ips_exe_MD5[0].text,
    ips_jdb_MD5[0].text, sonar_exe_MD5[0].text, sonar_jdb_MD5[0].text
]


# ダウンロード&プログレスバーモジュールに関するコード
def downloader(url, path):
    file_size = int(urlopen(url).info().get('Content-Length', -1))

    if os.path.exists(path):
        first_byte = os.path.getsize(path)
    else:
        first_byte = 0
    if first_byte >= file_size:
        return file_size
    header = {"Range": "bytes=%s-%s" % (first_byte, file_size)}
    pbar = tqdm(total=file_size,
                initial=first_byte,
                unit='B',
                unit_scale=True,
                desc=url.split('/')[-1])
    req = requests.get(url, headers=header, stream=True)
    with (open(path, 'ab')) as f:
        for chunk in req.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
                pbar.update(1024)
    pbar.close()
    return file_size


# ファイル MD5 情報比較に関するコード
def getFileMD5(filepath, filename, MD5):
    fp = open(filepath, 'rb')
    contents = fp.read()
    fp.close()
    if hashlib.md5(contents).hexdigest() == str.lower(MD5):
        print('\nファイル名:', filename, '\n', 'ウェブサイトから提供された MD5 情報:', MD5, '\n',
              'ファイルの MD5 情報:',
              hashlib.md5(contents).hexdigest(), '\n', 'MD5 情報一致')
    else:
        print('ファイル名:', filename, 'MD5 情報不一致、ご確認のほどよろしくお願いします。')


# 実行コード（当日の日付に命名したフォルダーに格納）
if __name__ == '__main__':
    path = './' + time.strftime("%Y%m%d")
    try:
        os.makedirs(path)
    except:
        pass

    for link, filename in zip(link_list, filename_list):
        savepath = path + "/" + filename
        downloader(link, savepath)
    for filename, MD5 in zip(filename_list, MD5_list):
        filepath = '.\\' + time.strftime("%Y%m%d") + '\\' + filename
        getFileMD5(filepath, filename, MD5)
    os.system("pause")
