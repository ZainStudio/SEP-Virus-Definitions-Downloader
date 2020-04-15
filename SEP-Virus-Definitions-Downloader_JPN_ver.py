import hashlib
import os
import requests
import time
import json
import re
from jsonpath import jsonpath
from tqdm import tqdm
from urllib.request import urlopen

# 提示用
print("================ SEP パターンファイル取得ツール ================")
print("SEP パターンファイルのダウンロードリンクを分析しています…")

# ここからはSEP12
link_sep12savce = requests.get(
    'https://www.broadcom.com/api/getjsonbyurl?vanityurl=support/security-center/definitions/download/detail&locale=avg_en&updateddate=&gid=sep'
)
link_sep12ips = requests.get(
    'https://www.broadcom.com/api/getjsonbyurl?vanityurl=support/security-center/definitions/download/detail&locale=avg_en&updateddate=&gid=ips'
)
# ここからはSEP14
link_sep14 = requests.get(
    'https://www.broadcom.com/api/getjsonbyurl?vanityurl=support/security-center/definitions/download/detail&locale=avg_en&updateddate=&gid=sep14'
)
link_ips14 = requests.get(
    'https://www.broadcom.com/api/getjsonbyurl?vanityurl=support/security-center/definitions/download/detail&locale=avg_en&updateddate=&gid=ips14'
)
link_sonar = requests.get(
    'https://www.broadcom.com/api/getjsonbyurl?vanityurl=support/security-center/definitions/download/detail&locale=avg_en&updateddate=&gid=sonar'
)

# 取得した元データ(str) を dict に転換する
json_sep12savce = json.loads(link_sep12savce.text)
json_sep12ips = json.loads(link_sep12ips.text)
json_sep14 = json.loads(link_sep14.text)
json_ips14 = json.loads(link_ips14.text)
json_sonar = json.loads(link_sonar.text)

# ダウンロードリンクが記載される JSON の分析
# （ここからはSEP12）
# savce(SEP12) 定義ファイルに関する JSON コードの抽出
v5i64 = jsonpath(json_sep12savce, "$[groups][0][packages][1][file][_url_]")
v5i64_MD5 = jsonpath(json_sep12savce, "$[groups][0][packages][1][file][md5]")
v5i64_filename = jsonpath(json_sep12savce,
                          "$[groups][0][packages][1][file][name]")
jdb = jsonpath(json_sep12savce, "$[groups][0][packages][2][file][_url_]")
jdb_MD5 = jsonpath(json_sep12savce, "$[groups][0][packages][2][file][md5]")
jdb_filename_org = jsonpath(json_sep12savce,
                        "$[groups][0][packages][2][file][name]")

# ips(SEP12) ファイルに関する JSON コードの抽出
ips_exe = jsonpath(json_sep12ips, "$[groups][0][packages][0][file][_url_]")
ips_exe_MD5 = jsonpath(json_sep12ips, "$[groups][0][packages][0][file][md5]")
ips_exe_filename_org = jsonpath(json_sep12ips,
                            "$[groups][0][packages][0][file][name]")
ips_jdb = jsonpath(json_sep12ips, "$[groups][0][packages][1][file][_url_]")
ips_jdb_MD5 = jsonpath(json_sep12ips, "$[groups][0][packages][1][file][md5]")
ips_jdb_filename_org = jsonpath(json_sep12ips,
                            "$[groups][0][packages][1][file][name]")

# SEP14 ファイルに関する JSON コードの抽出
core15sds_v5i64 = jsonpath(json_sep14,
                           "$[groups][0][packages][5][file][_url_]")
core15sds_v5i64_MD5 = jsonpath(json_sep14,
                               "$[groups][0][packages][5][file][md5]")
core15sds_v5i64_filename = jsonpath(json_sep14,
                                    "$[groups][0][packages][5][file][name]")
core15sds_jdb = jsonpath(json_sep14, "$[groups][0][packages][8][file][_url_]")
core15sds_jdb_MD5 = jsonpath(json_sep14,
                             "$[groups][0][packages][8][file][md5]")
core15sds_jdb_filename_org = jsonpath(json_sep14,
                                  "$[groups][0][packages][8][file][name]")

# ips(SEP14) ファイルに関する JSON コードの抽出
ips14_exe = jsonpath(json_ips14, "$[groups][0][packages][4][file][_url_]")
ips14_exe_MD5 = jsonpath(json_ips14, "$[groups][0][packages][4][file][md5]")
ips14_exe_filename_org = jsonpath(json_ips14,
                              "$[groups][0][packages][4][file][name]")

ips14_jdb = jsonpath(json_ips14, "$[groups][0][packages][5][file][_url_]")
ips14_jdb_MD5 = jsonpath(json_ips14, "$[groups][0][packages][5][file][md5]")
ips14_jdb_filename_org = jsonpath(json_ips14,
                              "$[groups][0][packages][5][file][name]")

# sonar ファイルに関する JSON コードの抽出
sonar_exe = jsonpath(json_sonar, "$[groups][0][packages][0][file][_url_]")
sonar_exe_MD5 = jsonpath(json_sonar, "$[groups][0][packages][0][file][md5]")
sonar_exe_filename_org = jsonpath(json_sonar,
                              "$[groups][0][packages][0][file][name]")
sonar_jdb = jsonpath(json_sonar, "$[groups][0][packages][1][file][_url_]")
sonar_jdb_MD5 = jsonpath(json_sonar, "$[groups][0][packages][1][file][md5]")
sonar_jdb_filename_org = jsonpath(json_sonar,
                              "$[groups][0][packages][1][file][name]")

# ファイル名整形
jdb_filename = re.findall('v.*b', str(jdb_filename_org))
ips_exe_filename = re.findall('2.*e', str(ips_exe_filename_org))
ips_jdb_filename = re.findall('2.*b', str(ips_jdb_filename_org))
core15sds_jdb_filename = re.findall('v.*b', str(core15sds_jdb_filename_org))
ips14_exe_filename = re.findall('2.*e', str(ips14_exe_filename_org))
ips14_jdb_filename = re.findall('2.*b', str(ips14_jdb_filename_org))
sonar_exe_filename = re.findall('2.*e', str(sonar_exe_filename_org))
sonar_jdb_filename = re.findall('2.*b', str(sonar_jdb_filename_org))

# List で取集したリンク・ファイル名・ファイル MD5 情報を格納
link_list = [
    v5i64[0], jdb[0], ips_exe[0], ips_jdb[0], sonar_exe[0], sonar_jdb[0],
    core15sds_v5i64[0], core15sds_jdb[0], ips14_exe[0], ips14_jdb[0]
]

filename_list = [
    v5i64_filename[0], jdb_filename[0], ips_exe_filename[0],
    ips_jdb_filename[0], sonar_exe_filename[0], sonar_jdb_filename[0],
    core15sds_v5i64_filename[0], core15sds_jdb_filename[0],
    ips14_exe_filename[0], ips14_jdb_filename[0]
]

MD5_list = [
    v5i64_MD5[0], jdb_MD5[0], ips_exe_MD5[0], ips_jdb_MD5[0], sonar_exe_MD5[0],
    sonar_jdb_MD5[0], core15sds_v5i64_MD5[0], core15sds_jdb_MD5[0],
    ips14_exe_MD5[0], ips14_jdb_MD5[0]
]

# 提示 & Debug用
#print(link_list, filename_list, MD5_list)
print("======================== 分析完了 ========================")
print("SEP パターンファイルのダウンロードしています…")

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
