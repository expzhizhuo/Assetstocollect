# 关联资产收集，基于FOFA api

## 配置

打开脚本文件修改config中的email和key，email是fofa的注册邮箱，key是fofa个人中心的api key

```bash
config = {
    'email': '',  # fofa的登录邮箱
    'key': '',  # fofa个人中心的key
    'size': '100',  # 默认是是普通会员，普通会员做多100条，高级会员10000条,程序会根据会员等级自动调整
    'base_url': 'https://fofa.info/api/v1/search/all',  # fofa api接口地址
    'user_url': 'https://fofa.info/api/v1/info/my',  # fofa 账户信息接口
}
```



首次使用需要安装依赖文件

```bash
pip3 install requests
pip3 install base64
pip3 install argparse
```

使用命令

```bash
python3 .\Assetstocollect.py -h
```

就可以查看相关使用命令

```bash
usage: Assetstocollect.py [-h] [-u URL] [-uf [URL_FILE]] [-i IP] [-if [IP_FILE]]

关联资产收集基于FOFA API --By zhizhuo 由于FOFA会员等级限制，普通会员最多100条，高级会员做多10000条 程序默认下载api可获取最大数量

optional arguments:
  -h, --help            show this help message and exit
  -u URL, -url URL      单个url关联资产收集，例如：baidu.com顶级域名
  -uf [URL_FILE], --url-file [URL_FILE]
                        多个url关联资产收集，以文件形式存储,文件中的url格式为baidu.com顶级域名
  -i IP, -ip IP         单个ip关联资产收集，例如：192.168.0.1
  -if [IP_FILE], --ip-file [IP_FILE]
                        多个ip关联资产收集，以文件形式存储,文件中的ip格式为192.168.0.1
```

输出文件在脚本的当前目录为ip_result.txt和url_result.txt

项目地址：https://github.com/zhizhuoshuma/Assetstocollect

后续会优化添加其他功能
