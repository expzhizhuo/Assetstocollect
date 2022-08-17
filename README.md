# 关联资产收集，基于FOFA api

## 新增计划

- 新增资产存活检测 已完成
- 新增资产指纹识别 未完成
- 新增xray工具联动 未完成
- 新增awvs工具联动 未完成
- 新增afrog工具联动 已完成
- 新增关联资产爬虫 未完成
- 新增WAF识别 未完成
- 新增多线程资产存活探测 未完成
- 新增其他测绘平台 未完成
- 新增数据自动去重 未完成
- 新增子域名资产穷举 未完成
- 新增fofa语句插件 已完成

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
python3 .\scan.py -h
```

就可以查看相关使用命令

```bash
optional arguments:
  -h, --help            show this help message and exit
  -u URL, -url URL      单个url关联资产收集，例如：baidu.com顶级域名
  -uf [URL_FILE], --url-file [URL_FILE]
                        多个url关联资产收集，以文件形式存储,文件中的url格式为baidu.com顶级域名
  -i IP, -ip IP         单个ip关联资产收集，例如：192.168.0.1
  -if [IP_FILE], --ip-file [IP_FILE]
                        多个ip关联资产收集，以文件形式存储,文件中的ip格式为192.168.0.1
  -d [DETECTION], -D [DETECTION]
                        检测通过FOFA获取到的资产存活状态
  -s [SCAN], -S [SCAN]  使用afrog对从fofa获取的资产进行扫描
  -se [SEARCH], --search [SEARCH]
                        fofa语法查询，输入fofa的查询语句即可，程序会自动进行Base64加密
```

**输出文件在脚本的当前目录在result目录下面**

**fofa的查询结果在fofa.txt中**

**afrog的扫描结果在reports目录下面**

项目地址：https://github.com/zhizhuoshuma/Assetstocollect

后续会优化添加其他功能
