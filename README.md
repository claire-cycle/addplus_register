# AddPlus Twitter Auth Tool

## 项目简介

这是一个用于自动化Twitter/X账号认证并获取AddPlus平台推广链接的工具。该工具可以批量处理多个Twitter账号的认证流程，获取AddPlus平台的会话令牌，并生成推广链接。

## 功能特点

- 自动化Twitter/X OAuth2认证流程
- 批量处理多个Twitter账号
- 自动获取AddPlus平台会话令牌
- 生成并保存推广链接
- 完整的Cookie管理和会话处理
- 详细的日志输出和错误处理

## 安装要求

- Python 3.6+
- 依赖包：requests

## 安装方法

```bash
# 克隆仓库
git clone https://github.com/yourusername/addplus-ref.git
cd addplus-ref

# 安装依赖
pip install -r requirements.txt
```

## 使用方法

1. 在`xtoken.txt`文件中添加Twitter/X账号的认证令牌，每行一个
2. 运行主程序

```bash
python main.py
```

3. 程序会自动处理每个令牌，并将生成的推广链接保存到`ref_url.txt`文件中

## 文件说明

- `main.py`: 主程序，包含认证流程和推广链接生成逻辑
- `xauth.py`: Twitter/X认证工具类，处理OAuth1和OAuth2认证流程
- `xtoken.txt`: 存储Twitter/X账号认证令牌的文件
- `ref_url.txt`: 存储生成的推广链接和会话令牌的文件
- `test.py`: 测试脚本，用于测试认证回调

## 获取Twitter/X认证令牌

要获取Twitter/X认证令牌，您需要：

1. 登录您的Twitter/X账号
2. 从浏览器开发者工具中获取`auth_token`的值
3. 将获取到的令牌添加到`xtoken.txt`文件中

## 注意事项

- 请合理使用该工具，避免频繁请求导致账号被限制
- 默认情况下，每个令牌处理完成后会等待5秒再处理下一个
- 请确保您的网络环境能够正常访问Twitter/X和AddPlus平台

## 许可证

本项目采用MIT许可证。详情请参阅[LICENSE](LICENSE)文件。

## 免责声明

本工具仅供学习和研究使用，请勿用于非法用途。使用本工具所产生的任何后果由使用者自行承担。