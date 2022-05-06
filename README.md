#### 1. 创建conda环境
```
conda create -n EVE_ESI_tool python=3.8
```

#### 2. 安装必须的库

```
conda install -c conda-forge requests python-jose pyyaml
```

#### 3. 使用`utils.get_refresh_token`绑定新账户
* 详见`example.py`