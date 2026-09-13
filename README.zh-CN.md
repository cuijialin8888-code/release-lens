# release-lens

**在发布包交到用户手里之前，先发现发布目录里的错误。**

`release-lens` 是一个离线、确定性的开源发布包体检器：检查版本一致性、Python wheel/sdist 元数据、压缩包路径安全、重复 ZIP 成员，以及 SHA-256 校验和清单。

它与发布器不同：

- `audit` 只读，不解压、不安装、不导入、不执行包内代码；
- 默认不联网，只读取你指定的发布目录；
- 运行时零第三方依赖，只使用 Python 标准库；
- 每条问题都有稳定的 `RLA###` 编号，并提供本地证据；
- 支持终端、JSON、Markdown 报告。

## 30 秒开始

```console
python -m pip install .
release-lens audit dist --expected-version 0.1.0
```

生成 SHA-256 清单是单独的、显式的写操作：

```console
release-lens manifest dist
release-lens audit dist --expected-version 0.1.0 --format json --strict
```

有错误时 `audit` 返回退出码 `1`；使用 `--strict` 时，警告也会使检查失败。

## 检查内容

| 范围 | 内容 |
| --- | --- |
| 版本身份 | 期望版本、wheel/sdist 元数据、本地 `pyproject.toml` 版本 |
| Python 包 | wheel 的 `METADATA`/`RECORD`、sdist 的 `PKG-INFO` |
| 压缩包安全 | 绝对路径、父目录路径、重复 ZIP 成员、tar 链接 |
| 完整性 | GNU/BSD/普通格式 SHA-256 清单、缺失项、摘要不匹配、未覆盖资产 |
| 输出 | 稳定问题编号、资产摘要/大小、终端/JSON/Markdown |

## 边界

它不保证包没有恶意代码、可重复构建、已签名或符合某个生态系统的全部发布规范；也不会访问 GitHub、包索引或密钥服务器。压缩包只检查成员，不会解压。完整边界见 [docs/design.md](docs/design.md)。

## 开发

```console
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

MIT 许可证，见 [LICENSE](LICENSE)。
