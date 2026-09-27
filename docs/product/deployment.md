# 节点调查试点部署

## 交付模式

单组织私有部署。浏览器与后端同源；所有日志、运行记录和证据保留在部署主机。默认回环地址只用于演示。共享口令支持一组分析员共同使用同一工作空间，并不提供用户级权限或多租户隔离。

## 安装与启动

```bash
python -m venv .venv-product
.venv-product/bin/pip install -r requirements-product.txt
export NODOZE_PYTHON="$PWD/.venv-product/bin/python"
export NODOZE_DATASET_CATALOG="$PWD/webapp/runtime/examples/catalog.json"
export NODOZE_RUN_STORE="$PWD/webapp/runtime/investigations"
export NODOZE_BIND='127.0.0.1:8000'
webapp/deploy/start.sh
```

测试部署时使用 Gunicorn 26.2.0。配置为 1 个进程、4 个线程，同一实例同时最多一项剪枝计算；已有计算时新请求返回 409。这个配置是本项目内存与同步锁约束的选择，并非通用最优配置。Gunicorn 的线程和进程模型见[官方设置](https://docs.gunicorn.org/en/stable/settings.html)与[设计文档](https://docs.gunicorn.org/en/stable/design.html)；版本来源是 [PyPI 26.2.0](https://pypi.org/project/gunicorn/26.2.0/)。

生产入口通过同源 TLS 反向代理访问回环 Gunicorn。用安全渠道生成并设置两个**不同**的随机值，每个至少 32 字符：

- `NODOZE_ACCESS_TOKEN`：共享访问口令。浏览器登录后仅保留 HttpOnly / SameSite=Strict 会话 Cookie；不放入 URL 或 localStorage。
- `NODOZE_SESSION_SECRET`：服务端会话签名密钥，重启保持稳定。
- `NODOZE_SECURE_COOKIE=1`：TLS 环境启用。

代理转发 `Host` 与 `X-Forwarded-Proto`；仅可信回环代理连接 Gunicorn，防止将客户端自行提供的转发头当成真实连接信息。需给调查请求配置足够的代理读取超时，并按客户实际规模测试。

不要把口令写入仓库、截图或启动命令参数。非回环绑定缺少访问配置时启动会拒绝。回环演示没有口令，不应直接映射到外部服务。

## 客户数据接入

当前输入是 eCAR 格式逐行 JSON，可 gzip 压缩。字段最少包括：

```json
{"id":"event-001","actorID":"process-001","objectID":"file-001","hostname":"customer-host","pid":123,"object":"FILE","action":"WRITE","timestamp":"2026-09-27T10:00:00+08:00","properties":{"image_path":"customer.exe","file_path":"customer.txt"}}
```

`id` 是全日志唯一事件身份，`actorID/objectID` 是稳定实体 ID；时间必须有时区。当前解析器支持 FILE、PROCESS、FLOW。FILE READ 与 inbound FLOW 按信息流方向转换；其他关系适配需要显式确认语义，不能直接把所有日志字段当成因果边。应提供候选窗口之前的同主机历史，否则没有可用频率基线。

```bash
python webapp/scripts/prepare_customer.py \
  --input /data/customer/events.jsonl.gz \
  --host customer-host \
  --start '2026-09-27T10:10:00+08:00' \
  --end '2026-09-27T10:40:00+08:00' \
  --dataset-id customer-incident-001 \
  --name '客户事件调查' \
  --output webapp/runtime/customer-incident-001-v1.json \
  --catalog webapp/runtime/customer-catalog.json
```

将 `NODOZE_DATASET_CATALOG` 指向生成的目录文件后重启服务。工具不需要 PDF、真值、POI 或告警；操作员在网页中选择节点与关联时间锚。工具不会覆盖已存在输出或重复目录 ID，冲突事件身份和缺少时区会失败。同一目录仅由一个操作员顺序写入；目录与账本不是跨文件数据库事务。

只建立候选账本，不自动运行剪枝。目录支持原始只读缓存与版本化历史 SQLite 索引，路径需在部署机可读。旧 /research 页面用于已有研究演示；新客户账本请从产品入口调查。

## API 与证据

- `GET /api/datasets/<id>/nodes?q=...&type=...`：节点检索。
- `GET /api/datasets/<id>/nodes/<node>/events?page=0&q=...`：关联锚候选。
- `POST /api/investigations`：`dataset_id/node_id/anchor_event_id/budget_edges`。
- `GET /api/investigations?page=0`：产品历史分页，每页 30 项。
- `GET /api/investigations/<run>`：冻结结果。
- `GET .../<run>/events`、`.../events/<event>`：事件与见证。
- `GET .../<run>/export`、`.../export.csv`：JSON 可复放证据与保留事件 CSV。

配置访问口令后，API 可使用 `Authorization: Bearer <token>` 或网页登录会话。旧研究 `/prune` 同样返回独立运行 ID，后续旧接口读取必须带 `run_id` 查询参数，源缓存不会再被覆盖。

CSV 对日志中的公式起始字符加保护引号，JSON 保存原值。JSON 包含候选事件决策向量以及保留原始日志，文件可能较大且包含敏感调查信息。

## 运行与恢复

- 运行数据保存为 `NODOZE_RUN_STORE/runs.sqlite` 的压缩结果及元数据。目录创建权限 0700，数据库 0600；外层文件系统权限仍由部署方管理。
- SQLite 使用 WAL。备份请使用 SQLite 备份 API，或停止服务后整体备份目录；不要在运行时只复制主数据库文件。
- 原始源数据离线后，冻结结果仍可查看、检索和导出；重新运行需要恢复历史索引和候选缓存。
- 当前无自动清理和保留周期任务；容量与备份需纳入试点运维。读取热缓存只保存一项运行，避免重复解压；源数据全量加载仍有明显内存成本。
- 日志不记录鉴权口令或查询参数；服务端错误带 incident_id，不把堆栈返回浏览器。

## 验收复现

```bash
python -m pytest -q
python webapp/scripts/verify_product_browser.py --url http://127.0.0.1:8000
PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  python scripts/benchmark_product.py --catalog webapp/runtime/examples/catalog.json
python webapp/scripts/verify_decision_audit.py downloaded-evidence.json
```

浏览器验收需另装 Python Playwright 和 Chromium，不属于运行时依赖。脚本会创建实际调查记录，适合试点验收或测试空间使用。
