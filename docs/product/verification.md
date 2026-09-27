# 最终交付验证

验证日期：2026-09-28，Asia/Shanghai。

## 已运行的检查

- 产品隔离分支 `product/node-guided-investigation`：完整 pytest **696 passed**，13.29 秒。
- 接入现有主工作目录：完整 pytest **555 passed**，12.91 秒。两处原有测试集合不同，数量不应相加。
- `git diff --check` 无空白错误；产品 JavaScript 经 `node --check` 检查。
- 独立代码审查发现 2 个 Important 问题，均以回归验证修复：历史须先筛选产品再分页；冻结结果重开不依赖在线原始数据。
- 后续审查覆盖这些修复、客户日志准备及 Gunicorn 配置；15 项相关测试通过，无剩余 Critical / Important 发现。
- 原网页 `http://127.0.0.1:8000/` 已替换为节点工作台，通过 Gunicorn 单进程 4 线程运行；`/research` 保留研究界面。
- 在正式接入的 8000 端口再次运行真实 Chromium 验收。27,011 候选事件，B=1,000，保留 502，缩减 98.14%，未用 498；完整 UI 5.907 秒。第二次 B=256 独立保存。JSON/CSV 下载、见证详情、历史重开、390 px 无横向溢出、模拟原数据接口离线后重开与导出均成功。无 JS 异常。记录见 browser-validation.json。
- 五个既有源码文件在接入前逐一与基线比对，避免覆盖用户修改；27 项产品文件受控接入。原主工作目录 26 项已存在的修改/删除内容保持一致。备份清单位于 `webapp/runtime/product-release-backups/75160ad5d9804d15998f22bf2dffd6cf/manifest.json`。

## 未验收的内容

未做公网部署、外部发布、客户真实数据盲测、SSO/RBAC、多租户、负载 p95 或 SLA 验收。未取得完整逐事件真值，也未复现作者版 SPARSE。不会据此声称这些事项已经完成。
