# FakeSSH

[![CI and container image](https://github.com/YeTianXingShi/fakessh/actions/workflows/ci.yml/badge.svg)](https://github.com/YeTianXingShi/fakessh/actions/workflows/ci.yml)
[![Container image](https://img.shields.io/badge/GHCR-ghcr.io%2Fyetianxingshi%2Ffakessh-blue?logo=docker)](https://github.com/YeTianXingShi/fakessh/pkgs/container/fakessh)

FakeSSH 是一个被动 SSH 凭据蜜罐：它接受 password 和单密码提示的 keyboard-interactive 认证，记录提交内容，然后始终返回认证失败。服务不提供 shell，也不会主动连接、扫描或回传任何外部主机。同一进程还提供无需登录的只读 Web 面板。

> **警告：Web 面板会公开显示捕获到的明文用户名、密码和来源 IP。** 不要在未理解风险时将 8080 端口暴露到公网。建议通过防火墙、VPN 或反向代理访问控制限制面板；应用本身按需求不提供登录。

## 功能

- SSH 监听 `:2222`，所有密码认证始终失败，不创建会话或 shell。
- 按“完整用户名原始字节 + 完整密码原始字节”去重并累计次数。
- 按“凭据 + IP + 认证方式 + SSH 客户端版本”聚合来源。
- SQLite 使用事务、UPSERT、WAL 和 busy timeout，小时桶保存近期趋势。
- 记录首次/最后时间、来源 IPv4/IPv6、端口、方法和客户端版本。
- 展示字段有长度上限；超长值带截断标记，完整值摘要仍参与去重。
- 非 UTF-8、控制字符以 `\xNN` 安全转义；HTML 模板自动转义动态内容。
- SSH Ed25519 主机密钥首次启动自动生成在数据卷内，重启不会改变。
- 只读面板提供统计、筛选、分页、来源明细、复制按钮和健康检查。

## 使用 Docker Compose

```bash
docker compose up -d --build
docker compose ps
```

若不需要本地构建，可以在 `compose.yaml` 中删除 `build: .`，并把镜像改为公开的多架构镜像：

```yaml
image: ghcr.io/yetianxingshi/fakessh:latest
```

或直接运行：

```bash
docker pull ghcr.io/yetianxingshi/fakessh:latest
docker run -d --name fakessh \
  --restart unless-stopped \
  --security-opt no-new-privileges:true --cap-drop ALL \
  -p 2222:2222 -p 8080:8080 \
  -v fakessh-data:/data \
  ghcr.io/yetianxingshi/fakessh:latest
```

生产部署也可以固定首个稳定版本，避免跟随 `latest` 自动升级：

```bash
docker pull ghcr.io/yetianxingshi/fakessh:1.0.0
```

默认映射：

- 宿主机 `22` → 容器 SSH `2222`
- 宿主机 `8080` → 容器 Web `8080`
- 命名卷 `fakessh-data` → `/data`

连接测试：

```bash
ssh root@localhost
curl http://localhost:8080/healthz
```

无论输入什么密码，SSH 都应返回认证失败；随后可在 `http://localhost:8080/attempts` 查看记录。

若宿主机的真实 sshd 已占用 22 端口，请把 [compose.yaml](compose.yaml) 改为例如 `"2222:2222"`，然后使用 `ssh -p 2222 root@localhost`。不要为了蜜罐停止唯一的远程管理入口。

## 直接构建和运行

需要 Go 1.24 或更高版本：

```bash
go test ./...
go build -o fakessh ./cmd/fakessh
DATA_DIR=./data SSH_LISTEN_ADDR=:2222 WEB_LISTEN_ADDR=:8080 ./fakessh
```

也可以只构建镜像：

```bash
docker build -t fakessh:local .
docker run -d --name fakessh \
  -p 2222:2222 -p 8080:8080 \
  -v fakessh-data:/data fakessh:local
```

最终容器以 UID/GID `10001` 运行，丢弃全部 Linux capabilities，并启用 Docker healthcheck。

## 配置

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `SSH_LISTEN_ADDR` | `:2222` | SSH 监听地址 |
| `WEB_LISTEN_ADDR` | `:8080` | Web 监听地址 |
| `DATA_DIR` | `/data` | 持久化目录 |
| `DB_PATH` | `/data/fakessh.db` | SQLite 数据库路径 |
| `SSH_HOST_KEY_PATH` | `/data/ssh_host_ed25519_key` | SSH 主机私钥路径 |
| `LOG_LEVEL` | `info` | `debug`、`info`、`warn` 或 `error` |

`DB_PATH` 和 `SSH_HOST_KEY_PATH` 的默认值跟随 `DATA_DIR`。这是单实例 SQLite 服务，不要让多个容器同时写同一个数据卷。

## Web 路由

- `/`：总次数、唯一凭据/IP、小时趋势和 Top 排名。
- `/attempts`：凭据列表，可按用户名、密码、IP、方法和客户端版本筛选，单页最多 200 条。
- `/sources`：聚合来源；从凭据列表进入时仅显示对应凭据。
- `/healthz`：进程和 SQLite 可用性检查。

所有筛选均使用绑定参数。Web 响应设置严格 CSP、`noindex`、禁止 MIME sniffing、禁止嵌入等安全头。第一版没有写入、删除或 CSV 导出接口。

## 备份和恢复

最稳妥的方式是短暂停止容器后复制整个卷中的数据库、WAL 文件和主机密钥：

```bash
docker compose stop fakessh
docker run --rm -v fakessh-data:/data -v "$PWD":/backup alpine:3.22 \
  tar -C /data -czf /backup/fakessh-backup.tar.gz .
docker compose start fakessh
```

恢复时使用新的空卷，并保持文件由 UID `10001` 可读写。主机密钥位于备份中；保留它可避免 SSH 客户端报告主机指纹变化。数据默认永久保留，没有自动清理任务。

## 测试

```bash
go test ./...
go test -race ./...
docker build -t fakessh:local .
```

测试覆盖凭据去重、不同来源聚合、并发计数、时间范围、重启持久化、SSH 两种认证始终失败、主机密钥持久化、筛选/分页、IPv6、二进制和超长字段、安全转义及健康检查。

## GitHub CI/CD

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) 在每次提交和 Pull Request 时执行竞态测试与 `go vet`。推送到 `main` 后会使用 Buildx 构建 `linux/amd64`、`linux/arm64` 镜像并发布：

- `ghcr.io/yetianxingshi/fakessh:latest`
- `ghcr.io/yetianxingshi/fakessh:sha-<commit>`
- `ghcr.io/yetianxingshi/fakessh:1.0.0`、`:1.0`、`:1`（当前稳定版）

推送形如 `v1.2.3` 的 Git 标签会生成 `1.2.3`、`1.2` 和 `1` 镜像标签。该仓库的 GHCR 软件包已设为公开，无需 GitHub 登录即可拉取。
