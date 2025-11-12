#!/bin/bash

###############################################################################
# VPS Initial Setup Script
# Автоматическая настройка VPS сервера согласно best practices
# 
# Использование: sudo bash vps-initial-setup.sh
###############################################################################

set -e  # Остановка при ошибке
set -u  # Ошибка при использовании неопределенных переменных

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для логирования
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Проверка прав root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Этот скрипт должен быть запущен с правами root (sudo)"
        exit 1
    fi
}

# Определение дистрибутива
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        log_info "Обнаружен дистрибутив: $DISTRO $VERSION"
    else
        log_error "Не удалось определить дистрибутив"
        exit 1
    fi
}

# Обновление системы
update_system() {
    log_info "Обновление списка пакетов и системы..."
    
    if [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "debian" ]]; then
        apt-get update
        apt-get upgrade -y
        apt-get autoremove -y
        apt-get autoclean -y
    elif [[ "$DISTRO" == "centos" ]] || [[ "$DISTRO" == "rhel" ]] || [[ "$DISTRO" == "fedora" ]]; then
        if command -v dnf &> /dev/null; then
            dnf update -y
            dnf autoremove -y
        else
            yum update -y
            yum autoremove -y
        fi
    fi
    
    log_success "Система обновлена"
}

# Установка базовых утилит
install_basic_tools() {
    log_info "Установка базовых утилит..."
    
    if [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "debian" ]]; then
        apt-get install -y \
            curl \
            wget \
            git \
            vim \
            nano \
            htop \
            net-tools \
            ufw \
            fail2ban \
            unattended-upgrades \
            apt-listchanges \
            logwatch \
            rsync \
            zip \
            unzip \
            tree \
            jq \
            build-essential \
            software-properties-common
    elif [[ "$DISTRO" == "centos" ]] || [[ "$DISTRO" == "rhel" ]] || [[ "$DISTRO" == "fedora" ]]; then
        if command -v dnf &> /dev/null; then
            dnf install -y \
                curl \
                wget \
                git \
                vim \
                nano \
                htop \
                net-tools \
                firewalld \
                fail2ban \
                rsync \
                zip \
                unzip \
                tree \
                jq \
                gcc \
                gcc-c++ \
                make
        else
            yum install -y \
                curl \
                wget \
                git \
                vim \
                nano \
                htop \
                net-tools \
                firewalld \
                fail2ban \
                rsync \
                zip \
                unzip \
                tree \
                jq \
                gcc \
                gcc-c++ \
                make
        fi
    fi
    
    log_success "Базовые утилиты установлены"
}

# Создание нового пользователя
create_user() {
    log_info "Создание нового пользователя..."
    
    read -p "Введите имя нового пользователя: " NEW_USER
    
    if id "$NEW_USER" &>/dev/null; then
        log_warning "Пользователь $NEW_USER уже существует"
    else
        read -sp "Введите пароль для пользователя $NEW_USER: " USER_PASSWORD
        echo
        
        if [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "debian" ]]; then
            useradd -m -s /bin/bash "$NEW_USER"
        else
            useradd -m -s /bin/bash "$NEW_USER"
        fi
        
        echo "$NEW_USER:$USER_PASSWORD" | chpasswd
        usermod -aG sudo "$NEW_USER" 2>/dev/null || usermod -aG wheel "$NEW_USER" 2>/dev/null
        
        log_success "Пользователь $NEW_USER создан и добавлен в группу sudo"
    fi
}

# Настройка SSH
configure_ssh() {
    log_info "Настройка SSH..."
    
    SSH_CONFIG="/etc/ssh/sshd_config"
    SSH_BACKUP="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Создание резервной копии
    cp "$SSH_CONFIG" "$SSH_BACKUP"
    log_info "Резервная копия SSH конфигурации создана: $SSH_BACKUP"
    
    # Отключение root логина
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONFIG"
    
    # Отключение парольной аутентификации (только ключи)
    read -p "Отключить парольную аутентификацию? (y/n): " DISABLE_PASSWORD_AUTH
    if [[ "$DISABLE_PASSWORD_AUTH" == "y" ]]; then
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG"
        sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG"
        log_warning "Парольная аутентификация отключена. Убедитесь, что у вас есть SSH ключ!"
    fi
    
    # Изменение порта SSH (опционально)
    read -p "Изменить SSH порт? (y/n): " CHANGE_SSH_PORT
    if [[ "$CHANGE_SSH_PORT" == "y" ]]; then
        read -p "Введите новый порт (1024-65535): " NEW_SSH_PORT
        sed -i "s/#Port 22/Port $NEW_SSH_PORT/" "$SSH_CONFIG"
        sed -i "s/^Port [0-9]*/Port $NEW_SSH_PORT/" "$SSH_CONFIG"
        log_info "SSH порт изменен на $NEW_SSH_PORT"
    fi
    
    # Ограничение попыток входа
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' "$SSH_CONFIG"
    sed -i 's/^MaxAuthTries [0-9]*/MaxAuthTries 3/' "$SSH_CONFIG"
    
    # Отключение пустых паролей
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' "$SSH_CONFIG"
    sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/' "$SSH_CONFIG"
    
    # Отключение X11 forwarding
    sed -i 's/#X11Forwarding yes/X11Forwarding no/' "$SSH_CONFIG"
    sed -i 's/X11Forwarding yes/X11Forwarding no/' "$SSH_CONFIG"
    
    # Настройка таймаутов
    if ! grep -q "ClientAliveInterval" "$SSH_CONFIG"; then
        echo "ClientAliveInterval 300" >> "$SSH_CONFIG"
        echo "ClientAliveCountMax 2" >> "$SSH_CONFIG"
    fi
    
    # Перезагрузка SSH
    if [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "debian" ]]; then
        systemctl restart sshd || systemctl restart ssh
    else
        systemctl restart sshd
    fi
    
    log_success "SSH настроен"
}

# Настройка firewall
configure_firewall() {
    log_info "Настройка firewall..."
    
    if [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "debian" ]]; then
        # UFW для Ubuntu/Debian
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        
        # Разрешение SSH
        if [[ -n "${NEW_SSH_PORT:-}" ]]; then
            ufw allow "${NEW_SSH_PORT}/tcp" comment 'SSH'
        else
            ufw allow 22/tcp comment 'SSH'
        fi
        
        # Разрешение HTTP/HTTPS
        read -p "Разрешить HTTP (80) и HTTPS (443)? (y/n): " ALLOW_WEB
        if [[ "$ALLOW_WEB" == "y" ]]; then
            ufw allow 80/tcp comment 'HTTP'
            ufw allow 443/tcp comment 'HTTPS'
        fi
        
        ufw --force enable
        log_success "UFW настроен и активирован"
        
    elif [[ "$DISTRO" == "centos" ]] || [[ "$DISTRO" == "rhel" ]] || [[ "$DISTRO" == "fedora" ]]; then
        # Firewalld для CentOS/RHEL/Fedora
        systemctl enable firewalld
        systemctl start firewalld
        
        # Разрешение SSH
        if [[ -n "${NEW_SSH_PORT:-}" ]]; then
            firewall-cmd --permanent --add-port="${NEW_SSH_PORT}/tcp"
        else
            firewall-cmd --permanent --add-service=ssh
        fi
        
        # Разрешение HTTP/HTTPS
        read -p "Разрешить HTTP (80) и HTTPS (443)? (y/n): " ALLOW_WEB
        if [[ "$ALLOW_WEB" == "y" ]]; then
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
        fi
        
        firewall-cmd --reload
        log_success "Firewalld настроен и активирован"
    fi
}

# Настройка fail2ban
configure_fail2ban() {
    log_info "Настройка fail2ban..."
    
    if [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "debian" ]]; then
        systemctl enable fail2ban
        systemctl start fail2ban
    else
        systemctl enable fail2ban
        systemctl start fail2ban
    fi
    
    # Создание конфигурации для SSH
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendname = Fail2Ban
action = %(action_)s

[sshd]
enabled = true
port = ${NEW_SSH_PORT:-22}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
EOF
    
    systemctl restart fail2ban
    log_success "Fail2ban настроен"
}

# Настройка автоматических обновлений безопасности
configure_auto_updates() {
    log_info "Настройка автоматических обновлений безопасности..."
    
    if [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "debian" ]]; then
        cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
        
        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
        
        systemctl enable unattended-upgrades
        systemctl start unattended-upgrades
        log_success "Автоматические обновления безопасности настроены"
    else
        log_warning "Автоматические обновления для $DISTRO требуют ручной настройки"
    fi
}

# Настройка timezone
configure_timezone() {
    log_info "Настройка timezone..."
    
    read -p "Введите timezone (например, Europe/Moscow, America/New_York): " TIMEZONE
    
    if [[ -n "$TIMEZONE" ]]; then
        timedatectl set-timezone "$TIMEZONE"
        log_success "Timezone установлен: $TIMEZONE"
    else
        log_warning "Timezone не изменен"
    fi
}

# Настройка swap
configure_swap() {
    log_info "Проверка и настройка swap..."
    
    if [[ -z "$(swapon --show)" ]]; then
        read -p "Создать swap файл? (y/n): " CREATE_SWAP
        if [[ "$CREATE_SWAP" == "y" ]]; then
            read -p "Размер swap в GB (рекомендуется: 1-2x RAM): " SWAP_SIZE
            
            # Создание swap файла
            fallocate -l "${SWAP_SIZE}G" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_SIZE * 1024))
            chmod 600 /swapfile
            mkswap /swapfile
            swapon /swapfile
            
            # Добавление в fstab
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
            
            # Настройка swappiness
            echo 'vm.swappiness=10' >> /etc/sysctl.conf
            sysctl -p
            
            log_success "Swap файл создан (${SWAP_SIZE}GB)"
        fi
    else
        log_info "Swap уже настроен"
    fi
}

# Настройка sysctl для безопасности и производительности
configure_sysctl() {
    log_info "Настройка sysctl параметров..."
    
    cat >> /etc/sysctl.conf << 'EOF'

# Security settings
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Performance settings
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 2048
EOF
    
    sysctl -p
    log_success "Sysctl параметры настроены"
}

# Настройка лимитов системы
configure_limits() {
    log_info "Настройка лимитов системы..."
    
    cat >> /etc/security/limits.conf << 'EOF'

# Увеличение лимитов для файловых дескрипторов
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535

# Увеличение лимитов процессов
* soft nproc 65535
* hard nproc 65535
EOF
    
    log_success "Лимиты системы настроены"
}

# Отключение ненужных служб
disable_unnecessary_services() {
    log_info "Отключение ненужных служб..."
    
    # Список служб для отключения (если они установлены)
    SERVICES_TO_DISABLE=(
        "bluetooth"
        "cups"
        "avahi-daemon"
    )
    
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            systemctl stop "$service"
            systemctl disable "$service"
            log_info "Служба $service отключена"
        fi
    done
    
    log_success "Проверка служб завершена"
}

# Создание директории для SSH ключей нового пользователя
setup_ssh_keys() {
    if [[ -n "${NEW_USER:-}" ]]; then
        log_info "Настройка SSH ключей для пользователя $NEW_USER..."
        
        USER_HOME=$(eval echo ~$NEW_USER)
        SSH_DIR="$USER_HOME/.ssh"
        
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        chown "$NEW_USER:$NEW_USER" "$SSH_DIR"
        
        log_info "Директория для SSH ключей создана: $SSH_DIR"
        log_warning "Не забудьте добавить публичный SSH ключ в $SSH_DIR/authorized_keys"
    fi
}

# Вывод итоговой информации
print_summary() {
    echo ""
    log_success "=========================================="
    log_success "Настройка VPS завершена!"
    log_success "=========================================="
    echo ""
    log_info "Выполненные действия:"
    echo "  ✓ Система обновлена"
    echo "  ✓ Базовые утилиты установлены"
    if [[ -n "${NEW_USER:-}" ]]; then
        echo "  ✓ Пользователь $NEW_USER создан"
    fi
    echo "  ✓ SSH настроен"
    echo "  ✓ Firewall настроен"
    echo "  ✓ Fail2ban настроен"
    echo "  ✓ Автоматические обновления безопасности настроены"
    echo "  ✓ Sysctl параметры оптимизированы"
    echo ""
    log_warning "ВАЖНО:"
    if [[ -n "${NEW_USER:-}" ]]; then
        echo "  1. Убедитесь, что вы можете войти под пользователем $NEW_USER"
        echo "  2. Добавьте SSH ключ в ~/.ssh/authorized_keys для пользователя $NEW_USER"
    fi
    if [[ "${DISABLE_PASSWORD_AUTH:-}" == "y" ]]; then
        echo "  3. Парольная аутентификация отключена - используйте только SSH ключи"
    fi
    if [[ "${CHANGE_SSH_PORT:-}" == "y" ]]; then
        echo "  4. SSH порт изменен на ${NEW_SSH_PORT:-22}"
    fi
    echo "  5. Проверьте настройки firewall перед выходом из сессии root"
    echo ""
}

# Главная функция
main() {
    log_info "Начало настройки VPS сервера..."
    echo ""
    
    check_root
    detect_distro
    update_system
    install_basic_tools
    create_user
    configure_ssh
    configure_firewall
    configure_fail2ban
    configure_auto_updates
    configure_timezone
    configure_swap
    configure_sysctl
    configure_limits
    disable_unnecessary_services
    setup_ssh_keys
    print_summary
    
    log_success "Все настройки применены успешно!"
}

# Запуск скрипта
main "$@"

