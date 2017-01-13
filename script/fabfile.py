from __future__ import with_statement
from fabric import tasks
from fabric.api import *
from fabric.contrib.console import confirm
from fabric.contrib.files import *
from fabric.network import disconnect_all

env.user = 'root'
env.mysql_user = 'root'
env.password = ''
env.cdh_version = '5.9.0'
env.ips = '172.0.0.1 172.0.0.2 172.0.0.3 172.0.0.4'
env.rds_host = 'rdshost.amazonaws.com'
env.rds_user = 'rds_admin'
env.ldap_url = 'LDAP-IP'



def prepare_cm_node():
    prepare_linux()
    prepare_mysql()
    prepare_cloudera_manager()

def prepare_cm_node_rhel7():
    prepare_linux_rhel7()
    prepare_mariadb()
    prepare_cloudera_manager_rhel7()

def prepare_cm_node_rds():
    prepare_linux()
    prepare_rds()
    prepare_cloudera_manager_rds()

def prepare_cm_node_kerberos():
    prepare_cm_node()
    prepare_kerberos()

def prepare_data_node():
    prepare_linux()

def prepare_data_node_rhel7():
    prepare_linux_rhel7()

def prepare_data_node_kerberos():
    prepare_data_node()
    prepare_kerberos()

def prepare_data_node_rhel7_kerberos():
    prepare_data_node_rhel7()
    prepare_kerberos()



def prepare_linux():
    #NTP Setup
    with settings(warn_only=True):
        yum_auto_install("ntp")
        yum_auto_install("ntpdate")
        yum_auto_install("ntp-doc")
        sudo("chkconfig ntpd on")
        sudo("service ntpd stop")
        sudo("ntpdate pool.ntp.org")
        sudo("service ntpd start")

    #Add hostname and IP to /etc/hosts
    with settings(warn_only=True):
        if run("cat /etc/hosts | grep .ec2.internal").failed == True:
            sudo('echo "{}   {} {}" >> /etc/hosts'.format(hostname_ip(),hostname_fqdn(),hostname_short()))

    #IPv6 Disable
    with settings(warn_only=True):
        if run("cat /etc/sysctl.conf | grep net.ipv6.conf.all.disable_ipv6").failed == True:
            sudo('echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf')
        else:
            sed("/etc/sysctl.conf", '^net.ipv6.conf.all.disable_ipv6.*', 'net.ipv6.conf.all.disable_ipv6 = 1',use_sudo=True)

    with settings(warn_only=True):
        if sudo("cat /etc/sysctl.conf | grep net.ipv6.conf.default.disable_ipv6").failed == True:
            sudo('echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf')
        else:
            sed("/etc/sysctl.conf", '^net.ipv6.conf.default.disable_ipv6.*', 'net.ipv6.conf.default.disable_ipv6 = 1',use_sudo=True)

    with settings(warn_only=True):
        if sudo("cat /etc/sysconfig/network | grep NETWORKING_IPV6").failed == True:
            sudo('echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network')
        else:
            sed("/etc/sysconfig/network", '^NETWORKING_IPV6=.*', 'NETWORKING_IPV6=no',use_sudo=True)

    with settings(warn_only=True):
        if sudo("cat /etc/sysconfig/network | grep IPV6INIT").failed == True:
            sudo('echo "IPV6INIT=no" >> /etc/sysconfig/network')
        else:
            sed("/etc/sysconfig/network", '^IPV6INIT=.*', 'IPV6INIT=no',use_sudo=True)

    #IP Tables Stopped and Off
    sudo("service iptables stop")
    sudo("chkconfig iptables off")
    sudo("service ip6tables stop")
    sudo("chkconfig ip6tables off")

    #Swappiness
    sudo("sysctl vm.swappiness=0")
    with settings(warn_only=True):
        if sudo("cat /etc/sysctl.conf | grep vm.swappiness").failed == True:
            sudo('echo "vm.swappiness = 0" >> /etc/sysctl.conf')
        else:
            sed("/etc/sysctl.conf","vm.swappiness.*","vm.swappiness = 0",use_sudo=True)

    #Name Service Caching Daemon
    with settings(warn_only=True):
        yum_auto_install("nscd")
        sudo("service nscd start")
        sudo("chkconfig nscd on")

    #SE Linux
    sed("/etc/selinux/config",'^SELINUX=.*','SELINUX=disabled',use_sudo=True)

    #Disable Transparent Huge Pages
    with settings(warn_only=True):
        sudo('echo never > /sys/kernel/mm/redhat_transparent_hugepage/defrag')
        sudo('echo never > /sys/kernel/mm/redhat_transparent_hugepage/enabled')
        if sudo('cat /etc/rc.local | grep "echo never > /sys/kernel/mm/redhat_transparent_hugepage/defrag"').failed == True:
            sudo('echo "echo never > /sys/kernel/mm/redhat_transparent_hugepage/defrag" >> /etc/rc.local')
        if sudo('cat /etc/rc.local | grep "echo never > /sys/kernel/mm/redhat_transparent_hugepage/enabled"').failed == True:
            sudo('echo "echo never > /sys/kernel/mm/redhat_transparent_hugepage/enabled" >> /etc/rc.local')

    #Stop Unnecessary Services
    with settings(warn_only=True):
        sudo("service cups stop")
        sudo("service postfix stop")
        sudo("service bluetooth stop")

    #Reload sysctl
    with settings(warn_only=True):
        sudo("sysctl -p")

    #Install WGET
    yum_auto_install("wget")

    #Install Desired version of Java
    with settings(warn_only=True):
        yum_auto_remove("jre-1.5.0-gcj")
        yum_auto_remove("java-1.6.0-openjdk")
        yum_auto_remove("java-1.7.0-openjdk")
        yum_auto_remove("jdk1.8.0_66")
        sudo("rm jdk-8u66-linux-x64.rpm")
        sudo('wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u66-b14/jdk-8u66-linux-x64.rpm"')
        sudo("rpm -ivh jdk-8u66-linux-x64.rpm")

    #Install CM API Python Extensions
    sudo("rpm -ivh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm")
    yum_auto_install("python-pip")
    sudo("pip install cm-api")

    #Mount EBS Volume
    # sudo("mkfs -t ext4 /dev/xvdb")
    # sudo("mkfs -t ext4 /dev/xvdc")
    # sudo("mkdir /data01")
    # sudo("mkdir /data02")
    # sudo("mount -t ext4 /dev/xvdb /data01 -o noatime")
    # sudo("mount -t ext4 /dev/xvdc /data02 -o noatime")
    # sudo("echo '/dev/xvdb /data01 ext4 defaults,noatime 0 0' >> /tmp/fstab")
    # sudo("echo '/dev/xvdc /data02 ext4 defaults,noatime 0 0' >> /tmp/fstab")
    # sudo("sh -c 'cat /tmp/fstab >> /etc/fstab'")


def prepare_linux_rhel7():
    #NTP Setup
    with settings(warn_only=True):
        yum_auto_install("ntp")
        yum_auto_install("ntpdate")
        sudo("systemctl enable ntpd")
        sudo("systemctl stop ntpd")
        sudo("ntpdate pool.ntp.org")
        sudo("systemctl start systemctl")

    #Add hostname and IP to /etc/hosts
    with settings(warn_only=True):
        if run("cat /etc/hosts | grep .ec2.internal").failed == True:
            sudo('echo "{}   {} {}" >> /etc/hosts'.format(hostname_ip(),hostname_fqdn(),hostname_short()))

    #IPv6 Disable
    with settings(warn_only=True):
        if run("cat /etc/sysctl.conf | grep net.ipv6.conf.all.disable_ipv6").failed == True:
            sudo('echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf')
        else:
            sed("/etc/sysctl.conf", '^net.ipv6.conf.all.disable_ipv6.*', 'net.ipv6.conf.all.disable_ipv6 = 1',use_sudo=True)

    with settings(warn_only=True):
        if sudo("cat /etc/sysctl.conf | grep net.ipv6.conf.default.disable_ipv6").failed == True:
            sudo('echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf')
        else:
            sed("/etc/sysctl.conf", '^net.ipv6.conf.default.disable_ipv6.*', 'net.ipv6.conf.default.disable_ipv6 = 1',use_sudo=True)

    with settings(warn_only=True):
        if sudo("cat /etc/sysconfig/network | grep NETWORKING_IPV6").failed == True:
            sudo('echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network')
        else:
            sed("/etc/sysconfig/network", '^NETWORKING_IPV6=.*', 'NETWORKING_IPV6=no',use_sudo=True)

    with settings(warn_only=True):
        if sudo("cat /etc/sysconfig/network | grep IPV6INIT").failed == True:
            sudo('echo "IPV6INIT=no" >> /etc/sysconfig/network')
        else:
            sed("/etc/sysconfig/network", '^IPV6INIT=.*', 'IPV6INIT=no',use_sudo=True)

    #IP Tables Stopped and Off
    # sudo("systemctl stop firewalld")
    # sudo("systemctl disable firewalld")
    # sudo("systemctl stop ip6tables")
    # sudo("systemctl disable ip6tables")

    #Swappiness
    sudo("sysctl vm.swappiness=0")
    with settings(warn_only=True):
        if sudo("cat /etc/sysctl.conf | grep vm.swappiness").failed == True:
            sudo('echo "vm.swappiness = 0" >> /etc/sysctl.conf')
        else:
            sed("/etc/sysctl.conf","vm.swappiness.*","vm.swappiness = 0",use_sudo=True)

    #Name Service Caching Daemon
    with settings(warn_only=True):
        yum_auto_install("nscd")
        sudo("systemctl start nscd")
        sudo("systemctl enable nscd")

    #SE Linux
    sed("/etc/selinux/config",'^SELINUX=.*','SELINUX=disabled',use_sudo=True)

    #Disable Transparent Huge Pages
    with settings(warn_only=True):
        sudo('echo never > /sys/kernel/mm/redhat_transparent_hugepage/defrag')
        sudo('echo never > /sys/kernel/mm/redhat_transparent_hugepage/enabled')
        if sudo('cat /etc/rc.local | grep "echo never > /sys/kernel/mm/redhat_transparent_hugepage/defrag"').failed == True:
            sudo('echo "echo never > /sys/kernel/mm/redhat_transparent_hugepage/defrag" >> /etc/rc.local')
        if sudo('cat /etc/rc.local | grep "echo never > /sys/kernel/mm/redhat_transparent_hugepage/enabled"').failed == True:
            sudo('echo "echo never > /sys/kernel/mm/redhat_transparent_hugepage/enabled" >> /etc/rc.local')

    #Stop Unnecessary Services
    with settings(warn_only=True):
        sudo("systemctl stop cups")
        sudo("systemctl stop postfix")
        sudo("systemctl stop bluetooth")

    #Reload sysctl
    with settings(warn_only=True):
        sudo("sysctl -p")

    #Install WGET
    yum_auto_install("wget")

    #Install Desired version of Java
    with settings(warn_only=True):
        yum_auto_remove("jre-1.5.0-gcj")
        yum_auto_remove("java-1.6.0-openjdk")
        yum_auto_remove("java-1.7.0-openjdk")
        yum_auto_remove("jdk1.8.0_66")
        sudo("rm jdk-8u66-linux-x64.rpm")
        sudo('wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u66-b14/jdk-8u66-linux-x64.rpm"')
        sudo("yum -y --nogpgcheck localinstall jdk-8u66-linux-x64.rpm")

    #Install CM API Python Extensions
    sudo('curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"')
    sudo("python get-pip.py")
    sudo("pip install cm-api")

    #Mount EBS Volume
    # sudo("mkfs -t ext4 /dev/xvdb")
    # sudo("mkfs -t ext4 /dev/xvdc")
    # sudo("mkdir /data01")
    # sudo("mkdir /data02")
    # sudo("mount -t ext4 /dev/xvdb /data01 -o noatime")
    # sudo("mount -t ext4 /dev/xvdc /data02 -o noatime")
    # sudo("echo '/dev/xvdb /data01 ext4 defaults,noatime 0 0' >> /tmp/fstab")
    # sudo("echo '/dev/xvdc /data02 ext4 defaults,noatime 0 0' >> /tmp/fstab")
    # sudo("sh -c 'cat /tmp/fstab >> /etc/fstab'")


def prepare_mysql():
    #Install MySQL Commponents
    yum_auto_install("mysql")
    yum_auto_install("mysql-server")
    yum_auto_install("mysql-connector-java")

    #MySQL InnoDB Config File
    upload_template("../my.cnf","/etc/my.cnf",use_sudo=True)
    sudo("chmod 644 /etc/my.cnf")

    #Install, Prepare, Configure, and Start MySQL DB
    sudo("mysql_install_db")
    sudo("chown mysql:mysql -R /var/lib/mysql")
    sudo("service mysqld start")
    sudo("/usr/bin/mysql_secure_installation")

    mysql_output = run('mysql -u{} -p{} -N -B -e "SELECT support FROM information_schema.engines WHERE engine = \'InnoDB\'"'.format(env.mysql_user,env.password))
    match = re.search("YES", mysql_output)
    if match:
        print("InnoDB enabled!!")
    else:
        print("InnoDB failed!!")
        abort("Requires InnoDB to be active!!  Re-install MySQL DB!!")

    mysql_cm_auto_create("amon","amon","amon_password")
    mysql_cm_auto_create("rman","rman","rman_password")
    mysql_cm_auto_create("metastore","hive","hive_password")
    mysql_cm_auto_create("sentry","sentry","sentry_password")
    mysql_cm_auto_create("nav","nav","nav_password")
    mysql_cm_auto_create("navms","navms","navms_password")
    mysql_cm_auto_create("oozie","oozie","oozie_password")
    mysql_cm_auto_create("hue","hue","hue_password")


def prepare_mariadb():
    #Install MySQL Commponents
    yum_auto_install("mariadb")
    yum_auto_install("mariadb-server")
    yum_auto_install("mysql-connector-java")

    #MySQL InnoDB Config File
    upload_template("../my.cnf","/etc/my.cnf",use_sudo=True)
    sudo("chmod 644 /etc/my.cnf")

    sudo("touch /var/log/mysqld.log")
    sudo("chown mysql:mysql /var/log/mysqld.log")
    sudo("mkdir /var/run/mysqld")
    sudo("chown mysql:mysql /var/run/mysqld")

    #Install, Prepare, Configure, and Start MySQL DB
    sudo("mysql_install_db")
    sudo("chown mysql:mysql -R /var/lib/mysql")
    sudo("systemctl start mariadb")
    sudo("/usr/bin/mysql_secure_installation")

    mysql_output = run('mysql -u{} -p{} -N -B -e "SELECT support FROM information_schema.engines WHERE engine = \'InnoDB\'"'.format(env.mysql_user,env.password))
    match = re.search("DEFAULT", mysql_output)
    if match:
        print("InnoDB enabled!!")
    else:
        print("InnoDB failed!!")
        abort("Requires InnoDB to be active!!  Re-install MySQL DB!!")

    mysql_cm_auto_create("amon","amon","amon_password")
    mysql_cm_auto_create("rman","rman","rman_password")
    mysql_cm_auto_create("metastore","hive","hive_password")
    mysql_cm_auto_create("sentry","sentry","sentry_password")
    mysql_cm_auto_create("nav","nav","nav_password")
    mysql_cm_auto_create("navms","navms","navms_password")
    mysql_cm_auto_create("oozie","oozie","oozie_password")
    mysql_cm_auto_create("hue","hue","hue_password")


def prepare_rds():
    #Install MySQL Commponents
    yum_auto_install("mysql")
    yum_auto_install("mysql-connector-java")

    rds_cm_auto_create("amon","amon","amon_password")
    rds_cm_auto_create("rman","rman","rman_password")
    rds_cm_auto_create("metastore","hive","hive_password")
    rds_cm_auto_create("sentry","sentry","sentry_password")
    rds_cm_auto_create("nav","nav","nav_password")
    rds_cm_auto_create("navms","navms","navms_password")
    rds_cm_auto_create("oozie","oozie","oozie_password")
    rds_cm_auto_create("hue","hue","hue_password")
    rds_cm_auto_create("smon","smon","smon_password")
    rds_cm_auto_create("hmon","hmon","hmon_password")
    rds_cm_auto_create("scm","scm","scm_password")

    rds_db_drop("scm")

def rds_db_drop(db_name):
    sudo('mysql -h{} -u{} -p{} -e "DROP DATABASE {}"'.format(env.rds_host,env.rds_user,env.password,db_name))

def prepare_cloudera_manager():
    #File Server
    with settings(warn_only=True):
        yum_auto_install("httpd")
        sudo("service httpd start")
        sudo("mkdir /var/www/html/cdh5")

    #Parcel Preparation
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/CDH-{}-1.cdh{}.p0.42-el6.parcel".format(env.cdh_version,env.cdh_version,env.cdh_version))
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/CDH-{}-1.cdh{}.p0.42-el6.parcel.sha1".format(env.cdh_version,env.cdh_version,env.cdh_version))
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/manifest.json".format(env.cdh_version))
    sudo("wget --directory-prefix=/etc/yum.repos.d http://archive.cloudera.com/cm5/redhat/6/x86_64/cm/cloudera-manager.repo")

    #Download Cloudera Parcels from Repo added Above
    yum_auto_install("cloudera-manager-daemons")
    yum_auto_install("cloudera-manager-server")

    mysql_user_auto_create("*",env.mysql_user,env.password)
    sudo("/usr/share/cmf/schema/scm_prepare_database.sh mysql -h{} -u{} -p{} --scm-host {} scm scm scm".format(hostname_fqdn(),env.mysql_user,env.password,hostname_fqdn()))

    sudo("service cloudera-scm-server start")


def prepare_cloudera_manager_rhel7():
    #File Server
    with settings(warn_only=True):
        yum_auto_install("httpd")
        sudo("systemctl start httpd")
        sudo("mkdir /var/www/html/cdh5")

    #Parcel Preparation
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/CDH-{}-1.cdh{}.p0.23-el7.parcel".format(env.cdh_version,env.cdh_version,env.cdh_version))
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/CDH-{}-1.cdh{}.p0.23-el7.parcel.sha1".format(env.cdh_version,env.cdh_version,env.cdh_version))
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/manifest.json".format(env.cdh_version))
    sudo("wget --directory-prefix=/etc/yum.repos.d http://archive.cloudera.com/cm5/redhat/7/x86_64/cm/cloudera-manager.repo")

    #Download Cloudera Parcels from Repo added Above
    yum_auto_install("cloudera-manager-daemons")
    yum_auto_install("cloudera-manager-server")

    mysql_user_auto_create("*",env.mysql_user,env.password)
    sudo("/usr/share/cmf/schema/scm_prepare_database.sh mysql -h{} -u{} -p{} --scm-host {} scm scm scm".format(hostname_fqdn(),env.mysql_user,env.password,hostname_fqdn()))

    sudo("systemctl start cloudera-scm-server")



def prepare_cloudera_manager_rds():
    #File Server
    with settings(warn_only=True):
        yum_auto_install("httpd")
        sudo("service httpd start")
        sudo("mkdir /var/www/html/cdh5")

    #Parcel Preparation
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/CDH-{}-1.cdh{}.p0.42-el6.parcel".format(env.cdh_version,env.cdh_version,env.cdh_version))
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/CDH-{}-1.cdh{}.p0.42-el6.parcel.sha1".format(env.cdh_version,env.cdh_version,env.cdh_version))
    sudo("wget --directory-prefix=/var/www/html/cdh5 http://archive.cloudera.com/cdh5/parcels/{}/manifest.json".format(env.cdh_version))
    sudo("wget --directory-prefix=/etc/yum.repos.d http://archive.cloudera.com/cm5/redhat/6/x86_64/cm/cloudera-manager.repo")

    #Download Cloudera Parcels from Repo added Above
    yum_auto_install("cloudera-manager-daemons")
    yum_auto_install("cloudera-manager-server")

#    mysql_user_auto_create("*",env.mysql_user,env.password)
    sudo("/usr/share/cmf/schema/scm_prepare_database.sh mysql -h{} -u{} -p{} --scm-host {} scm scm scm_password".format(env.rds_host,env.rds_user,env.password,hotname_fqdn()))

    sudo("service cloudera-scm-server start")

def prepare_kerberos():
    #Kerberos Packages
    yum_auto_install("openldap-clients")
    yum_auto_install("krb5-workstation")
    yum_auto_install("krb5-libs")

    #LDAP Certificate
    sudo("mkdir /etc/openldap/cacerts")
    upload_template("~/cacert.cer","/etc/openldap/cacerts/cacert.pem",use_sudo=True)

def auto_prepare_tls():
	hostname = hostname_fqdn()
    sudo("mkdir -p /opt/cloudera/security/x509")
	sudo("mkdir -p /opt/cloudera/security/jks")
	sudo("mkdir -p /opt/cloudera/security/CAcerts")

	# Create Java Keystore
	sudo('keytool -genkeypair -noprompt -keystore /opt/cloudera/security/jks/{}.keystore -keyalg RSA -alias {} -dname "CN={},O=Hadoop" -storepass cloudera -keypass cloudera -validity 90'.format(hostname, hostname, hostname))
	sudo('ln -s /opt/cloudera/security/jks/{}.keystore /opt/cloudera/security/jks/keystore.jks'.format(hostname))

	sudo("cp /usr/java/latest/jre/lib/security/cacerts /usr/java/latest/jre/lib/security/jssecacerts")

	sudo('keytool -export -noprompt -alias {} -keystore /opt/cloudera/security/jks/{}.keystore -rfc -file /opt/cloudera/security/x509/selfsigned.cer -storepass cloudera -keypass cloudera'.format(hostname, hostname))
	sudo('keytool -import -noprompt -alias {} -file /opt/cloudera/security/x509/selfsigned.cer -keystore /usr/java/latest/jre/lib/security/jssecacerts -storepass changeit'.format(hostname))
	sudo('keytool -importcert -noprompt -keystore /opt/cloudera/security/jks/{}.keystore -alias {}.selfsignCA -file /opt/cloudera/security/x509/selfsigned.cer -storepass cloudera'.format(hostname, hostname))
	sudo("mv /opt/cloudera/security/x509/selfsigned.cer /opt/cloudera/security/x509/{}.pem".format(hostname))
	# Only need the symbolic link on Cloudera Manager Server Node.
	sudo('ln -s /opt/cloudera/security/x509/{}.pem /opt/cloudera/security/x509/cmserver.pem'.format(hostname))

	sudo('keytool -importkeystore -noprompt -srckeystore /opt/cloudera/security/jks/{}.keystore -srcalias {} -srcstorepass cloudera -srckeypass cloudera -destkeystore /opt/cloudera/security/x509/{}.p12 -deststoretype PKCS12 -deststorepass cloudera -destkeypass cloudera'.format(hostname, hostname, hostname))
	sudo('openssl pkcs12 -in /opt/cloudera/security/x509/{}.p12 -passin pass:cloudera -nokeys -out /opt/cloudera/security/x509/{}.pem'.format(hostname, hostname))
	sudo('openssl pkcs12 -in /opt/cloudera/security/x509/{}.p12 -passin pass:cloudera -nocerts -out /opt/cloudera/security/x509/{}.key -passout pass:cloudera'.format(hostname, hostname))
	sudo('openssl rsa -in /opt/cloudera/security/x509/{}.key -passin pass:cloudera -out /opt/cloudera/security/x509/{}.passless.pem'.format(hostname, hostname))

	# Level 1
	sudo("sed -e 's/use_tls=[0-9]/use_tls=1/' /etc/cloudera-scm-agent/config.ini > /etc/cloudera-scm-agent/config.ini.tls_level_1")
	sudo("cp /etc/cloudera-scm-agent/config.ini.tls_level_1 /etc/cloudera-scm-agent/config.ini")

	# Level 2
	sudo('sed -e "s/use_tls=[0-9]/use_tls=1/" -e "s/$( grep verify_cert_file= /etc/cloudera-scm-agent/config.ini )/verify_cert_file=\/opt\/cloudera\/security\/x509\/cmserver.pem/" /etc/cloudera-scm-agent/config.ini.tls_level_1 > /etc/cloudera-scm-agent/config.ini.tls_level_2')
	sudo("cp /etc/cloudera-scm-agent/config.ini.tls_level_2 /etc/cloudera-scm-agent/config.ini")

	# Level 3
	sudo('echo "cloudera" > /etc/cloudera-scm-agent/agentkey.pw')
	sudo('ln -s /opt/cloudera/security/x509/{}.pem /opt/cloudera/security/x509/cmagent.pem'.format(hostname))
	sudo('ln -s /opt/cloudera/security/x509/{}.key /opt/cloudera/security/x509/cmagent.key'.format(hostname))
	sudo('sed -e "s/$( grep client_key_file= /etc/cloudera-scm-agent/config.ini )/client_key_file=\/opt\/cloudera\/security\/x509\/cmagent.key/" -e "s/$( grep client_keypw_file= /etc/cloudera-scm-agent/config.ini )/client_keypw_file=\/etc\/cloudera-scm-agent\/agentkey.pw/" -e "s/$( grep client_cert_file= /etc/cloudera-scm-agent/config.ini )/client_cert_file=\/opt\/cloudera\/security\/x509\/cmagent.pem/" /etc/cloudera-scm-agent/config.ini > /etc/cloudera-scm-agent/config.ini.tls_level_3')
	sudo("cp /etc/cloudera-scm-agent/config.ini.tls_level_3 /etc/cloudera-scm-agent/config.ini")

    # Extract the CA Certificate Chain.
    sudo("echo -n | openssl s_client -connect {}:636 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /opt/cloudera/security/CACerts/ad-ca.cert".format(env.ldap_url))


def auto_prepare_truststore():
    file_upload("~/aws-key.pem", "/home/ec2-user/aws-key.pem")
    chmod("/home/ec2-user/aws-key.pem","600")
    run("for NODE in {}; do ssh -i /home/ec2-user/aws-key.pem $NODE 'hostname'; done;".format(env.ips))






def yum_auto_install(package="openssh-server"):
    with settings(warn_only=True):
        sudo("yum install -y {}".format(package))

def yum_auto_remove(package):
    with settings(warn_only=True):
        sudo("yum remove -y {}".format(package))

def mysql_cm_auto_create(db_name,user_name,pass_wd):
    mysql_db_auto_create(db_name)
    mysql_user_auto_create(db_name,user_name,pass_wd)

def mysql_db_auto_create(db_name):
    run('mysql -u{} -p{} -e "CREATE DATABASE {} DEFAULT CHARACTER SET utf8;"'.format(env.mysql_user,env.password,db_name))

def mysql_user_auto_create(db_name,user_name,pass_wd):
    run('mysql -u{} -p{} -e "GRANT ALL ON {}.* TO \'{}\'@\'%\' IDENTIFIED BY \'{}\' WITH GRANT OPTION;"'.format(env.mysql_user,env.password,db_name,user_name,pass_wd))

def rds_cm_auto_create(db_name,user_name,pass_wd):
    rds_db_auto_create(db_name)
    rds_user_auto_create(db_name,user_name,pass_wd)

def rds_db_auto_create(db_name):
    run('mysql -h {} -u{} -p{} -e "CREATE DATABASE {} DEFAULT CHARACTER SET utf8;"'.format(env.rds_host,env.rds_user,env.password,db_name))

def rds_user_auto_create(db_name,user_name,pass_wd):
    run('mysql -h {} -u{} -p{} -e "GRANT ALL ON {}.* TO \'{}\'@\'%\' IDENTIFIED BY \'{}\' WITH GRANT OPTION;"'.format(env.rds_host,env.rds_user,env.password,db_name,user_name,pass_wd))









def env_print():
    print(env);

def hostname_fqdn():
    host = run("hostname -f")
    return host

def hostname_short():
    host = run("hostname -f | awk -F'.' '{print $1}'")
    return host

def hostname_ip():
    host = run("hostname -f | awk -F'.' '{print $1}' | sed -e 's/-/./g' -e 's/ip.//'")
    return host

def hello():
    print("Hello world!")

def host_type():
    run('uname -s')

def uptime():
    run("uptime")

def yum_install(package="openssh-server"):
    with settings(warn_only=True):
        if run("yum list installed {}".format(package)).failed:
            if confirm("Install {} via yum install?".format(package), default=False) == True:
                if sudo("yum install {}".format(package), pty=True).failed:
                    print("{} unsuccessfully installed!".format(package))
                else:
                    print("{} successfully installed!".format(package))
            else:
                print("{} not installed!".format(package))
        else:
            print("{} already Exists!".format(package))

def yum_remove(package):
    with settings(warn_only=True):
        if sudo("yum list installed {}".format(package)).failed:
            print("{} already uninstalled!".format(package))
        else:
            if confirm("UnInstall {} via yum remove?".format(package), default=False) == True:
                if sudo("yum remove {}".format(package), pty=True).failed:
                    print("{} unsuccessfully removed!".format(package))
                else:
                    print("{} successfully removed!".format(package))
            else:
                print("{} not removed!".format(package))

def ip_tables():
    sudo("service iptables stop")
    sudo("service ip6tables stop")

def ntp():
    yum_install("ntp")
    yum_install("ntpdate")
    yum_install("ntp-doc")
    if confirm("Do ntp ntpdate and ntp-doc already exist?", default=False) == False:
        sudo("chkconfig ntpd on")
        sudo("ntpdate pool.ntp.org")
        sudo("service ntpd start")
    else:
        print("ntp is already installed and running!")

def max_open_files():
    if confirm("Change number of open files for hdfs, mapred, and hbase on {}?".format(env.host_string), default=False) == True:
        sudo('echo "hdfs - nofile 32768" >> /etc/security/limits.conf')
        sudo('echo "mapred - nofile 32768" >> /etc/security/limits.conf')
        sudo('echo "hbase - nofile 32768" >> /etc/security/limits.conf')

        sudo('echo "hdfs - noproc 32768" >> /etc/security/limits.conf')
        sudo('echo "mapred - noproc 32768" >> /etc/security/limits.conf')
        sudo('echo "hbase - noproc 32768" >> /etc/security/limits.conf')
    else:
        print("Number of open files/processes not changed on {}".format(env.host_string))

def swappiness():
    if confirm("Check swappiness on {}?".format(env.host_string), default=False) == True:
        if sudo("sysctl vm.swappiness").failed:
            print("Upload of /etc/my.cnf failed!")
        else:
            if confirm("Change swappiness to 0?", default=False) == True:
                sudo("sysctl vm.swappiness=0")
                sudo("cat /etc/sysctl.conf")
                if confirm("Add vm.swappiness to sysctl.conf file?", default=False) == True:
                    sudo('echo "vm.swappiness = 0" >> /etc/sysctl.conf')
                else:
                    replace("/etc/sysctl.conf","vm.swappiness.*","vm.swappiness = 0")
                print("Swappiness changed on {}.".format(env.host_string))
            else:
                print("Swappiness will not be changed.")
    else:
        print("Swappiness not changed on {}".format(env.host_string))

def selinux():
    if exists("/etc/selinux/config"):
        run("cat /etc/selinux/config")
        if confirm("Disable SELinux on {}?".format(env.host_string), default=False) == True:
            replace("/etc/selinux/config","SELINUX.*","SELINUX=disabled")
    else:
        print("SELinux file doesn't exist on: {}".format(env.host_string))

def my_cnf():
    if confirm("Move my.cnf file to " + env.host_string, default=False) == True:
        if upload_template("../my.cnf","/etc/my.cnf",use_sudo=True).failed:
            print("Upload of /etc/my.cnf failed!")
        else:
            print("Upload of /etc/my.cnf success!")
    else:
        print("File not moved to " + env.host_string + "!")

def file_upload(file_name,target_path):
    if confirm("Move {} file to {} @ {}?".format(file_name,env.host_string,target_path), default=False) == True:
        if upload_template(file_name,target_path).failed:
            print("Upload of {} failed!".format(file_name))
        else:
            print("Upload of {} success!".format(file_name))
    else:
        print("File not moved to {}!".format(env.host_string))

def chmod(file_name, modes):
    if exists(file_name):
        if confirm("Change mode of " + file_name + " to " + modes + "?", default=False) == True:
            if sudo("chmod " + modes + " " + file_name).failed:
                print("Change Mode Failed!")
            else:
                print("Change Mode Success!")
        else:
            print(file_name + " mode not changed!")
    else:
        print(file_name + " doesn't exist on: " + env.host_string)

def chown(dir_name, owner):
    if exists(dir_name):
        if confirm("Change ownership of " + dir_name + " to " + owner + "?", default=False) == True:
            if sudo("chown -R " + owner + ":" + owner + " " + dir_name).failed:
                print("Change Owner to " + owner + " Failed!")
            else:
                print("Change Owner to " + owner + " Success!")
        else:
            print(dir_name + " owner not changed!")
    else:
        print(dir_name + " doesn't exist on: " + env.host_string)

def chown(dir_name, owner, group):
    if exists(dir_name):
        if confirm("Change ownership of " + dir_name + " to " + owner + ":" + group + " ?", default=False) == True:
            if sudo("chown -R " + owner + ":" + group + " " + dir_name).failed:
                print("Change Owner to " + owner + " Failed!")
            else:
                print("Change Owner to " + owner + " Success!")
        else:
            print(dir_name + " owner not changed!")
    else:
        print(dir_name + " doesn't exist on: " + env.host_string)

def mkdir(dir_name):
    if exists(dir_name):
        print(dir_name + " already exist on: " + env.host_string)
    else:
        if confirm("Create directory " + dir_name + " ?", default=False) == True:
            if sudo("mkdir " + dir_name).failed:
                print("Directory creation of " + dir_name + " Failed!")
            else:
                print("Directory creation of " + dir_name + " Success!")
        else:
            print(dir_name + " directory not created!")

def rm_dir(dir_name):
    if exists(dir_name):
        if confirm("Permanently Remove " + dir_name + " on " + env.host_string + "?", default=False) == True:
            if sudo("rm -r " + dir_name).failed:
                print("Removal of " + dir_name + " Failed!")
            else:
                print("Removal of " + dir_name + " Success!")
        else:
            print(dir_name + " directory not removed!")
    else:
        print(dir_name + " doesn't exist on: " + env.host_string)

def rm_file(file_name):
    if exists(file_name):
        if confirm("Permanently Remove " + file_name + " on " + env.host_string + "?", default=False) == True:
            if sudo("rm " + file_name).failed:
                print("Removal of " + file_name + " Failed!")
            else:
                print("Removal of " + file_name + " Success!")
        else:
            print(file_name + " file not removed!")
    else:
        print(file_name + " doesn't exist on: " + env.host_string)

def cp_file(file_name,target_name):
    if exists(file_name):
        if confirm("Copy {} on {} to {}?".format(file_name,env.host_string,target_name), default=False) == True:
            if sudo("cp {} {}".format(file_name,target_name)).failed:
                print("Copy of {} Failed!".format(file_name))
            else:
                print("Copy of {} to {} Success!".format(file_name, target_name))
        else:
            print("{} file not copied!".format(file_name))
    else:
        print("{} doesn't exist on: {}".format(file_name,env.host_string))

def replace(file_name,orig_string,new_string):
    if exists(file_name):
        if confirm("Search {} for {} and replace with {}?".format(file_name,orig_string,new_string), default=False) == True:
            if sudo("sed -i.bak$(date +'%s') \'s/{}/{}/g\' {}".format(orig_string,new_string,file_name)).failed:
                print("Replace of " + file_name + " Failed!")
            else:
                print("Replace of " + file_name + " Success!")
        else:
            print(file_name + " file not replaced!")
    else:
        print(file_name + " doesn't exist on: " + env.host_string)

def append(file_name,match_string,append_string):
    if exists(file_name):
        if confirm("Search {} for {} and append a new line with {}?".format(file_name,match_string,append_string), default=False) == True:
            if sudo("sed -i.bak$(date +'%s') \'/{}/a {}\' {}".format(match_string,append_string,file_name)).failed:
                print("Append of {} Failed!".format(file_name))
            else:
                print("Append of {} Success!".format(file_name))
        else:
            print("{} file not appended!".format(file_name))
    else:
        print("{} doesn't exist on: {}".format(file_name,env.host_string))

def unzip(file_name,target_path):
    if exists(file_name):
        if confirm("Unzip {} into {}?".format(file_name,target_path), default=False) == True:
            if sudo("unzip {} -d {}".format(file_name,target_path)).failed:
                print("Unzip of {} Failed!".format(file_name))
            else:
                print("Unzip of {} into {} Success!".format(file_name,target_path))
        else:
            print("Nothing to unzip based on response!")
    else:
            print("{} doesn't exist on: {}".format(file_name,env.host_string))

def mysql_install():
    if confirm("Install MySQL server on: " + env.host_string, default=False) == True:
        if sudo("mysql_install_db").failed:
            print("MySQL install failed!")
        else:
            print("MySQL install success!")
    else:
        print("MySQL install not started on: " + env.host_string + "!")

def mysql_start():
    with settings(warn_only=True):
        if confirm("Start MySQL server on: " + env.host_string, default=False) == True:
            if sudo("service mysqld start").failed:
                print("MySQL server failed to start!")
                chown("/var/lib/mysql","mysql")
                mysql_start()
            else:
                print("MySQL server started successfully!")
        else:
            print("MySQL server not started on: " + env.host_string + "!")

def mysql_stop():
    with settings(warn_only=True):
        if confirm("Stopping MySQL server on: " + env.host_string, default=False) == True:
            if sudo("service mysqld stop").failed:
                print("MySQL server failed to stop!")
            else:
                print("MySQL server stopped successfully!")
        else:
            print("MySQL server not stopped on: " + env.host_string + "!")

def mariadb_stop():
    with settings(warn_only=True):
        if confirm("Stopping MariaDB server on: " + env.host_string, default=False) == True:
            if sudo("systemctl stop mariadb").failed:
                print("MariaDB server failed to stop!")
            else:
                print("MariaDB server stopped successfully!")
        else:
            print("MariaDB server not stopped on: " + env.host_string + "!")

def mysql_secure():
    if confirm("Run MySQL secure script on: " + env.host_string, default=False) == True:
        if sudo("/usr/bin/mysql_secure_installation").failed:
            print("MySQL secure script failed!")
        else:
            print("MySQL secure script success!")
    else:
        print("MySQL secure script not started on: " + env.host_string + "!")

def innodb_check():
    mysql_output = run('mysql -u {} -p {} -N -B -e "SELECT support FROM information_schema.engines WHERE engine = \'InnoDB\'"'.format(env.user,env.password))
    match = re.search("YES", mysql_output)
    if match:
        print("InnoDB enabled!!")
    else:
        print("InnoDB failed!!")
        abort("Requires InnoDB to be active!!  Re-install MySQL DB!!")

def mysql_cm_create(db_name,user_name,pass_wd):
    mysql_db_create(db_name)
    mysql_user_create(db_name,user_name,pass_wd)

def mysql_db_create(db_name):
    if confirm("Create MySQL DB: " + db_name + " ?", default=False) == True:
        run('mysql -u root -p -e "CREATE DATABASE {} DEFAULT CHARACTER SET utf8;"'.format(db_name))

def mysql_user_create(db_name,user_name,pass_wd):
    if confirm("Grant Access on " + db_name + " to " + user_name + " ?", default=False) == True:
        run('mysql -u root -p -e "GRANT ALL ON {}.* TO \'{}\'@\'%\' IDENTIFIED BY \'{}\' WITH GRANT OPTION;"'.format(db_name,user_name,pass_wd))

def mysql_user_remove(user_name):
    if confirm("Remove MySQL user " + user_name + " ?", default=False) == True:
        run('mysql -u root -p -e "DROP USER \'{}\'@\'%\';"'.format(user_name))

def cm_prepare_db(ip_adr,user_name,pass_wd):
    if confirm("Prepare MySQL database for Cloudera Manager Server on: " + ip_adr + " ?", default=False) == True:
        sudo("/usr/share/cmf/schema/scm_prepare_database.sh mysql -h {} -u{} -p{} --scm-host {} scm scm scm".format(ip_adr,user_name,pass_wd,ip_adr))

def install_mysql():
    yum_install("mysql")            #Install MySQL on Nodes Past as variables in script call.
    yum_install("mysql-server")     #Install MySQL Server on Nodes Past as variables in script call.
    yum_install("mysql-connector-java")     #Install MySQL Java JDBC connector on the Nodes past as variables.
    my_cnf()                        #Copy my.cnf text file for InnoDB config to remote server(s).
    chmod("/etc/my.cnf","644")      #Change mode of my.cnf to mysql user to 644.
    mysql_install()                 #Install the MySQL instance with the new my.cnf file.
    mysql_start()                   #Start the MySQL instance with the new my.cnf file.
    mysql_secure()                  #Running the secure script to set root password and remove unwanted settings.
    innodb_check()                  #Checking that InnoDB enging is running on the newly installed MySQL server.
    mysql_cm_create("amon","amon","amon_password")
    mysql_cm_create("rman","rman","rman_password")
    mysql_cm_create("metastore","hive","hive_password")
    mysql_cm_create("sentry","sentry","sentry_password")
    mysql_cm_create("nav","nav","nav_password")
    mysql_cm_create("navms","navms","navms_password")
    mysql_cm_create("oozie","oozie","oozie_password")
    mysql_cm_create("hue","hue","hue_password")

def uninstall_mysql():
    mysql_stop()                    #Stop the running MySQL instance.
    yum_remove("mysql")             #Remove MySQL on Nodes Past as variables in script call.
#    yum_remove("mysql-server")      #Remove MySQL Server on Nodes Past as variables in script call.
    yum_remove("mysql-connector-java")     #Remove MySQL Java JDBC connector on the Nodes past as variables.
    rm_dir("/var/lib/mysql")        #Removing system files in preparation for a fresh build.

def uninstall_mariadb():
    mariadb_stop()                  #Stop the running MySQL instance.
    yum_remove("mariadb")           #Remove MySQL on Nodes Past as variables in script call.
    rm_dir("/var/lib/mysql")        #Removing system files in preparation for a fresh build.

def service_start(service_name):
    with settings(warn_only=True):
        if confirm("Start service " + service_name + " on server: " + env.host_string, default=False) == True:
            if sudo("service {} start".format(service_name)).failed:
                print(service_name + " failed to start!")
            else:
                print(service_name + " started successfully!")
        else:
            print(service_name + " service not started on: " + env.host_string + "!")

def service_stop(service_name):
    with settings(warn_only=True):
        if confirm("Stop service " + service_name + " on server: " + env.host_string, default=False) == True:
            if sudo("service {} stop".format(service_name)).failed:
                print(service_name + " failed to stop!")
            else:
                print(service_name + " stoped successfully!")
        else:
            print(service_name + " service not stoped on: " + env.host_string + "!")

def wget(source_path,target_path):
    if confirm("WGET file " + source_path + " into: " + target_path, default=False) == True:
        if sudo("wget {} -P {}".format(source_path,target_path)).failed:
            print(source_path + " failed to retrieve!")
        else:
            print(source_path + " successfully retrieved!")
    else:
        print(source_path + " not started on: " + env.host_string + "!")

def install_repo():
    yum_install("wget")             #Installing wget to get CM repositories
    yum_install("httpd")            #Installing the web server for repo's
    service_start("httpd")          #Starting the web server for repo's

    mkdir("/var/www/html/cdh5")     #Creating repo directory for CDH 5
    wget("http://archive.cloudera.com/cdh5/parcels/5.4.7/CDH-5.4.7-1.cdh5.4.7.p0.3-el6.parcel","/var/www/html/cdh5")   #Getting CDH parcels from cloudera.com archive
    wget("http://archive.cloudera.com/cdh5/parcels/5.4.7/CDH-5.4.7-1.cdh5.4.7.p0.3-el6.parcel.sha1","/var/www/html/cdh5")   #Getting CDH parcels from cloudera.com archive
    wget("http://archive.cloudera.com/cdh5/parcels/5.4.7/manifest.json","/var/www/html/cdh5")   #Getting CDH parcels from cloudera.com archive

#    mkdir("/var/www/html/gplextras")     #Creating repo directory for GPLextras
#    wget("http://archive.cloudera.com/gplextras/parcels/latest/HADOOP_LZO-0.4.15-1.gplextras.p0.123-el6.parcel","/var/www/html/gplextras")   #Getting GPLextras parcels from cloudera.com archive
#    wget("http://archive.cloudera.com/gplextras/parcels/latest/manifest.json","/var/www/html/gplextras")   #Getting GPLextras parcels from cloudera.com archive

def uninstall_repo():
    service_stop("httpd")           #Stoping the web server for repo's
    yum_remove("wget")              #Removing wget to get CM repositories
    rm_dir("/var/www/html/cdh5")         #Removing repo directory for CDH 5
    rm_dir("/var/www/html/accumulo")     #Removing repo directory for Accumulo
    rm_dir("/var/www/html/gplextras")    #Removing repo directory for GPLextras
    rm_dir("/var/www/html/sqoop")        #Removing repo directory for Sqoop

def install_cm():
    wget("http://archive.cloudera.com/cm5/redhat/6/x86_64/cm/cloudera-manager.repo","/etc/yum.repos.d/")

    yum_install("oracle-j2sdk1.7")                     #Installing oracle-j2sdk1.7 for CM
    yum_install("cloudera-manager-daemons")            #Installing CM Daemons
    yum_install("cloudera-manager-server")             #Installing CM Server

    mysql_user_create("*","temp","temp")               #Create temp MySQL user to run CM prepare DB script.
    cm_prepare_db("{}".format(env.host_string),"temp","temp")      #Passing parameters to the CM prepare DB script.
    mysql_user_remove("temp")                          #Remove temp MySQL user from DB.

    service_start("cloudera-scm-server")               #Start the Cloudera Manager Server.

def uninstall_cm():
    service_stop("cloudera-scm-server")                #Stopping the CM server.

    yum_remove("oracle-j2sdk1.7")                      #Removing oracle-j2sdk1.7 for CM.
    yum_remove("cloudera-manager-daemons")             #Removing CM Daemons.
    yum_remove("cloudera-manager-server")              #Removing CM Server.

    rm_file("/etc/yum.repos.d/cloudera-manager.repo")  #Removing the repo file from the yum repository.

def kerb_db_install():
    if confirm("Create Database for Kerberos on: {}".format(env.host_string), default=False) == True:
        if sudo("/usr/sbin/kdb5_util create -s").failed:
            print("Kerberos DB install failed!")
        else:
            print("Kerberos DB install success!")
    else:
        print("Kerberos DB install not started on: {}!".format(env.host_string))

def first_principal(admin_acct):
    if confirm("Create first principal {} on: {}".format(admin_acct,env.host_string), default=False) == True:
        if sudo('/usr/sbin/kadmin.local -q "addprinc {}/admin"'.format(admin_acct)).failed:
            print("Kerberos first principal creation failed!")
        else:
            print("Kerberos first principal creation success!")
    else:
        print("Kerberos first principal install not started on: {}!".format(env.host_string))

def start_kerberos():
    if confirm("Start kerberos agents on: {}?".format(env.host_string), default=False) == True:
        service_start("krb5kdc")
        service_start("kadmin")
    else:
        print("Kerberos agents will not started on: {}!".format(env.host_string))

def stop_kerberos():
    if confirm("Stop kerberos agents on: {}?".format(env.host_string), default=False) == True:
        service_stop("krb5kdc")
        service_stop("kadmin")
    else:
        print("Kerberos agents will not stopped on: {}!".format(env.host_string))

def install_kerberos():
    if confirm("Install Kerberos Server on {}?".format(env.host_string), default=False) == True:
        yum_install("krb5-workstation")                #Installing krb5-workstation for Kerberos Client
        yum_install("krb5-server")                         #Installing krb5-server for Kerberos Authentication
        yum_install("krb5-libs")                           #Installing krb5-libs for Kerberos Authentication
        yum_install("krb5-auth-dialog")                    #Installing krb5-auth-dialog for Kerberos Authentication
        yum_install("openldap-clients")                    #Installing openldap-clients for Kerberos and AD (active directory)

        replace("/etc/krb5.conf","EXAMPLE.COM","EXAMPLE.COM.")
        replace("/etc/krb5.conf","kerberos.example.com","{}".format(env.host_string))
        replace("/etc/krb5.conf","example.com","example.com")

        mkdir("/root/jce")     #Creating jce directory for CDH 5
        file_upload("~/UnlimitedJCEPolicyJDK7.zip","/root/jce/UnlimitedJCEPolicyJDK7.zip")
        unzip("/root/jce/UnlimitedJCEPolicyJDK7.zip","/root/jce")
        cp_file("/usr/java/jdk1.7.0_67-cloudera/jre/lib/security/local_policy.jar","/usr/java/jdk1.7.0_67-cloudera/jre/lib/security/local_policy.jar.orig")
        cp_file("/usr/java/jdk1.7.0_67-cloudera/jre/lib/security/US_export_policy.jar","/usr/java/jdk1.7.0_67-cloudera/jre/lib/security/US_export_policy.jar.orig")
        cp_file("/root/jce/UnlimitedJCEPolicy/local_policy.jar","/usr/java/jdk1.7.0_67-cloudera/jre/lib/security/local_policy.jar")
        cp_file("/root/jce/UnlimitedJCEPolicy/US_export_policy.jar","/usr/java/jdk1.7.0_67-cloudera/jre/lib/security/US_export_policy.jar")

        replace("/var/kerberos/krb5kdc/kdc.conf","EXAMPLE.COM","EXAMPLE.COM")

        kerb_db_install()

        first_principal("krb_admin")

        replace("/var/kerberos/krb5kdc/kadm5.acl","EXAMPLE.COM","EXAMPLE.COM")

        replace("/var/kerberos/krb5kdc/kdc.conf","EXAMPLE.COM","EXAMPLE.COM")
        append("/var/kerberos/krb5kdc/kdc.conf","dict_file","max_file = 1d")
        append("/var/kerberos/krb5kdc/kdc.conf","dict_file","max_renewable_life = 7d")
        append("/var/kerberos/krb5kdc/kdc.conf","supported_enctypes","default_principal_flags = +renewable, +forwardable")

        start_kerberos()
    else:
        if confirm("Install Kerberos Client on {}?".format(env.host_string), default=False) == True:
            yum_install("krb5-workstation")                #Installing krb5-workstation for Kerberos Client
            yum_install("krb5-libs")                       #Installing krb5-libs for Kerberos Authentication
            yum_install("krb5-auth-dialog")                #Installing krb5-auth-dialog for Kerberos Client
            yum_install("openldap-clients")                #Installing openldap-clients for Kerberos and AD (active directory)
        else:
            print("Nothing for Kerberos installed.")

def uninstall_kerberos():
    stop_kerberos()
    yum_remove("krb5-server")                      #Removing krb5-server for CM.
    yum_remove("krb5-libs")                        #Removing krb5-libs for Kerberos Authentication for CM
    yum_remove("krb5-auth-dialog")                 #Removing krb5-auth-dialog for Kerberos Authentication.
    yum_remove("krb5-workstation")                 #Removing krb5-workstation.
    yum_remove("openldap-clients")                 #Removing open ldap.


def cdh5_main():
    ntp()
    ip_tables()
    swappiness()
    selinux()
    max_open_files()
    service_start("rpcbind")                           #Start the RPCBind service to allow for NFS Gateway.

    if confirm("Installing MySQL server for Cloudera Manager?", default=False) == True:
        install_mysql()
    else:
        if confirm("Uninstall MySQL server and settings?", default=False) == True:
            uninstall_mysql()
        else:
            print("Nothing for MySQL required, moving on to Repository creation.")

    if confirm("Installing Repo server for Cloudera Manager?", default=False) == True:
        install_repo()
    else:
        if confirm("Uninstall Repo server and settings?", default=False) == True:
            uninstall_repo()
        else:
            print("Nothing for Repo required, moving on to Cloudera Manager installation.")

    if confirm("Install Cloudera Manager?", default=False) == True:
        install_cm()
    else:
        if confirm("Uninstall Cloudera Manager?", default=False) == True:
            uninstall_cm()
        else:
            print("Nothing for Cloudera Manager required, moving on to Kerberos step.")

    if confirm("Start Installation of Kerberos on {}?".format(env.host_string), default=False) == True:
        install_kerberos()
    else:
        if confirm("Uninstall of Kerberos on {}?".format(env.host_string), default=False) == True:
            uninstall_kerberos()
        else:
            print("Nothing for Kerberos required, moving on to disconnection step.")

    disconnect_all()
