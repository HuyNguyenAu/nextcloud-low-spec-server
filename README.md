# Nextcloud Low Spec Server

This is my personal setup notes to install Nextcloud and OnlyOffice Document Server together on the same server.

## Vultr High Frequency Compute:
Pricing: $6 USD per month    
Storage SSD: 32GB  
CPU: 1  
RAM: 1024 MB  
Bandwith: 1 TB  
Geekbench Score: 4883

## Sources:
https://www.marksei.com/how-to-install-nextcloud-18-on-ubuntu/
https://www.howtoforge.com/tutorial/ubuntu-nginx-nextcloud/
https://docs.nextcloud.com/server/stable/admin_manual/installation/example_ubuntu.html
https://docs.nextcloud.com/server/stable/admin_manual/installation/source_installation.html
https://docs.nextcloud.com/server/18/admin_manual/configuration_server/caching_configuration.html


## Update Server:
`sudo apt update && sudo apt upgrade`

## Install Required Dependencies:
sudo apt-get install apache2 mariadb-server libapache2-mod-php7.2 php7.2-mysql php7.2-fpm
sudo apt-get install php7.2-gd php7.2-json php7.2-mysql php7.2-curl php7.2-mbstring
sudo apt-get install php7.2-intl php-imagick php7.2-xml php7.2-zip

## Download Nextcloud Package:
wget https://download.nextcloud.com/server/releases/nextcloud-18.0.1.tar.bz2
tar -xvjf nextcloud-18.0.1.tar.bz2

sudo mv nextcloud/ /var/www/

groups
sudo chown www-data:www-data nextcloud/
sudo chown -R www-data:www-data nextcloud/*
sudo chown -R www-data:www-data nextcloud/.htaccess
sudo chown -R www-data:www-data nextcloud/.user.ini
ls -al /var/www/nextcloud

sudo mysql_secure_installation
sudo mysql -u root -p

CREATE DATABASE nextcloud;
CREATE USER 'user'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON nextcloud.* TO 'user'@'localhost';
FLUSH PRIVILEGES;

sudo touch /etc/apache2/sites-available/nextcloud.conf
sudo nano /etc/apache2/sites-available/nextcloud.conf

<VirtualHost 127.0.0.1:8080>
  DocumentRoot /var/www/nextcloud/
  ServerName cloud.example.com

  <Directory /var/www/nextcloud/>
    Require all granted
    AllowOverride All
    Options FollowSymLinks MultiViews

    <IfModule mod_dav.c>
      Dav off
    </IfModule>

    SetEnv HOME /var/www/nextcloud
    SetEnv HTTP_HOME /var/www/nextcloud
  </Directory>

  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log common
</VirtualHost>

sudo a2ensite nextcloud
sudo a2dissite 000-default
sudo a2enmod rewrite headers env dir mime
sudo systemctl enable apache2
sudo systemctl restart apache2

sudo nano /etc/php/7.2/fpm/php.ini

date.timezone = Australia/Melbourne

sudo nano /etc/php/7.2/cli/php.ini

cgi.fix_pathinfo=0

sudo nano /etc/php/7.2/fpm/pool.d/www.conf

env[HOSTNAME] = $HOSTNAME
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp

sudo systemctl restart php7.2-fpm
netstat -tap

sudo apt install certbot
sudo certbot -d cloud.example.com --manual --preferred-challenges dns certonly

sudo nano /etc/apache2/ports.conf

# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 8080

#<IfModule ssl_module>
#        Listen 443
#</IfModule>

#<IfModule mod_gnutls.c>
#        Listen 443
#</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

sudo systemctl restart apache2

sudo apt install nginx
sudo unlink /etc/nginx/sites-enabled/default
sudo touch /etc/nginx/sites-available/reverse-proxy.conf
sudo nano /etc/nginx/sites-available/reverse-proxy.conf

upstream php-handler {
    server unix:/var/run/php/php7.2-fpm.sock;
}

server {
    listen 80;
    listen [::]:80;
    server_name cloud.example.com;
    # enforce https
    return 301 https://$server_name:443$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name cloud.example.com;

    # Use Mozilla's guidelines for SSL/TLS settings
    # https://mozilla.github.io/server-side-tls/ssl-config-generator/
    # NOTE: some settings below might be redundant
    ssl_certificate /etc/letsencrypt/live/cloud.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloud.example.com/privkey.pem;

    # Add headers to serve security related headers
    # Before enabling Strict-Transport-Security headers please read into this
    # topic first.
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;" always;
    #
    # WARNING: Only add the preload option once you read about
    # the consequences in https://hstspreload.org/. This option
    # will add the domain to a hardcoded list that is shipped
    # in all major browsers and getting removed from this list
    # could take several months.
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Download-Options "noopen" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Permitted-Cross-Domain-Policies "none" always;
    add_header X-Robots-Tag "none" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Remove X-Powered-By, which is an information leak
    fastcgi_hide_header X-Powered-By;

    # Path to the root of your installation
    root /var/www/nextcloud;

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # The following 2 rules are only needed for the user_webfinger app.
    # Uncomment it if you're planning to use this app.
    #rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
    #rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json last;

    # The following rule is only needed for the Social app.
    # Uncomment it if you're planning to use this app.
    #rewrite ^/.well-known/webfinger /public.php?service=webfinger last;

    location = /.well-known/carddav {
      return 301 $scheme://$host:$server_port/remote.php/dav;
    }
    location = /.well-known/caldav {
      return 301 $scheme://$host:$server_port/remote.php/dav;
    }

    # set max upload size
    client_max_body_size 512M;
    fastcgi_buffers 64 4K;

    # Enable gzip but do not remove ETag headers
    gzip on;
    gzip_vary on;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
    gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

    # Uncomment if your server is build with the ngx_pagespeed module
    # This module is currently not supported.
    #pagespeed off;

    location / {
        rewrite ^ /index.php;
    }

    location ~ ^\/(?:build|tests|config|lib|3rdparty|templates|data)\/ {
        deny all;
    }
    location ~ ^\/(?:\.|autotest|occ|issue|indie|db_|console) {
        deny all;
    }

    location ~ ^\/(?:index|remote|public|cron|core\/ajax\/update|status|ocs\/v[12]|updater\/.+|oc[ms]-provider\/.+)\.php(?:$|\/) {
        fastcgi_split_path_info ^(.+?\.php)(\/.*|)$;
        set $path_info $fastcgi_path_info;
        try_files $fastcgi_script_name =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_param HTTPS on;
        # Avoid sending the security headers twice
        fastcgi_param modHeadersAvailable true;
        # Enable pretty urls
        fastcgi_param front_controller_active true;
        fastcgi_pass php-handler;
        fastcgi_intercept_errors on;
        fastcgi_request_buffering off;
    }

    location ~ ^\/(?:updater|oc[ms]-provider)(?:$|\/) {
        try_files $uri/ =404;
        index index.php;
    }

    # Adding the cache control header for js, css and map files
    # Make sure it is BELOW the PHP block
    location ~ \.(?:css|js|woff2?|svg|gif|map)$ {
        try_files $uri /index.php$request_uri;
        add_header Cache-Control "public, max-age=15778463";
        # Add headers to serve security related headers (It is intended to
        # have those duplicated to the ones above)
        # Before enabling Strict-Transport-Security headers please read into
        # this topic first.
        add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;" always;
        #
        # WARNING: Only add the preload option once you read about
        # the consequences in https://hstspreload.org/. This option
        # will add the domain to a hardcoded list that is shipped
        # in all major browsers and getting removed from this list
        # could take several months.
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Download-Options "noopen" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Permitted-Cross-Domain-Policies "none" always;
        add_header X-Robots-Tag "none" always;
        add_header X-XSS-Protection "1; mode=block" always;

        # Optional: Don't log access to assets
        access_log off;
    }

    location ~ \.(?:png|html|ttf|ico|jpg|jpeg|bcmap)$ {
        try_files $uri /index.php$request_uri;
        # Optional: Don't log access to other assets
        access_log off;
    }
}

sudo ln -s /etc/nginx/sites-available/reverse-proxy.conf /etc/nginx/sites-enabled/reverse-proxy.conf
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx

netstat -tap

sudo apt install redis-server php-redis
sudo nano /var/www/nextcloud/config/config.php

'log_type' => 'file',
'logfile' => '/var/log/nextcloud.log',
'logfilemode' => '0640',
'loglevel' => '0',
'logdateformat' => 'F d, Y H:i:s',
'memcache.locking' => '\OC\Memcache\Redis',
'memcache.distributed' => '\OC\Memcache\Redis',
'memcache.local' => '\OC\Memcache\Redis',
  'redis' => [
     'host' => '127.0.0.1',
      'port' => '6379',
      'timeout' => '3',
    ],

sudo chown www-data:www-data /var/lib/php/sessions/
sudo systemctl restart apache2

sudo ufw allow 'OpenSSH'
sudo ufw allow 'HTTP'
sudo ufw allow 'HTTPS'
sudo ufw allow 'Nginx Full'
sudo ufw status
sudo ufw enable
sudo ufw status

sudo -u www-data php occ db:add-missing-indices
sudo -u www-data php nextcloud/occ db:convert-filecache-bigint
