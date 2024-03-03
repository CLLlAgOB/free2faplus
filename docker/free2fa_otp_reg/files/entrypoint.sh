#!/bin/sh
# change permission
chown -R appuser:appuser /app/ /opt/db/
chmod 770 -R /opt/db/

# Starting the container's main command
su -s /bin/bash appuser -c "gunicorn -w 4 --certfile=/app/certs/free2fa_otp_reg.crt --keyfile=/app/certs/free2fa_otp_reg.key --bind free2fa_otp_reg:8010 main:app"