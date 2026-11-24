FROM mcr.microsoft.com/mssql/server:2017-latest

# 555 rather than 444: BuildKit also applies --chmod to the /certs directory it
# creates, and a non-root SQL Server needs the x bit to enter it.
COPY --chmod=555 certs/server.* /certs/
COPY --chmod=555 certs/customCA.* /certs/
COPY docker-mssql.conf /var/opt/mssql/mssql.conf
