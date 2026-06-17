FROM ubuntu:latest

# ruleid: dockerfile.security.run-as-root
USER root

RUN apt-get update && apt-get install -y nginx

# ok: dockerfile.security.run-as-root
USER app

COPY . /app

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
