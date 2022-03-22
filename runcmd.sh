sudo systemctl start docker
docker build -t simple-fundamentals .
docker run -d --rm --name fundament -p 3005:3005 -p 3006:3006 -p 4444:4444 simple-fundamentals
