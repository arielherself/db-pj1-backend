docker-bserv:
	sudo docker build -t bserv -f ./Dockerfile .
docker-bserv_pg:
	sudo docker build -t bserv_pg -f ./Dockerfile.pg .
