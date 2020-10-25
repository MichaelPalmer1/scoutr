
build:
	docker build -t simple-deployer .

deploy: build
	docker run -v ${HOME}/.aws:/root/.aws -it simple-deployer sls deploy
