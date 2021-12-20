all: deploy

deploy:
	mvn clean deploy -Dmaven.test.skip=true -U