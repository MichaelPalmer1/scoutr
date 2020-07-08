FROM python:3.7
RUN apt-get update
RUN apt-get install npm -y
RUN npm install -g serverless
RUN mkdir /temp
ADD . /temp
WORKDIR /temp
#RUN sls plugin install -n serverless-python-requirements

