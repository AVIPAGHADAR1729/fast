FROM python:3.10
WORKDIR /crud_apis
RUN pip install fastapi[all] fastapi-mail fastapi-jwt-auth[asymmetric] passlib[bcrypt] pymongo
ADD . ./
EXPOSE 5000
CMD [ "python3", "./run.py" ]
