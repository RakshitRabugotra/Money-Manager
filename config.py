from dotenv import load_dotenv
import os
import redis
load_dotenv()

class ApplicationConfig:
    try:
        SECRET_KEY = os.environ["SECRET_KEY"]
    except KeyError:
        SECRET_KEY = "admslkamdkasldnajndjs"

    SQLALCHEMY_TRACK_NOTIFICATIONS = False
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_DATABASE_URI = r"sqlite:///./db.sqlite"

    SESSION_TYPE = "redis"
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_REDIS = redis.from_url("redis://127.0.0.1:6379")