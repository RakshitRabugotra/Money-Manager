from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4
import datetime

db = SQLAlchemy()


def get_uuid():
    return uuid4().hex

def now():
    return datetime.datetime.now()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(32), primary_key=True, unique=True, default=get_uuid)
    email = db.Column(db.String(345), unique=True)
    username = db.Column(db.String(30), nullable=False)
    password = db.Column(db.Text, nullable=False)

    # Serializes the object
    @staticmethod
    def serialize(user) -> dict:
        return {
            "id": user.id,
            "email": user.email,
            "username": user.username,
        }

