from database.base import Base
from flask_login import UserMixin
from sqlalchemy import Boolean, Column, Integer, String, Text


class User(Base):
    __tablename__ = "user"
    email = Column(Text, primary_key=True)
    password = Column(String)
    g5k_user = Column(String)
    g5k_pwd = Column(String)
    iot_user = Column(String)
    iot_pwd = Column(String)
    ssh_key = Column(Text)
    email_token = Column(Text)
    confirmed_email = Column(Boolean, default=False)
    is_authorized = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)


    def is_active(self):
        """True, as all users are active."""
        return True


    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.email


    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated


    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False


    def __repr__(self):
        return "User(%s, %s, %s)" % (self.email, self.is_authorized, self.is_admin)


class Agent(Base):
    __tablename__ = "agent"
    name = Column(Text, primary_key=True)
    type = Column(Text)
    ip = Column(Text)
    port = Column(Integer)
    state = Column(Text)
    token = Column(Text)


    def __repr__(self):
        return "Agent(%s, %s, %s)" % (self.name, self.type, self.state)


class Smtp(Base):
    __tablename__ = "smtp"
    server_address = Column(Text, primary_key=True)
    server_port = Column(Integer)
    account = Column(Text)
    password = Column(Text)
    email_filter = Column(Text)
    enabled = Column(Boolean, default=False)
