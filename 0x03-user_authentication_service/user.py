#!/usr/bin/env python3
''' The User models module
'''
from sqlalchemy import Integer, Column, String
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class User(Base):
    ''' Represents a record from user table
    '''
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=True)
    session_id = Column(String(250), nullable=False)
    reset_token = Column(String(250), nullable=False)
