from database.base import Base, DB_URL, engine, SessionLocal
from sqlalchemy import inspect
# Import tables to load the table description
import database.tables, logging


def open_session():
    return SessionLocal()


def row2dict(alchemyResult):
    return { c.key: getattr(alchemyResult, c.key) for c in inspect(alchemyResult).mapper.column_attrs }


def row2elem(alchemyResult):
    result = {}
    for ar in alchemyResult:
        if ar.name not in result:
            result[ar.name] = {}
        result[ar.name][ar.prop_name] = ar.prop_value
    return result

def row2props(alchemyResults):
    props = {}
    for ar in alchemyResults:
        if "prop_name" in ar.__dict__:
            props[ar.prop_name] = ar.prop_value
        else:
            logging.warning("Tuple does not have 'prop_name' key (%s)" % ar)
    return props


def close_session(session):
    session.commit()
    session.close()


def create_tables():
    inspector = inspect(engine)
    tables = []
    if DB_URL.startswith("sqlite"):
        tables = inspector.get_table_names()
    else:
        db_name = DB_URL.split('/')[-1]
        for sch in inspector.get_schema_names():
            if sch == db_name:
                tables = inspector.get_table_names(schema=sch)
    if len(tables) == 0:
        logging.info("The database is empty. Create tables...")
        Base.metadata.create_all(engine)
        return True
    return False
