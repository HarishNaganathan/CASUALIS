import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Alert, Incident
from database import engine, SessionLocal
import datetime

def seed_data():
    Base.metadata.drop_all(bind=engine) # Reset DB for demo
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # SCENARIO A: Compromised Session
    scenario_a = [
        ("Identity", "SESSION_TOKEN_THEFT", "CRITICAL", "john.doe", "LAPTOP-042", "185.10.10.1", "Suspicious token access"),
        ("Identity", "UNUSUAL_LOGIN", "HIGH", "john.doe", "LAPTOP-042", "185.10.10.1", "Login from new location"),
        ("Endpoint", "PRIVILEGE_ESCALATION", "HIGH", "john.doe", "LAPTOP-042", "185.10.10.1", "Escalated to SYSTEM"),
        ("Endpoint", "SUSPICIOUS_PROCESS", "MEDIUM", "john.doe", "LAPTOP-042", "185.10.10.1", "Executed powershell.exe"),
        ("Endpoint", "SENSITIVE_DATA_ACCESS", "HIGH", "john.doe", "LAPTOP-042", "185.10.10.1", "Accessed finance share"),
        ("Network", "POSSIBLE_EXFILTRATION", "CRITICAL", "john.doe", "LAPTOP-042", "185.10.10.1", "Large data transfer outbound"),
    ]

    # SCENARIO B: Lateral Movement
    scenario_b = [
        ("Endpoint", "LATERAL_MOVEMENT", "HIGH", "admin.svc", "SRV-FILE-01", "10.0.0.5", "SMB PsExec execution"),
        ("Identity", "UNUSUAL_LOGIN", "MEDIUM", "admin.svc", "SRV-FILE-01", "10.0.0.5", "Service account interactive login"),
        ("Endpoint", "SUSPICIOUS_PROCESS", "HIGH", "admin.svc", "SRV-FILE-01", "10.0.0.5", "Executed mimikatz.exe"),
    ]

    # SCENARIO C: Benign Admin
    scenario_c = [
        ("Endpoint", "SUSPICIOUS_PROCESS", "LOW", "it.support", "SRV-APP-02", "10.0.0.12", "Executed remote powershell"),
        ("Identity", "PRIVILEGE_ESCALATION", "LOW", "it.support", "SRV-APP-02", "10.0.0.12", "Used sudo"),
    ]

    now = datetime.datetime.utcnow()
    
    for i, data in enumerate(scenario_a):
        db.add(Alert(timestamp=now + datetime.timedelta(minutes=i), source=data[0], event_type=data[1], severity=data[2], user=data[3], device=data[4], ip=data[5], description=data[6]))

    for i, data in enumerate(scenario_b):
        db.add(Alert(timestamp=now + datetime.timedelta(minutes=i+30), source=data[0], event_type=data[1], severity=data[2], user=data[3], device=data[4], ip=data[5], description=data[6]))
        
    for i, data in enumerate(scenario_c):
        db.add(Alert(timestamp=now + datetime.timedelta(minutes=i+60), source=data[0], event_type=data[1], severity=data[2], user=data[3], device=data[4], ip=data[5], description=data[6]))

    db.commit()
    print("Database seeded with raw alerts.")

if __name__ == "__main__":
    seed_data()
