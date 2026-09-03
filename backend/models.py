from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Float, JSON
from sqlalchemy.orm import relationship
import datetime
from database import Base

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    source = Column(String)
    event_type = Column(String)
    severity = Column(String)
    user = Column(String)
    device = Column(String)
    ip = Column(String)
    process = Column(String)
    description = Column(String)
    raw_event = Column(String)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    
    incident = relationship("Incident", back_populates="alerts")

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    severity = Column(String)
    status = Column(String, default="Investigating")
    root_cause = Column(String)
    root_cause_confidence = Column(Float)
    predicted_next_step = Column(String)
    prediction_confidence = Column(Float)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Store graph as JSON for simplicity
    graph_data = Column(JSON, nullable=True)
    
    alerts = relationship("Alert", back_populates="incident")
