from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import get_db, engine, Base
from models import Alert, Incident
import engine as causal_engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CAUSALIS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "Operational", "environment": "Demo SOC"}

@app.get("/api/overview")
def get_overview(db: Session = Depends(get_db)):
    total_alerts = db.query(Alert).count()
    total_incidents = db.query(Incident).count()
    critical_incidents = db.query(Incident).filter(Incident.severity == "CRITICAL").count()
    
    compression = round(total_alerts / max(1, total_incidents), 1)
    
    return {
        "metrics": {
            "total_alerts": total_alerts,
            "correlated_incidents": total_incidents,
            "critical_incidents": critical_incidents,
            "alert_compression": f"{compression}x"
        }
    }

@app.get("/api/incidents")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.id.desc()).all()
    return incidents

@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "root_cause": incident.root_cause,
        "root_cause_confidence": incident.root_cause_confidence,
        "predicted_next_step": incident.predicted_next_step,
        "prediction_confidence": incident.prediction_confidence,
        "graph": incident.graph_data
    }

@app.post("/api/incidents/{incident_id}/simulate-response")
def simulate_response(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    incident.status = "CONTAINED"
    db.commit()
    
    return {"status": incident.status, "message": "Response simulated successfully."}

@app.post("/api/demo/run-correlation")
def run_correlation(db: Session = Depends(get_db)):
    result = causal_engine.run_correlation_pipeline(db)
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
