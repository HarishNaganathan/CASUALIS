from models import Alert, Incident
from sqlalchemy.orm import Session
import datetime

CORRELATION_THRESHOLD = 55

ATTACK_PROGRESSION = {
    "SESSION_TOKEN_THEFT": {"next": [("UNUSUAL_LOGIN", 85)], "stage_score": 10},
    "CREDENTIAL_COMPROMISE": {"next": [("UNUSUAL_LOGIN", 80)], "stage_score": 10},
    "UNUSUAL_LOGIN": {"next": [("PRIVILEGE_ESCALATION", 75), ("REMOTE_ACCESS", 70)], "stage_score": 20},
    "REMOTE_ACCESS": {"next": [("LATERAL_MOVEMENT", 85)], "stage_score": 30},
    "LATERAL_MOVEMENT": {"next": [("DOMAIN_ADMIN_COMPROMISE", 60), ("SUSPICIOUS_PROCESS", 75)], "stage_score": 40},
    "PRIVILEGE_ESCALATION": {"next": [("SUSPICIOUS_PROCESS", 80), ("PROCESS_EXECUTION", 70)], "stage_score": 50},
    "SUSPICIOUS_PROCESS": {"next": [("SENSITIVE_DATA_ACCESS", 85)], "stage_score": 60},
    "PROCESS_EXECUTION": {"next": [("SENSITIVE_DATA_ACCESS", 75)], "stage_score": 60},
    "SENSITIVE_DATA_ACCESS": {"next": [("DATA_EXFILTRATION", 90), ("POSSIBLE_EXFILTRATION", 80)], "stage_score": 80},
    "POSSIBLE_EXFILTRATION": {"next": [], "stage_score": 100},
    "DATA_EXFILTRATION": {"next": [], "stage_score": 100},
    "DOMAIN_ADMIN_COMPROMISE": {"next": [], "stage_score": 100}
}

SEVERITY_MAPPING = {
    "SESSION_TOKEN_THEFT": "CRITICAL",
    "DATA_EXFILTRATION": "CRITICAL",
    "POSSIBLE_EXFILTRATION": "CRITICAL",
    "LATERAL_MOVEMENT": "HIGH",
    "PRIVILEGE_ESCALATION": "HIGH",
    "CREDENTIAL_COMPROMISE": "HIGH",
    "DOMAIN_ADMIN_COMPROMISE": "CRITICAL",
    "SUSPICIOUS_PROCESS": "MEDIUM",
    "UNUSUAL_LOGIN": "MEDIUM",
    "SENSITIVE_DATA_ACCESS": "MEDIUM",
    "PROCESS_EXECUTION": "LOW"
}

def normalize_entity(val):
    if val is None:
        return None
    return str(val).strip().lower()

def resolve_entities(alerts):
    # Normalize identifiers deterministically without deleting raw data
    # (Since we are modifying the Alert objects before commit, we need to be careful.
    # However, these are processed alerts, so standardizing in memory for correlation is fine.
    # A better way would be to compute a separate key if we want to preserve DB raw fields, 
    # but the DB already has raw_event for that. We'll normalize the structured fields.)
    for alert in alerts:
        if alert.user: alert.user = normalize_entity(alert.user)
        if alert.device: alert.device = normalize_entity(alert.device)
        if alert.ip: alert.ip = normalize_entity(alert.ip)
        if alert.process: alert.process = normalize_entity(alert.process)
    return alerts

def calculate_time_score(a1, a2):
    if not a1.timestamp or not a2.timestamp:
        return 0
    time_diff_seconds = abs((a2.timestamp - a1.timestamp).total_seconds())
    if time_diff_seconds <= 300: # 5 minutes
        return 15
    elif time_diff_seconds <= 900: # 15 minutes
        return 10
    elif time_diff_seconds <= 3600: # 1 hour
        return 5
    return 0

def calculate_progression_score(event1, event2):
    prog1 = ATTACK_PROGRESSION.get(event1)
    if prog1:
        for next_evt, conf in prog1["next"]:
            if next_evt == event2:
                return 25
    return 0

def calculate_correlation_score(a1, a2):
    score = 0
    reasons = []
    
    if a1.user and a2.user and a1.user == a2.user:
        score += 25
        reasons.append("same user")
    if a1.device and a2.device and a1.device == a2.device:
        score += 20
        reasons.append("same device")
    if a1.ip and a2.ip and a1.ip == a2.ip:
        score += 15
        reasons.append("same ip")
        
    t_score = calculate_time_score(a1, a2)
    if t_score > 0:
        score += t_score
        reasons.append("temporal proximity")
        
    p_score = calculate_progression_score(a1.event_type, a2.event_type)
    if p_score > 0:
        score += p_score
        reasons.append("logical attack progression")
        
    return score, reasons

def build_incident_groups(alerts):
    groups = []
    sorted_alerts = sorted(alerts, key=lambda x: x.timestamp if x.timestamp else datetime.datetime.min)
    
    for alert in sorted_alerts:
        assigned = False
        for group in groups:
            max_score = 0
            for g_alert in group:
                score, _ = calculate_correlation_score(g_alert, alert)
                if score > max_score:
                    max_score = score
            if max_score >= CORRELATION_THRESHOLD:
                group.append(alert)
                assigned = True
                break
        if not assigned:
            groups.append([alert])
            
    return groups

def calculate_root_cause(group):
    # Score candidate root causes based on early appearance, stage, and downstream impact
    candidates = []
    sorted_group = sorted(group, key=lambda x: x.timestamp if x.timestamp else datetime.datetime.min)
    total_events = len(sorted_group)
    
    for idx, alert in enumerate(sorted_group):
        score = 0
        reasons = []
        
        prog = ATTACK_PROGRESSION.get(alert.event_type)
        if prog:
            stage_points = 100 - prog["stage_score"]
            score += stage_points
            if stage_points > 50:
                reasons.append("initial attack-stage event")
        
        # Temporal position logic
        time_points = max(0, 50 - (idx * 10))
        score += time_points
        if idx == 0:
            reasons.append("earliest relevant event")
            
        # Downstream events logic
        downstream_count = total_events - 1 - idx
        if downstream_count > 0:
            reasons.append(f"supports {downstream_count} downstream events")
            score += min(20, downstream_count * 5)
            
        candidates.append({
            "alert": alert, 
            "score": score,
            "reasons": reasons
        })
        
    candidates.sort(key=lambda x: x["score"], reverse=True)
    best = candidates[0]
    
    confidence = min(99.0, max(50.0, float(best["score"])))
    reason_str = ", ".join(best["reasons"])
    
    return best["alert"].event_type, confidence, reason_str

def predict_next_step(group):
    sorted_group = sorted(group, key=lambda x: x.timestamp if x.timestamp else datetime.datetime.min)
    last_alert = sorted_group[-1]
    
    prog = ATTACK_PROGRESSION.get(last_alert.event_type)
    if prog and prog["next"]:
        best_next = max(prog["next"], key=lambda x: x[1])
        return best_next[0], float(best_next[1])
        
    return "Unknown / No strong prediction", 0.0

def determine_incident_properties(group):
    event_types = set([a.event_type for a in group])
    title = "Suspicious Activity"
    if "SESSION_TOKEN_THEFT" in event_types:
        title = "Compromised Identity"
    elif "LATERAL_MOVEMENT" in event_types:
        title = "Lateral Movement Detected"
        
    severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    max_sev = "LOW"
    for e in event_types:
        sev = SEVERITY_MAPPING.get(e, "LOW")
        if severity_order[sev] > severity_order[max_sev]:
            max_sev = sev
            
    root_cause, rc_conf, _ = calculate_root_cause(group)
    next_step, next_conf = predict_next_step(group)
    
    return title, max_sev, root_cause, rc_conf, next_step, next_conf

def build_causal_graph(group):
    nodes = []
    edges = []
    
    sorted_group = sorted(group, key=lambda x: x.timestamp if x.timestamp else datetime.datetime.min)
    
    for i, a in enumerate(sorted_group):
        nodes.append({
            "id": str(a.id),
            "data": {
                "label": a.event_type, 
                "type": a.source,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "severity": a.severity
            },
            "position": {"x": 100, "y": 50 + (i * 100)}
        })
        
        if i > 0:
            best_prev = sorted_group[i-1]
            best_score = -1
            best_reasons = []
            
            for j in range(i):
                score, reasons = calculate_correlation_score(sorted_group[j], a)
                if score > best_score:
                    best_score = score
                    best_prev = sorted_group[j]
                    best_reasons = reasons
            
            relationship = "associated"
            prog = ATTACK_PROGRESSION.get(best_prev.event_type)
            if prog:
                for next_evt, _ in prog["next"]:
                    if next_evt == a.event_type:
                        relationship = "supports"
                        break
                
            edges.append({
                "id": f"e{best_prev.id}-{a.id}",
                "source": str(best_prev.id),
                "target": str(a.id),
                "data": {
                    "relationship": relationship,
                    "score": best_score,
                    "reasons": best_reasons
                }
            })
            
    return {"nodes": nodes, "edges": edges}

def run_correlation_pipeline(db: Session):
    uncorrelated = db.query(Alert).filter(Alert.incident_id == None).all()
    if not uncorrelated:
        return {"status": "No new alerts", "alerts_processed": 0, "incidents_created": 0, "incident_ids": []}
        
    resolved = resolve_entities(uncorrelated)
    groups = build_incident_groups(resolved)
    
    incidents_created = 0
    incident_ids = []
    
    for group in groups:
        if len(group) == 1:
            sev = SEVERITY_MAPPING.get(group[0].event_type, "LOW")
            # LIMITATION: Currently isolated LOW/MEDIUM alerts remain with incident_id=None
            # and will be re-processed on subsequent correlation runs. 
            # Modifying this requires a DB schema migration to add a 'status' or 'processed' flag
            # which we are avoiding to keep database compatibility.
            if sev in ["LOW", "MEDIUM"]:
                continue
                
        title, severity, root_cause, rc_conf, next_step, next_conf = determine_incident_properties(group)
        _, _, rc_reason = calculate_root_cause(group)
        
        graph_data = build_causal_graph(group)
        # We append reasoning into graph_data since the Incident model lacks a root_cause_reasoning field
        graph_data["root_cause_reasoning"] = rc_reason
        
        inc = Incident(
            title=title,
            severity=severity,
            status="Investigating",
            root_cause=root_cause,
            root_cause_confidence=rc_conf,
            predicted_next_step=next_step,
            prediction_confidence=next_conf,
            graph_data=graph_data
        )
        db.add(inc)
        db.flush()
        
        for a in group:
            a.incident_id = inc.id
            
        incidents_created += 1
        incident_ids.append(inc.id)
        
    db.commit()
    
    return {
        "status": "Correlation completed",
        "alerts_processed": len(uncorrelated),
        "incidents_created": incidents_created,
        "incident_ids": incident_ids
    }
