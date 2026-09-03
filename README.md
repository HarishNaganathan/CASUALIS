# CAUSALIS

"From alert noise to explainable incidents."

CAUSALIS is an AI-assisted SOC investigation platform prototype built for a cybersecurity hackathon. It demonstrates how traditional, fragmented SOC alerts can be causally correlated into structured, explainable incidents with root-cause identification and next-step prediction.

## Architecture

- **Frontend**: React, TypeScript, Vite, Tailwind CSS, shadcn/ui, reactflow
- **Backend**: Python, FastAPI, SQLite, SQLAlchemy
- **Causal Engine**: Deterministic rules-based correlation for the demo scenario.

## Tech Stack

- **Frontend**: `npm run dev` in `/frontend`
- **Backend**: `uvicorn main:app --reload` in `/backend`

## Setup Instructions

1. **Backend**:
   ```bash
   cd backend
   python -m venv venv
   # activate venv
   pip install -r requirements.txt # (fastapi uvicorn sqlalchemy pydantic)
   python seed.py
   uvicorn main:app --reload
   ```

2. **Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

## Demo Walkthrough

1. Open the frontend URL.
2. The Dashboard shows the synthetic metrics (1247 alerts compressed to 42 incidents).
3. Click on incident `INC-1042` ("Compromised Identity").
4. Observe the Causal Attack Graph built via `reactflow`.
5. Review the Root Cause and Predicted Next Step.
6. Click "APPROVE RESPONSE" to simulate revoking the compromised session token.
7. Observe the incident status change to "CONTAINED".

## Limitations

This is a functional UI and API prototype designed to simulate a SOC workflow. The correlation engine uses deterministic mock data specifically structured for the hackathon demo to ensure a reliable presentation. Real-world implementation would require a massive graph database and heavily tuned ML models for entity resolution.
