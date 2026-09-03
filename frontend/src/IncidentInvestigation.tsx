import React, { useState, useEffect } from 'react';
import ReactFlow, { Background, Controls } from 'reactflow';
import 'reactflow/dist/style.css';

function IncidentInvestigation({ incidentId, onBack }: { incidentId: string, onBack: () => void }) {
  const [incident, setIncident] = useState<any>(null);
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [responseStatus, setResponseStatus] = useState<string | null>(null);

  useEffect(() => {
    fetch(`http://localhost:8000/api/incidents/${incidentId}`)
      .then(res => res.json())
      .then(data => {
        setIncident(data);
        setNodes(data.graph.nodes);
        setEdges(data.graph.edges);
      });
  }, [incidentId]);

  const handleSimulateResponse = () => {
    fetch(`http://localhost:8000/api/incidents/${incidentId}/simulate-response`, {
      method: 'POST'
    })
    .then(res => res.json())
    .then(data => {
      setResponseStatus(data.status);
    });
  };

  if (!incident) return <div className="p-8 text-white">Loading...</div>;

  return (
    <div className="flex flex-col h-full">
      <div className="p-6 border-b border-slate-800 flex justify-between items-center">
        <div>
          <button onClick={onBack} className="text-blue-400 hover:text-blue-300 text-sm mb-2">&larr; Back to Dashboard</button>
          <h2 className="text-2xl font-bold">{incident.title}</h2>
          <span className="text-red-400 text-sm font-bold bg-red-500/20 px-2 py-1 rounded-full">{incident.severity}</span>
          <span className="ml-4 text-slate-400 text-sm">Status: {responseStatus || incident.status}</span>
        </div>
      </div>
      
      <div className="flex flex-1 overflow-hidden">
        {/* Graph Area */}
        <div className="flex-1 bg-slate-950 relative border-r border-slate-800">
          <ReactFlow nodes={nodes} edges={edges} fitView>
            <Background color="#334155" gap={16} />
            <Controls />
          </ReactFlow>
        </div>

        {/* Right Panel */}
        <div className="w-96 bg-slate-900 p-6 flex flex-col gap-6 overflow-y-auto">
          
          <div className="glass-panel p-4">
            <h3 className="font-bold text-lg mb-2">ROOT CAUSE</h3>
            <p className="text-red-400 font-semibold">{incident.root_cause}</p>
            <p className="text-sm text-slate-400 mt-1">Confidence: {incident.root_cause_confidence}%</p>
          </div>

          <div className="glass-panel p-4">
            <h3 className="font-bold text-lg mb-2 text-orange-400">NEXT STEP PREDICTION</h3>
            <p className="font-semibold">{incident.predicted_next_step}</p>
            <p className="text-sm text-slate-400 mt-1">Probability: {incident.prediction_confidence}%</p>
            <div className="w-full bg-slate-800 h-2 mt-2 rounded-full overflow-hidden">
              <div className="bg-orange-500 h-full" style={{ width: `${incident.prediction_confidence}%` }}></div>
            </div>
          </div>

          <div className="glass-panel p-4 border-blue-900/50 bg-blue-950/20">
            <h3 className="font-bold text-lg mb-2 text-blue-400">RECOMMENDED ACTION</h3>
            <p className="text-sm">Revoke compromised session token</p>
            <div className="flex gap-2 mt-4">
              <button onClick={handleSimulateResponse} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded font-medium text-sm transition-colors">
                APPROVE RESPONSE
              </button>
              <button className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-2 rounded font-medium text-sm transition-colors">
                REJECT
              </button>
            </div>
            {responseStatus && (
              <p className="mt-4 text-green-400 text-sm font-semibold">
                ✓ Response simulated successfully. Incident status: {responseStatus}
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default IncidentInvestigation;
