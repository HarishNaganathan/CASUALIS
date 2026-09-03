import React, { useEffect, useState } from 'react';
import IncidentInvestigation from './IncidentInvestigation';

function App() {
  const [metrics, setMetrics] = useState({
    total_alerts: 0,
    correlated_incidents: 0,
    critical_incidents: 0,
    alert_compression: "0x"
  });
  
  const [incidents, setIncidents] = useState<any[]>([]);
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);

  const fetchData = () => {
    fetch(`${import.meta.env.VITE_API_URL}/api/overview`)
      .then(res => res.json())
      .then(data => setMetrics(data.metrics))
      .catch(err => console.error(err));
      
    fetch(`${import.meta.env.VITE_API_URL}/api/incidents`)
      .then(res => res.json())
      .then(data => setIncidents(data))
      .catch(err => console.error(err));
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunCorrelation = () => {
    fetch(`${import.meta.env.VITE_API_URL}/api/demo/run-correlation`, { method: 'POST' })
      .then(() => fetchData());
  };

  if (activeIncidentId) {
    return <div className="h-screen w-full bg-slate-950 text-slate-50 font-sans">
      <IncidentInvestigation incidentId={activeIncidentId} onBack={() => setActiveIncidentId(null)} />
    </div>;
  }

  return (
    <div className="flex h-screen w-full bg-slate-950 text-slate-50 font-sans">
      {/* Sidebar */}
      <div className="w-64 bg-slate-900 border-r border-slate-800 p-4 flex flex-col gap-4">
        <h1 className="text-xl font-bold tracking-widest text-blue-500 mb-6">CAUSALIS</h1>
        <nav className="flex flex-col gap-2">
          <a href="#" className="p-2 rounded bg-slate-800 text-slate-100">Overview</a>
          <a href="#" className="p-2 rounded hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors">Incidents</a>
          <a href="#" className="p-2 rounded hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors">Alerts</a>
          <a href="#" className="p-2 rounded hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors">Attack Graph</a>
          <a href="#" className="p-2 rounded hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors">Root Cause</a>
        </nav>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Topbar */}
        <header className="h-16 border-b border-slate-800 flex items-center px-6 justify-between shrink-0">
          <div className="flex items-center gap-4">
            <span className="text-sm text-slate-400">Environment: Demo SOC</span>
            <span className="flex items-center gap-2 text-sm text-green-400">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
              System Operational
            </span>
          </div>
          <div className="flex items-center gap-4">
            <button onClick={handleRunCorrelation} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-1.5 rounded font-medium text-sm transition-colors">
              RUN CORRELATION
            </button>
            <input type="text" placeholder="Search..." className="bg-slate-900 border border-slate-700 rounded-md px-3 py-1.5 text-sm focus:outline-none focus:border-blue-500" />
            <div className="w-8 h-8 rounded-full bg-slate-700"></div>
          </div>
        </header>

        {/* Dashboard */}
        <main className="p-8 flex-1 overflow-y-auto">
          <h2 className="text-2xl font-semibold mb-6">SOC Overview</h2>
          
          <div className="grid grid-cols-4 gap-6 mb-8">
            <div className="glass-panel p-6">
              <h3 className="text-slate-400 text-sm font-medium mb-2">Total Alerts</h3>
              <p className="text-3xl font-bold">{metrics.total_alerts}</p>
            </div>
            <div className="glass-panel p-6">
              <h3 className="text-slate-400 text-sm font-medium mb-2">Correlated Incidents</h3>
              <p className="text-3xl font-bold">{metrics.correlated_incidents}</p>
            </div>
            <div className="glass-panel p-6 border-red-900/50 bg-red-950/20">
              <h3 className="text-red-400 text-sm font-medium mb-2">Critical Incidents</h3>
              <p className="text-3xl font-bold text-red-500">{metrics.critical_incidents}</p>
            </div>
            <div className="glass-panel p-6">
              <h3 className="text-slate-400 text-sm font-medium mb-2">Alert Compression</h3>
              <p className="text-3xl font-bold text-blue-400">{metrics.alert_compression}</p>
            </div>
          </div>

          <h3 className="text-xl font-semibold mb-4">Active Incidents</h3>
          <div className="glass-panel overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-4 font-medium">Incident ID</th>
                  <th className="p-4 font-medium">Title</th>
                  <th className="p-4 font-medium">Severity</th>
                  <th className="p-4 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {incidents.map((incident: any) => (
                  <tr key={incident.id} onClick={() => setActiveIncidentId(incident.id)} className="hover:bg-slate-800/30 transition-colors cursor-pointer">
                    <td className="p-4 font-mono text-blue-400">INC-{incident.id}</td>
                    <td className="p-4 font-medium">{incident.title}</td>
                    <td className="p-4">
                      <span className={`px-2 py-1 rounded-full text-xs font-bold ${
                        incident.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                        incident.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-slate-500/20 text-slate-400'
                      }`}>
                        {incident.severity}
                      </span>
                    </td>
                    <td className="p-4 text-slate-300">{incident.status}</td>
                  </tr>
                ))}
                {incidents.length === 0 && (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-slate-500">
                      No correlated incidents. Click "Run Correlation" to process alerts.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
