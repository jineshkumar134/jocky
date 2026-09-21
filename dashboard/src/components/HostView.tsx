import React, { useState } from 'react';
import { HostItem } from '../types';
import { Server, AlertCircle, CheckCircle2, HelpCircle } from 'lucide-react';

interface HostViewProps {
  hosts: HostItem[];
}

export const HostView: React.FC<HostViewProps> = ({ hosts }) => {
  const [selectedHostId, setSelectedHostId] = useState<string | null>(hosts[0]?.host_id || null);
  const selectedHost = hosts.find((h) => h.host_id === selectedHostId) || hosts[0];

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'ONLINE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" /> ONLINE
          </span>
        );
      case 'OFFLINE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
            <AlertCircle className="w-3.5 h-3.5" /> OFFLINE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700" title="Host registered in inventory; not contacted in current run">
            <HelpCircle className="w-3.5 h-3.5" /> UNKNOWN
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" /> Host Topology &amp; Registration
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Central inventory of all systems registered into this case.
          </p>
        </div>
        <div className="text-xs font-mono text-slate-500">
          Total Hosts: {hosts.length} &bull; Active: {hosts.filter((h) => h.status === 'ONLINE').length}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Host Cards / List */}
        <div className="space-y-3">
          {hosts.map((host) => {
            const isSelected = host.host_id === selectedHost?.host_id;
            return (
              <div
                key={host.host_id}
                onClick={() => setSelectedHostId(host.host_id)}
                className={`p-4 rounded-xl border transition cursor-pointer text-left ${
                  isSelected
                    ? 'border-cyan-500/60 bg-cyan-950/20 shadow-lg shadow-cyan-950/20'
                    : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-sm text-slate-200">{host.hostname}</span>
                  {getStatusBadge(host.status)}
                </div>

                <div className="mt-2 text-xs font-mono text-slate-400 space-y-1">
                  <div className="text-[11px] text-slate-500 truncate">ID: {host.host_id}</div>
                  <div className="flex items-center gap-2 mt-1">
                    {host.is_primary && (
                      <span className="px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 text-[10px]">
                        Primary Executed Host
                      </span>
                    )}
                    {host.has_evidence ? (
                      <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px]">
                        Evidence Attached
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                        No Attached Package
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Host Details Panel */}
        <div className="lg:col-span-2 p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-6">
          {selectedHost ? (
            <>
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <h3 className="text-base font-bold font-mono text-slate-100">{selectedHost.hostname}</h3>
                  <p className="text-xs font-mono text-slate-500 mt-0.5">Host Identifier: {selectedHost.host_id}</p>
                </div>
                {getStatusBadge(selectedHost.status)}
              </div>

              {/* Host Platform & Collection Status */}
              <div className="space-y-4">
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400">
                  Telemetry &amp; Collection State
                </h4>

                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-slate-500 text-[10px]">ROLE IN INVESTIGATION</div>
                    <div className="text-slate-200 font-semibold mt-1">
                      {selectedHost.is_primary ? 'Target Executed Host' : 'Registered Inventory Host'}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-slate-500 text-[10px]">EVIDENCE COLLECTION</div>
                    <div className="text-slate-200 font-semibold mt-1">
                      {selectedHost.has_evidence ? 'Artifacts Extracted & Attached' : 'Not Executed in Local Run'}
                    </div>
                  </div>
                </div>

                {selectedHost.platform_info ? (
                  <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-2 text-xs font-mono">
                    <div className="text-slate-400 font-semibold text-[11px] mb-2">Platform Specification</div>
                    <div className="grid grid-cols-2 gap-y-2">
                      <div><span className="text-slate-500">OS:</span> {selectedHost.platform_info.os_name}</div>
                      <div><span className="text-slate-500">Arch:</span> {selectedHost.platform_info.architecture}</div>
                      <div><span className="text-slate-500">Runtime:</span> {selectedHost.platform_info.runtime}</div>
                      <div><span className="text-slate-500">Adapter:</span> {selectedHost.platform_info.adapter_name}</div>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800/60 text-xs text-slate-400 italic">
                    Platform specifications not queried for this synthetic/uncontacted host.
                  </div>
                )}

                {selectedHost.security_status && (
                  <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-2 text-xs font-mono">
                    <div className="text-slate-400 font-semibold text-[11px] mb-2">Security Pre-Check State</div>
                    <div className="grid grid-cols-3 gap-2">
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-500 text-[10px] block">HVCI</span>
                        <span className="font-bold text-slate-300">
                          {selectedHost.security_status.hvci?.applicable ? (selectedHost.security_status.hvci.enabled ? 'ENABLED' : 'DISABLED') : 'NOT APPLICABLE'}
                        </span>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-500 text-[10px] block">VBS</span>
                        <span className="font-bold text-slate-300">
                          {selectedHost.security_status.vbs?.applicable ? (selectedHost.security_status.vbs.enabled ? 'ENABLED' : 'DISABLED') : 'NOT APPLICABLE'}
                        </span>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-500 text-[10px] block">SECURE BOOT</span>
                        <span className="font-bold text-slate-300">
                          {selectedHost.security_status.secure_boot?.applicable ? (selectedHost.security_status.secure_boot.enabled ? 'ENABLED' : 'DISABLED') : 'NOT APPLICABLE'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-center py-12 text-slate-500 text-sm">No host selected</div>
          )}
        </div>
      </div>
    </div>
  );
};
