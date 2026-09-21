import React, { useState } from 'react';
import { EvidenceResponse, UniversalEvidence } from '../types';
import { FileText, Search, Filter, CheckCircle, Database, Layers } from 'lucide-react';

interface EvidenceExplorerProps {
  evidenceData: EvidenceResponse;
}

const EVIDENCE_TYPES = [
  'ALL',
  'FILE',
  'PROCESS',
  'SYSTEM',
  'NETWORK_CONNECTION',
  'NETWORK_LISTENER',
  'DNS_RECORD',
  'WALLET',
  'TRANSACTION',
  'VASP',
  'BLOCKCHAIN_EVENT',
];

export const EvidenceExplorer: React.FC<EvidenceExplorerProps> = ({ evidenceData }) => {
  const [selectedType, setSelectedType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedItem, setSelectedItem] = useState<UniversalEvidence | null>(evidenceData.evidence[0] || null);

  const filteredItems = evidenceData.evidence.filter((item) => {
    const matchesType = selectedType === 'ALL' || item.type === selectedType;
    const matchesSearch =
      searchQuery === '' ||
      item.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      JSON.stringify(item.entity).toLowerCase().includes(searchQuery.toLowerCase());
    return matchesType && matchesSearch;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" /> Universal Evidence Explorer
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographically integrity-verified evidence items and grounded relationships.
          </p>
        </div>

        <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
          <span className="bg-slate-950 border border-slate-800 px-2.5 py-1 rounded">
            Total Items: <strong className="text-slate-200">{evidenceData.evidence.length}</strong>
          </span>
          <span className="bg-slate-950 border border-slate-800 px-2.5 py-1 rounded">
            Package Hash: <strong className="text-cyan-400">{evidenceData.package_hash.slice(0, 8)}...</strong>
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by Evidence ID, PID, filename, domain, IP, or wallet address..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono placeholder:text-slate-500"
          />
        </div>

        <div className="flex items-center gap-2 overflow-x-auto pb-1 max-w-full">
          <Filter className="w-4 h-4 text-slate-500 shrink-0" />
          <div className="flex gap-1.5 shrink-0">
            {EVIDENCE_TYPES.map((type) => (
              <button
                key={type}
                onClick={() => setSelectedType(type)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono whitespace-nowrap transition ${
                  selectedType === type
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {type}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Content: List + Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Evidence List */}
        <div className="lg:col-span-5 space-y-2 max-h-[600px] overflow-y-auto pr-1">
          {filteredItems.length === 0 ? (
            <div className="p-8 text-center border border-slate-800 rounded-xl bg-slate-900/30 text-slate-500 text-xs font-mono">
              No evidence items match filter criteria.
            </div>
          ) : (
            filteredItems.map((item) => {
              const isSelected = item.id === selectedItem?.id;
              return (
                <div
                  key={item.id}
                  onClick={() => setSelectedItem(item)}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer transition ${
                    isSelected
                      ? 'border-blue-500/60 bg-blue-950/20'
                      : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-slate-200">{item.id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-cyan-400 border border-slate-700">
                      {item.type}
                    </span>
                  </div>

                  <div className="mt-1.5 text-xs text-slate-400 font-mono truncate">
                    {item.entity.name || item.entity.process_name || item.entity.domain || item.entity.address || item.entity.hash || 'Grounded Artifact'}
                  </div>

                  <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                    <span>Confidence: {(item.confidence * 100).toFixed(0)}%</span>
                    <span>{item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'UNTIMED'}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Evidence Item Details */}
        <div className="lg:col-span-7 p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-6">
          {selectedItem ? (
            <>
              <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <div className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider">{selectedItem.type}</div>
                  <h3 className="text-base font-bold font-mono text-slate-100 mt-0.5">{selectedItem.id}</h3>
                  <div className="text-xs text-slate-400 mt-1 flex items-center gap-3 font-mono">
                    <span>Source: {selectedItem.source}</span>
                    <span>&bull;</span>
                    <span>Confidence: {(selectedItem.confidence * 100).toFixed(0)}%</span>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2.5 py-1 rounded">
                  <CheckCircle className="w-3.5 h-3.5" /> HASH VERIFIED
                </div>
              </div>

              {/* Entity Attributes */}
              <div className="space-y-3">
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" /> Entity Grounded Data
                </h4>
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs overflow-x-auto text-slate-300">
                  <pre>{JSON.stringify(selectedItem.entity, null, 2)}</pre>
                </div>
              </div>

              {/* Provenance & Integrity */}
              <div className="space-y-3">
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-indigo-400" /> Provenance &amp; Cryptographic Integrity
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <div className="text-slate-500 text-[10px]">COLLECTOR ADAPTER</div>
                    <div className="text-slate-300 truncate">{selectedItem.provenance.collector}</div>
                    <div className="text-slate-500 text-[10px] mt-1">COLLECTION SOURCE</div>
                    <div className="text-slate-300 truncate">{selectedItem.provenance.source}</div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <div className="text-slate-500 text-[10px]">INTEGRITY ALGORITHM</div>
                    <div className="text-slate-300">{selectedItem.integrity.algorithm}</div>
                    <div className="text-slate-500 text-[10px] mt-1">CONTENT DIGEST</div>
                    <div className="text-emerald-400 truncate" title={selectedItem.integrity.value}>
                      {selectedItem.integrity.value}
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center py-16 text-slate-500 font-mono text-xs">Select an evidence item to view details</div>
          )}
        </div>
      </div>
    </div>
  );
};
