import React, { useState } from 'react';
import { TimelineData, TimelineEvent } from '../types';
import { Clock, Activity, Server, Globe, Link2, GitMerge } from 'lucide-react';

interface TimelineProps {
  timelineData: TimelineData;
}

const CATEGORIES = ['ALL', 'ENDPOINT', 'NETWORK', 'BLOCKCHAIN', 'VASP', 'CORRELATION'];

export const InvestigationTimelineView: React.FC<TimelineProps> = ({ timelineData }) => {
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);

  const filteredEvents = timelineData.events.filter((ev) => {
    if (selectedCategory === 'ALL') return true;
    return ev.category?.toUpperCase() === selectedCategory;
  });

  const getCategoryIcon = (category: string) => {
    switch (category?.toUpperCase()) {
      case 'ENDPOINT':
        return <Server className="w-3.5 h-3.5 text-cyan-400" />;
      case 'NETWORK':
        return <Activity className="w-3.5 h-3.5 text-blue-400" />;
      case 'BLOCKCHAIN':
        return <Link2 className="w-3.5 h-3.5 text-amber-400" />;
      case 'VASP':
        return <Globe className="w-3.5 h-3.5 text-emerald-400" />;
      default:
        return <GitMerge className="w-3.5 h-3.5 text-indigo-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" /> Investigation Chronological Timeline
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Phase 10 unified event sequence synthesized from endpoint, network telemetry, and on-chain hops.
          </p>
        </div>

        {/* Category Filters */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-2.5 py-1 rounded text-[11px] font-mono whitespace-nowrap transition ${
                selectedCategory === cat
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Timeline Events Column */}
        <div className="lg:col-span-7 space-y-3 relative pl-6 border-l-2 border-slate-800 max-h-[640px] overflow-y-auto pr-2">
          {filteredEvents.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs font-mono">
              No events found for category '{selectedCategory}'.
            </div>
          ) : (
            filteredEvents.map((ev, index) => {
              const isSelected = selectedEvent?.event_id === ev.event_id;
              const hasTime = !!ev.timestamp;
              return (
                <div
                  key={ev.event_id || index}
                  onClick={() => setSelectedEvent(ev)}
                  className={`relative p-4 rounded-xl border text-left cursor-pointer transition ${
                    isSelected
                      ? 'border-cyan-500/60 bg-cyan-950/20'
                      : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
                  }`}
                >
                  {/* Timeline dot */}
                  <div className="absolute -left-[31px] top-5 w-3.5 h-3.5 rounded-full bg-slate-950 border-2 border-cyan-500 flex items-center justify-center" />

                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="p-1 rounded bg-slate-800">{getCategoryIcon(ev.category)}</span>
                      <span className="font-bold text-xs text-slate-200">{ev.title}</span>
                    </div>

                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        hasTime
                          ? 'bg-slate-950 text-slate-300 border-slate-800'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30 font-semibold'
                      }`}
                    >
                      {hasTime ? new Date(ev.timestamp!).toLocaleTimeString() : 'UNTIMED'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 mt-2 font-mono line-clamp-2">{ev.description}</p>

                  <div className="mt-3 flex items-center justify-between text-[10px] font-mono text-slate-500">
                    <span>Type: {ev.event_type}</span>
                    <span>Confidence: {(ev.confidence * 100).toFixed(0)}%</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Event Details Inspector */}
        <div className="lg:col-span-5 p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4 font-mono text-xs">
          {selectedEvent ? (
            <>
              <div className="border-b border-slate-800 pb-3">
                <span className="text-[10px] text-cyan-400 uppercase tracking-wider block">
                  EVENT IDENTIFIER: {selectedEvent.event_id}
                </span>
                <h3 className="text-sm font-bold text-slate-100 mt-1">{selectedEvent.title}</h3>
                <span className="text-[11px] text-slate-400 mt-0.5 block">{selectedEvent.event_type}</span>
              </div>

              <div className="space-y-3">
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 mb-1">RECORDED TIMESTAMP</div>
                  <div className="text-slate-200">
                    {selectedEvent.timestamp
                      ? `${selectedEvent.timestamp} (${new Date(selectedEvent.timestamp).toUTCString()})`
                      : 'NO TIMESTAMP (Untimed forensic observation — not fabricated)'}
                  </div>
                </div>

                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 mb-1">EVENT DESCRIPTION</div>
                  <div className="text-slate-300 leading-relaxed">{selectedEvent.description}</div>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500">CATEGORY</div>
                    <div className="text-slate-200 font-semibold mt-0.5">{selectedEvent.category}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500">OBSERVED CONFIDENCE</div>
                    <div className="text-emerald-400 font-semibold mt-0.5">
                      {(selectedEvent.confidence * 100).toFixed(0)}%
                    </div>
                  </div>
                </div>

                {selectedEvent.evidence_ids && selectedEvent.evidence_ids.length > 0 && (
                  <div className="p-3 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500 mb-1">SUPPORTING EVIDENCE IDS</div>
                    <div className="space-y-1">
                      {selectedEvent.evidence_ids.map((id) => (
                        <div key={id} className="text-cyan-400 text-[11px]">
                          &bull; {id}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedEvent.correlation_id && (
                  <div className="p-3 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500 mb-1">CORRELATION FINDING ID</div>
                    <div className="text-indigo-400">{selectedEvent.correlation_id}</div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-center py-24 text-slate-500">
              Select an event from the timeline to inspect grounded parameters.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
