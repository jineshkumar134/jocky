import React, { useState } from 'react';
import { BlockchainVaspResponse } from '../types';
import { Link2, ArrowRight, AlertCircle } from 'lucide-react';

interface BlockchainVaspProps {
  data: BlockchainVaspResponse;
}

export const BlockchainVaspView: React.FC<BlockchainVaspProps> = ({ data }) => {
  const [activeSubTab, setActiveSubTab] = useState<'blockchain' | 'vasp'>('blockchain');
  const bc = data.blockchain;
  const vasp = data.vasp;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Link2 className="w-5 h-5 text-amber-400" /> Blockchain Trace &amp; VASP Attribution
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Phase 7 on-chain transaction graph, multi-hop flow discovery, and analytical exchange attribution.
          </p>
        </div>

        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg text-xs font-mono">
          <button
            onClick={() => setActiveSubTab('blockchain')}
            className={`px-3 py-1.5 rounded-md transition ${
              activeSubTab === 'blockchain' ? 'bg-amber-500/20 text-amber-300 font-semibold border border-amber-500/30' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Blockchain Flow ({bc?.hops.length ?? 0} hops)
          </button>
          <button
            onClick={() => setActiveSubTab('vasp')}
            className={`px-3 py-1.5 rounded-md transition ${
              activeSubTab === 'vasp' ? 'bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            VASP Attribution ({vasp?.attributions.length ?? 0})
          </button>
        </div>
      </div>

      {activeSubTab === 'blockchain' ? (
        <div className="space-y-6">
          {/* Seed Wallet & Summary Bar */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 flex flex-col md:flex-row justify-between gap-4 text-xs font-mono">
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">SEED ADDRESS ({bc?.chain || 'EVM'})</span>
              <span className="text-amber-400 font-bold text-sm">{bc?.seed_address || '0xWALLET001'}</span>
            </div>
            <div className="flex items-center gap-4 text-slate-400">
              <div>Wallets Discovered: <strong className="text-slate-200">{bc?.wallets.length ?? 0}</strong></div>
              <div>&bull;</div>
              <div>Transactions: <strong className="text-slate-200">{bc?.transactions.length ?? 0}</strong></div>
            </div>
          </div>

          {/* Multi-Hop Flow Visualization */}
          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400">
              Multi-Hop Transaction Chain
            </h3>

            {bc?.hops && bc.hops.length > 0 ? (
              <div className="space-y-3">
                {bc.hops.map((hop) => (
                  <div
                    key={hop.hop_number}
                    className="p-4 rounded-xl border border-slate-800 bg-slate-950/80 font-mono text-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
                  >
                    <div className="flex items-center gap-3">
                      <span className="w-7 h-7 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center font-bold text-xs shrink-0">
                        {hop.hop_number}
                      </span>
                      <div>
                        <div className="flex items-center gap-2 text-slate-300">
                          <span className="text-cyan-400">{hop.from_wallet}</span>
                          <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                          <span className="text-emerald-400">{hop.to_wallet}</span>
                        </div>
                        <div className="text-[11px] text-slate-500 mt-1">TX Hash: {hop.tx_hash}</div>
                      </div>
                    </div>

                    <div className="text-right shrink-0">
                      <div className="text-sm font-bold text-slate-200">{hop.amount} {hop.asset}</div>
                      <div className="text-[11px] text-slate-500">{new Date(hop.timestamp).toLocaleTimeString()}</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs font-mono">No transaction hops recorded.</div>
            )}
          </div>

          {/* Discovered Wallets Table */}
          {bc?.wallets && bc.wallets.length > 0 && (
            <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400">
                Discovered Target &amp; Intermediary Wallets
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs text-slate-300">
                  <thead className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                    <tr>
                      <th className="pb-2">Wallet Address</th>
                      <th className="pb-2">Classification</th>
                      <th className="pb-2">Label</th>
                      <th className="pb-2 text-right">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {bc.wallets.map((w) => (
                      <tr key={w.address} className="hover:bg-slate-800/20">
                        <td className="py-2.5 text-cyan-400">{w.address}</td>
                        <td className="py-2.5">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                            {w.wallet_type}
                          </span>
                        </td>
                        <td className="py-2.5 text-slate-400">{w.label || 'Unlabeled EOA'}</td>
                        <td className="py-2.5 text-right text-emerald-400">{(w.confidence * 100).toFixed(0)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* VASP Section */
        <div className="space-y-6">
          <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/10 flex items-start gap-3 text-xs text-amber-200">
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <strong className="font-semibold block mb-0.5">Notice Regarding Analytical VASP Attribution:</strong>
              Attributions shown below are derived from heuristic cluster mapping and transaction graph proximity.
              These represent analytical attribution models and must not be construed as confirmed KYC or verified individual identity.
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {vasp?.attributions && vasp.attributions.length > 0 ? (
              vasp.attributions.map((attr) => (
                <div key={attr.vasp_id} className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4 font-mono text-xs">
                  <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                    <div>
                      <span className="text-[10px] text-emerald-400 uppercase tracking-wider block">ANALYTICAL ATTRIBUTION</span>
                      <h4 className="text-base font-bold text-slate-100 mt-0.5">{attr.name}</h4>
                      <span className="text-slate-500 text-[11px]">VASP ID: {attr.vasp_id}</span>
                    </div>

                    <div className="text-right">
                      <div className="text-sm font-bold text-emerald-400">{attr.score.toFixed(2)}</div>
                      <div className="text-[10px] text-slate-500">{(attr.confidence * 100).toFixed(0)}% confidence</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-[10px] text-slate-400 uppercase">Supporting Attribution Reasons:</div>
                    <ul className="space-y-1 text-slate-300 text-[11px]">
                      {attr.reasons.map((r, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-emerald-400">&bull;</span>
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {attr.scoring_breakdown && (
                    <div className="pt-2 border-t border-slate-800/80">
                      <div className="text-[10px] text-slate-500 mb-1">SCORING BREAKDOWN</div>
                      <div className="flex flex-wrap gap-2 text-[10px]">
                        {Object.entries(attr.scoring_breakdown).map(([k, v]) => (
                          <span key={k} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                            {k}: <strong className="text-slate-200">{Number(v).toFixed(2)}</strong>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="col-span-2 p-12 text-center text-slate-500 font-mono text-xs border border-slate-800 rounded-xl bg-slate-900/30">
                No VASP candidates matched for target wallet.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
