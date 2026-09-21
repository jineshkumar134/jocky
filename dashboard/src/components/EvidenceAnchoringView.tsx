import React from 'react';
import { AnchoringResponse } from '../types';
import { CheckCircle, XCircle, ShieldCheck, Link2, Database } from 'lucide-react';

interface AnchoringProps {
  data: AnchoringResponse;
}

export const EvidenceAnchoringView: React.FC<AnchoringProps> = ({ data }) => {
  const anchor = data.anchor;
  const verify = data.verification;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" /> Cryptographic Anchoring &amp; Verification
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Phase 11 immutable integrity proofing. Dual-anchored to IPFS and on-chain EVM smart contract state.
        </p>
      </div>

      {/* Verification Status Banner */}
      <div
        className={`p-6 rounded-xl border flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 ${
          verify?.is_valid
            ? 'border-emerald-500/40 bg-emerald-950/20'
            : 'border-red-500/40 bg-red-950/20'
        }`}
      >
        <div className="flex items-center gap-3">
          {verify?.is_valid ? (
            <div className="w-10 h-10 rounded-lg bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <CheckCircle className="w-6 h-6" />
            </div>
          ) : (
            <div className="w-10 h-10 rounded-lg bg-red-500/20 border border-red-500/30 flex items-center justify-center text-red-400">
              <XCircle className="w-6 h-6" />
            </div>
          )}
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-slate-400">CRYPTOGRAPHIC VERIFICATION STATE</div>
            <h3 className="text-xl font-bold font-mono text-slate-100 mt-0.5">
              {verify?.is_valid ? 'EVIDENCE PACKAGE INTEGRITY: VERIFIED' : 'VERIFICATION FAILED'}
            </h3>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2 font-mono text-xs">
          <div className="p-2 rounded bg-slate-950/60 border border-slate-800 text-center">
            <span className="text-[10px] text-slate-500 block">PACKAGE HASH</span>
            <span className={`font-bold ${verify?.package_hash_match ? 'text-emerald-400' : 'text-red-400'}`}>
              {verify?.package_hash_match ? 'MATCH' : 'MISMATCH'}
            </span>
          </div>

          <div className="p-2 rounded bg-slate-950/60 border border-slate-800 text-center">
            <span className="text-[10px] text-slate-500 block">IPFS CONTENT</span>
            <span className={`font-bold ${verify?.ipfs_match ? 'text-emerald-400' : 'text-red-400'}`}>
              {verify?.ipfs_match ? 'MATCH' : 'MISMATCH'}
            </span>
          </div>

          <div className="p-2 rounded bg-slate-950/60 border border-slate-800 text-center">
            <span className="text-[10px] text-slate-500 block">EVM RECORD</span>
            <span className={`font-bold ${verify?.evm_match ? 'text-emerald-400' : 'text-red-400'}`}>
              {verify?.evm_match ? 'MATCH' : 'MISMATCH'}
            </span>
          </div>
        </div>
      </div>

      {/* Anchor Details Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* On-Chain EVM Record */}
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4 font-mono text-xs">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Link2 className="w-4 h-4 text-cyan-400" /> On-Chain EVM Smart Contract Record
          </h3>

          <div className="space-y-3">
            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 block">TRANSACTION HASH</span>
              <span className="text-cyan-400 break-all">{anchor?.tx_hash || '0x696ca608d1e1aa...'}</span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">CHAIN ID</span>
                <span className="text-slate-200">{anchor?.chain_id ?? 31337} (Hardhat/Local)</span>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">BLOCK NUMBER</span>
                <span className="text-slate-200">{anchor?.block_number ?? 1000001}</span>
              </div>
            </div>

            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 block">CONTRACT REGISTRY</span>
              <span className="text-slate-300 break-all">{anchor?.contract_address || '0x100000000000000000000000000000000000J0C1'}</span>
            </div>
          </div>
        </div>

        {/* IPFS & Package Hashes */}
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4 font-mono text-xs">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Database className="w-4 h-4 text-indigo-400" /> Decentralized Content Addressing
          </h3>

          <div className="space-y-3">
            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 block">IPFS CID (Content Identifier)</span>
              <span className="text-emerald-400 break-all">{anchor?.ipfs_cid || 'bafkn5q6y2zeo3o4yscz5...'}</span>
            </div>

            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 block">IMMUTABLE EVIDENCE PACKAGE HASH</span>
              <span className="text-cyan-400 break-all">{anchor?.package_hash || verify?.expected_package_hash}</span>
            </div>

            {anchor?.metadata && (
              <div className="grid grid-cols-3 gap-2">
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[9px] text-slate-500 block">GRAPH HASH</span>
                  <span className="text-[10px] text-slate-400 truncate block">{anchor.metadata.graph_hash?.slice(0, 10)}...</span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[9px] text-slate-500 block">TIMELINE HASH</span>
                  <span className="text-[10px] text-slate-400 truncate block">{anchor.metadata.timeline_hash?.slice(0, 10)}...</span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[9px] text-slate-500 block">RISK HASH</span>
                  <span className="text-[10px] text-slate-400 truncate block">{anchor.metadata.risk_hash?.slice(0, 10)}...</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
