import React, { useState, useMemo } from 'react';
import { GraphData, GraphNode, GraphEdge } from '../types';
import { Share2, ZoomIn, ZoomOut, RotateCcw, Info, LayoutGrid, CircleDot, Search, Filter } from 'lucide-react';

interface InvestigationGraphProps {
  graphData: GraphData;
}

type LayoutMode = 'flow' | 'radial';

interface LayerDef {
  id: string;
  title: string;
  subtitle: string;
  x: number;
  types: string[];
}

const LAYERS: LayerDef[] = [
  { id: 'endpoint', title: 'ENDPOINT & ARTIFACTS', subtitle: 'Host, files & drop targets', x: 130, types: ['SYSTEM', 'FILE'] },
  { id: 'execution', title: 'PROCESS EXECUTION', subtitle: 'Executables & listeners', x: 380, types: ['PROCESS', 'NETWORK_LISTENER'] },
  { id: 'network', title: 'NETWORK & C2', subtitle: 'Sockets & DNS resolutions', x: 630, types: ['NETWORK_CONNECTION', 'DNS_RECORD', 'DNS', 'NETWORK'] },
  { id: 'crypto', title: 'BLOCKCHAIN & VASP', subtitle: 'EVM wallets, txs & off-ramps', x: 860, types: ['WALLET', 'TRANSACTION', 'VASP', 'BLOCKCHAIN_EVENT'] },
];

export const InvestigationGraph: React.FC<InvestigationGraphProps> = ({ graphData }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('flow');
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');

  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const getNodeType = (node: GraphNode): string => {
    return (node.node_type || node.type || 'SYSTEM').toUpperCase();
  };

  const getNodeColor = (node: GraphNode) => {
    const rawType = getNodeType(node);
    switch (rawType) {
      case 'PROCESS':
        return '#06b6d4'; // cyan
      case 'NETWORK_CONNECTION':
      case 'NETWORK_LISTENER':
      case 'NETWORK':
        return '#3b82f6'; // blue
      case 'DNS':
      case 'DNS_RECORD':
        return '#8b5cf6'; // purple
      case 'WALLET':
        return '#f59e0b'; // amber
      case 'TRANSACTION':
      case 'BLOCKCHAIN_EVENT':
        return '#ec4899'; // pink
      case 'VASP':
        return '#10b981'; // emerald
      case 'FILE':
        return '#eab308'; // yellow
      case 'SYSTEM':
        return '#14b8a6'; // teal
      default:
        return '#94a3b8'; // slate
    }
  };

  const getNodeIcon = (node: GraphNode) => {
    const rawType = getNodeType(node);
    switch (rawType) {
      case 'SYSTEM': return 'SYS';
      case 'FILE': return 'FILE';
      case 'PROCESS': return 'PROC';
      case 'NETWORK_CONNECTION': return 'SOCK';
      case 'NETWORK_LISTENER': return 'LSTN';
      case 'DNS_RECORD':
      case 'DNS': return 'DNS';
      case 'WALLET': return 'EVM';
      case 'TRANSACTION': return 'TX';
      case 'VASP': return 'VASP';
      default: return 'ENT';
    }
  };

  // Calculate layout positions
  const nodePositions = useMemo(() => {
    const posMap: Record<string, { x: number; y: number }> = {};
    const nodes = graphData.nodes;

    if (layoutMode === 'flow') {
      // Group nodes into 4 horizontal layers
      const layerBuckets: Record<string, GraphNode[]> = {
        endpoint: [],
        execution: [],
        network: [],
        crypto: [],
      };

      nodes.forEach((node) => {
        const type = getNodeType(node);
        const layer = LAYERS.find((l) => l.types.includes(type));
        if (layer) {
          layerBuckets[layer.id].push(node);
        } else {
          layerBuckets.endpoint.push(node);
        }
      });

      const topOffset = 70;
      const canvasHeight = 490;

      LAYERS.forEach((layer) => {
        const list = layerBuckets[layer.id];
        const count = list.length;
        list.forEach((node, idx) => {
          const spacing = canvasHeight / (count + 1);
          const y = topOffset + (idx + 1) * spacing;
          posMap[node.id] = { x: layer.x, y };
        });
      });
    } else {
      // Radial concentric layout
      const center = { x: 480, y: 280 };
      const systemNodes = nodes.filter((n) => getNodeType(n) === 'SYSTEM');
      const innerNodes = nodes.filter((n) => ['PROCESS', 'FILE'].includes(getNodeType(n)));
      const midNodes = nodes.filter((n) =>
        ['NETWORK_CONNECTION', 'NETWORK_LISTENER', 'DNS_RECORD', 'DNS'].includes(getNodeType(n))
      );
      const outerNodes = nodes.filter((n) =>
        ['WALLET', 'TRANSACTION', 'VASP', 'BLOCKCHAIN_EVENT'].includes(getNodeType(n))
      );

      // Center
      systemNodes.forEach((node, idx) => {
        posMap[node.id] = { x: center.x, y: center.y + (idx * 24) };
      });

      // Ring 1 (r = 100)
      innerNodes.forEach((node, idx) => {
        const angle = (idx / innerNodes.length) * 2 * Math.PI - Math.PI / 2;
        posMap[node.id] = {
          x: center.x + 110 * Math.cos(angle),
          y: center.y + 110 * Math.sin(angle),
        };
      });

      // Ring 2 (r = 190)
      midNodes.forEach((node, idx) => {
        const angle = (idx / midNodes.length) * 2 * Math.PI - Math.PI / 2;
        posMap[node.id] = {
          x: center.x + 195 * Math.cos(angle),
          y: center.y + 195 * Math.sin(angle),
        };
      });

      // Ring 3 (r = 275)
      outerNodes.forEach((node, idx) => {
        const angle = (idx / outerNodes.length) * 2 * Math.PI - Math.PI / 2;
        posMap[node.id] = {
          x: center.x + 280 * Math.cos(angle),
          y: center.y + 280 * Math.sin(angle),
        };
      });

      // Fallback for any unmapped node
      nodes.forEach((node, idx) => {
        if (!posMap[node.id]) {
          const angle = (idx / nodes.length) * 2 * Math.PI;
          posMap[node.id] = {
            x: center.x + 150 * Math.cos(angle),
            y: center.y + 150 * Math.sin(angle),
          };
        }
      });
    }

    return posMap;
  }, [graphData.nodes, layoutMode]);

  // Connected nodes & edges for highlighting
  const connectedInfo = useMemo(() => {
    const activeId = selectedNode?.id || hoveredNodeId;
    if (!activeId) return { nodeIds: new Set<string>(), edgeIds: new Set<string>() };

    const nodeIds = new Set<string>([activeId]);
    const edgeIds = new Set<string>();

    graphData.edges.forEach((edge) => {
      const srcId = edge.source_id || edge.source || '';
      const tgtId = edge.target_id || edge.target || '';
      if (srcId === activeId || tgtId === activeId) {
        edgeIds.add(edge.id);
        nodeIds.add(srcId);
        nodeIds.add(tgtId);
      }
    });

    return { nodeIds, edgeIds };
  }, [selectedNode, hoveredNodeId, graphData.edges]);

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => setIsDragging(false);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return graphData.nodes.filter((node) => {
      const type = getNodeType(node);
      const matchesType = typeFilter === 'ALL' || type === typeFilter;
      const matchesSearch =
        !searchQuery ||
        node.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        type.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesType && matchesSearch;
    });
  }, [graphData.nodes, typeFilter, searchQuery]);

  return (
    <div className="space-y-4">
      {/* Header & Controls */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-3">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Share2 className="w-5 h-5 text-indigo-400" /> Investigation Attack Graph
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Phase 9 grounded topology linking process execution, socket telemetry, DNS mapping, and EVM flows.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Layout Mode Toggle */}
          <div className="flex rounded-lg bg-slate-900 border border-slate-800 p-0.5 text-xs font-mono">
            <button
              onClick={() => setLayoutMode('flow')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded transition ${
                layoutMode === 'flow' ? 'bg-indigo-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LayoutGrid className="w-3.5 h-3.5" /> Attack Chain
            </button>
            <button
              onClick={() => setLayoutMode('radial')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded transition ${
                layoutMode === 'radial' ? 'bg-indigo-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <CircleDot className="w-3.5 h-3.5" /> Concentric
            </button>
          </div>

          {/* Search Filter */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search graph..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 placeholder-slate-600 w-32 font-mono"
            />
          </div>

          {/* Type Filter */}
          <div className="relative flex items-center">
            <Filter className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 pointer-events-none" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-2 py-1 text-xs text-slate-300 focus:outline-none focus:border-indigo-500 font-mono cursor-pointer"
            >
              <option value="ALL">All Entities</option>
              <option value="SYSTEM">System</option>
              <option value="FILE">File</option>
              <option value="PROCESS">Process</option>
              <option value="NETWORK_CONNECTION">Network</option>
              <option value="DNS_RECORD">DNS</option>
              <option value="WALLET">Wallet</option>
              <option value="TRANSACTION">Transaction</option>
              <option value="VASP">VASP</option>
            </select>
          </div>

          {/* Zoom controls */}
          <div className="flex items-center gap-1">
            <button
              onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}
              className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 transition"
              title="Zoom In"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.4, z - 0.15))}
              className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 transition"
              title="Zoom Out"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
              }}
              className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 transition"
              title="Reset Viewport"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>

          <span className="text-xs font-mono text-slate-500 ml-1">
            {graphData.nodes.length} nodes &bull; {graphData.edges.length} edges
          </span>
        </div>
      </div>

      {/* Main Graph Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Interactive Graph Canvas */}
        <div
          className="lg:col-span-8 rounded-xl border border-slate-800 bg-slate-950 relative overflow-hidden h-[560px] cursor-grab active:cursor-grabbing select-none"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          {/* Subtle grid background */}
          <div
            className="absolute inset-0 opacity-15 pointer-events-none"
            style={{
              backgroundImage: 'radial-gradient(#38bdf8 1px, transparent 1px)',
              backgroundSize: '24px 24px',
            }}
          />

          <svg
            className="w-full h-full"
            viewBox="0 0 960 560"
            preserveAspectRatio="xMidYMid meet"
          >
            <defs>
              <marker
                id="arrow"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569" />
              </marker>
              <marker
                id="arrow-active"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
              </marker>
              <marker
                id="arrow-cross"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#a855f7" />
              </marker>
            </defs>

            <g
              style={{
                transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                transformOrigin: '480px 280px',
                transition: isDragging ? 'none' : 'transform 0.1s ease-out',
              }}
            >
              {/* Layer Column Backdrops (in flow mode) */}
              {layoutMode === 'flow' &&
                LAYERS.map((layer, idx) => (
                  <g key={layer.id} opacity={0.65}>
                    {/* Header line and label */}
                    <text
                      x={layer.x}
                      y={28}
                      textAnchor="middle"
                      fill="#94a3b8"
                      fontSize={11}
                      fontWeight="bold"
                      letterSpacing="1"
                      fontFamily="monospace"
                    >
                      {layer.title}
                    </text>
                    <text
                      x={layer.x}
                      y={42}
                      textAnchor="middle"
                      fill="#475569"
                      fontSize={9}
                      fontFamily="monospace"
                    >
                      {layer.subtitle}
                    </text>
                    {/* Subtle divider */}
                    {idx < LAYERS.length - 1 && (
                      <line
                        x1={layer.x + 125}
                        y1={20}
                        x2={layer.x + 125}
                        y2={540}
                        stroke="#1e293b"
                        strokeDasharray="4,4"
                      />
                    )}
                  </g>
                ))}

              {/* Radial Rings (in radial mode) */}
              {layoutMode === 'radial' && (
                <g opacity={0.4}>
                  <circle cx={480} cy={280} r={110} fill="none" stroke="#1e293b" strokeDasharray="3,3" />
                  <circle cx={480} cy={280} r={195} fill="none" stroke="#1e293b" strokeDasharray="3,3" />
                  <circle cx={480} cy={280} r={280} fill="none" stroke="#1e293b" strokeDasharray="3,3" />
                  <text x={480} y={160} textAnchor="middle" fill="#475569" fontSize={9} fontFamily="monospace">
                    EXECUTION LAYER
                  </text>
                  <text x={480} y={75} textAnchor="middle" fill="#475569" fontSize={9} fontFamily="monospace">
                    NETWORK &amp; C2 LAYER
                  </text>
                  <text x={480} y={-10} textAnchor="middle" fill="#475569" fontSize={9} fontFamily="monospace">
                    BLOCKCHAIN EXFILTRATION LAYER
                  </text>
                </g>
              )}

              {/* Edges */}
              {graphData.edges.map((edge) => {
                const srcId = edge.source_id || edge.source || '';
                const tgtId = edge.target_id || edge.target || '';
                const src = nodePositions[srcId];
                const tgt = nodePositions[tgtId];
                if (!src || !tgt) return null;

                const isEdgeSelected = selectedEdge?.id === edge.id;
                const isEdgeHighlighted = connectedInfo.edgeIds.has(edge.id);
                const isCrossDomain = edge.is_cross_domain || edge.relationship_type?.includes('CROSS') || false;

                // Bezier curve connector in flow mode or line in radial
                let pathData = '';
                if (layoutMode === 'flow') {
                  const dx = (tgt.x - src.x) * 0.5;
                  pathData = `M ${src.x} ${src.y} C ${src.x + dx} ${src.y}, ${tgt.x - dx} ${tgt.y}, ${tgt.x} ${tgt.y}`;
                } else {
                  pathData = `M ${src.x} ${src.y} L ${tgt.x} ${tgt.y}`;
                }

                let strokeColor = '#334155';
                let markerId = 'url(#arrow)';

                if (isEdgeSelected || isEdgeHighlighted) {
                  strokeColor = isCrossDomain ? '#a855f7' : '#38bdf8';
                  markerId = isCrossDomain ? 'url(#arrow-cross)' : 'url(#arrow-active)';
                } else if (isCrossDomain) {
                  strokeColor = '#6366f1';
                }

                return (
                  <g
                    key={edge.id}
                    className="cursor-pointer"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedEdge(edge);
                      setSelectedNode(null);
                    }}
                  >
                    <path
                      d={pathData}
                      fill="none"
                      stroke={strokeColor}
                      strokeWidth={isEdgeSelected || isEdgeHighlighted ? 2.5 : isCrossDomain ? 1.8 : 1.2}
                      strokeDasharray={isCrossDomain ? '5,4' : 'none'}
                      markerEnd={markerId}
                      opacity={
                        selectedNode || hoveredNodeId
                          ? isEdgeHighlighted || isEdgeSelected
                            ? 1
                            : 0.15
                          : 0.85
                      }
                      className="transition-colors duration-150"
                    />
                    {/* Invisible wide stroke for easy clicking */}
                    <path
                      d={pathData}
                      fill="none"
                      stroke="transparent"
                      strokeWidth={16}
                    />
                  </g>
                );
              })}

              {/* Nodes */}
              {filteredNodes.map((node) => {
                const pos = nodePositions[node.id];
                if (!pos) return null;

                const isSelected = selectedNode?.id === node.id;
                const isHovered = hoveredNodeId === node.id;
                const isConnected = connectedInfo.nodeIds.has(node.id);
                const isDimmed = (selectedNode || hoveredNodeId) && !isSelected && !isConnected && !isHovered;

                const color = getNodeColor(node);
                const iconText = getNodeIcon(node);
                const nodeType = getNodeType(node);

                return (
                  <g
                    key={node.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    className="cursor-pointer"
                    opacity={isDimmed ? 0.25 : 1}
                    onMouseEnter={() => setHoveredNodeId(node.id)}
                    onMouseLeave={() => setHoveredNodeId(null)}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNode(node);
                      setSelectedEdge(null);
                    }}
                  >
                    {/* Highlight Ring */}
                    {(isSelected || isHovered) && (
                      <circle
                        r={24}
                        fill="none"
                        stroke={color}
                        strokeWidth={2}
                        strokeDasharray="4,3"
                        className="animate-pulse"
                      />
                    )}

                    {/* Node Outer Circle */}
                    <circle
                      r={15}
                      fill="#090d16"
                      stroke={color}
                      strokeWidth={isSelected ? 3 : isConnected ? 2.5 : 1.8}
                    />

                    {/* Node Category Text inside badge */}
                    <text
                      y={3.5}
                      textAnchor="middle"
                      fill={color}
                      fontSize={8}
                      fontWeight="bold"
                      fontFamily="monospace"
                      className="select-none pointer-events-none"
                    >
                      {iconText}
                    </text>

                    {/* Node Label */}
                    <text
                      y={25}
                      textAnchor="middle"
                      fill={isSelected ? '#f8fafc' : '#cbd5e1'}
                      fontSize={9.5}
                      fontWeight={isSelected ? 'bold' : 'normal'}
                      fontFamily="monospace"
                      className="select-none pointer-events-none drop-shadow"
                    >
                      {node.label.length > 20 ? node.label.slice(0, 18) + '…' : node.label}
                    </text>

                    {/* Node Type Subtitle */}
                    <text
                      y={36}
                      textAnchor="middle"
                      fill="#64748b"
                      fontSize={7.5}
                      fontFamily="monospace"
                      className="select-none pointer-events-none"
                    >
                      {nodeType}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Canvas Bottom Legend */}
          <div className="absolute bottom-2.5 left-3 right-3 flex flex-wrap items-center justify-between gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-slate-400 backdrop-blur-sm pointer-events-none">
            <div className="flex items-center gap-3">
              <span className="text-slate-500 font-bold uppercase text-[10px]">LEGEND:</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-teal-400 inline-block" /> System</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" /> Process</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-blue-500 inline-block" /> Socket</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-purple-500 inline-block" /> DNS</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400 inline-block" /> Wallet</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-pink-500 inline-block" /> Tx</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" /> VASP</span>
            </div>
            <span className="text-[10px] text-slate-500">
              Drag to pan &bull; Scroll to zoom &bull; Click to inspect
            </span>
          </div>
        </div>

        {/* Details Inspector Panel */}
        <div className="lg:col-span-4 p-5 rounded-xl border border-slate-800 bg-slate-900/60 flex flex-col justify-between space-y-4">
          {selectedNode ? (
            <div className="space-y-4 font-mono text-xs">
              <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] text-cyan-400 uppercase tracking-wider block">SELECTED NODE</span>
                  <h3 className="text-sm font-bold text-slate-100 mt-0.5 break-all">{selectedNode.label}</h3>
                  <span className="text-[11px] text-slate-400">{getNodeType(selectedNode)}</span>
                </div>
                <div
                  className="w-3.5 h-3.5 rounded-full mt-1 shrink-0 shadow-lg"
                  style={{ backgroundColor: getNodeColor(selectedNode) }}
                />
              </div>

              <div className="space-y-2">
                <div className="text-slate-500 text-[10px]">NODE IDENTIFIER</div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 break-all text-[11px]">
                  {selectedNode.id}
                </div>

                {selectedNode.evidence_id && (
                  <>
                    <div className="text-slate-500 text-[10px] mt-2">LINKED EVIDENCE ID</div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-cyan-400 text-[11px] break-all">
                      {selectedNode.evidence_id}
                    </div>
                  </>
                )}

                <div className="grid grid-cols-2 gap-2 mt-2">
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">TYPE / DOMAIN</span>
                    <span className="text-slate-300 font-bold">{selectedNode.domain || getNodeType(selectedNode)}</span>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">CONFIDENCE</span>
                    <span className="text-emerald-400 font-bold">{((selectedNode.confidence ?? 1.0) * 100).toFixed(0)}%</span>
                  </div>
                </div>

                {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                  <div className="mt-2">
                    <span className="text-[10px] text-slate-500 block mb-1">FORENSIC METADATA</span>
                    <pre className="p-2 rounded bg-slate-950 border border-slate-800 text-[10px] overflow-x-auto text-slate-400 max-h-44">
                      {JSON.stringify(selectedNode.metadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          ) : selectedEdge ? (
            <div className="space-y-4 font-mono text-xs">
              <div className="border-b border-slate-800 pb-3">
                <span className="text-[10px] text-indigo-400 uppercase tracking-wider block">SELECTED RELATIONSHIP</span>
                <h3 className="text-sm font-bold text-slate-100 mt-0.5">
                  {selectedEdge.relationship_type || selectedEdge.type || selectedEdge.label || 'RELATIONSHIP'}
                </h3>
                <span className="text-[11px] text-slate-400">
                  {selectedEdge.is_cross_domain ? 'Cross-Domain Correlated Edge' : 'Grounded Observation Edge'}
                </span>
              </div>

              <div className="space-y-2">
                <div className="text-slate-500 text-[10px]">SOURCE &rarr; TARGET</div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 text-[11px] break-all">
                  {selectedEdge.source_id || selectedEdge.source} &rarr; {selectedEdge.target_id || selectedEdge.target}
                </div>

                <div className="grid grid-cols-2 gap-2 mt-2">
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">CONFIDENCE</span>
                    <span className="text-emerald-400 font-bold">{((selectedEdge.confidence ?? 1.0) * 100).toFixed(0)}%</span>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">LABEL</span>
                    <span className="text-slate-300">{selectedEdge.label || selectedEdge.relationship_type || selectedEdge.type || 'N/A'}</span>
                  </div>
                </div>

                {selectedEdge.correlation_id && (
                  <div className="mt-2">
                    <span className="text-[10px] text-slate-500 block">CORRELATION FINDING ID</span>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-indigo-400 mt-0.5 break-all text-[11px]">
                      {selectedEdge.correlation_id}
                    </div>
                  </div>
                )}

                {selectedEdge.evidence_ids && selectedEdge.evidence_ids.length > 0 && (
                  <div className="mt-2">
                    <span className="text-[10px] text-slate-500 block">GROUNDED EVIDENCE PAIR</span>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-cyan-400 mt-0.5 space-y-1 text-[11px]">
                      {selectedEdge.evidence_ids.map((eid) => (
                        <div key={eid} className="break-all">{eid}</div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedEdge.metadata && Object.keys(selectedEdge.metadata).length > 0 && (
                  <div className="mt-2">
                    <span className="text-[10px] text-slate-500 block mb-1">METADATA &amp; EXPLAINABILITY</span>
                    <pre className="p-2 rounded bg-slate-950 border border-slate-800 text-[10px] overflow-x-auto text-slate-400 max-h-40">
                      {JSON.stringify(selectedEdge.metadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-20 text-slate-500 font-mono text-xs space-y-2">
              <Info className="w-6 h-6 text-slate-600 mx-auto" />
              <div>Select any node or connecting edge in the attack chain to inspect forensic explainability attributes.</div>
            </div>
          )}

          <div className="pt-3 border-t border-slate-800/80 text-[11px] text-slate-500 font-mono flex justify-between items-center">
            <span>Graph Renderer: SVG Flow Engine</span>
            <span className="text-slate-600">Phase 9 Grounded</span>
          </div>
        </div>
      </div>
    </div>
  );
};
