
import React from 'react';
import { Severity } from '../../types.ts';

interface BadgeProps {
  severity: Severity;
}

export const SeverityBadge: React.FC<BadgeProps> = ({ severity }) => {
  const colors = {
    [Severity.LOW]: 'bg-blue-900/30 text-blue-400 border-blue-500/50',
    [Severity.MEDIUM]: 'bg-yellow-900/30 text-yellow-400 border-yellow-500/50',
    [Severity.HIGH]: 'bg-orange-900/30 text-orange-400 border-orange-500/50',
    [Severity.CRITICAL]: 'bg-red-900/30 text-red-400 border-red-500/50',
  };

  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${colors[severity]}`}>
      {severity}
    </span>
  );
};
