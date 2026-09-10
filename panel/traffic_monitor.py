#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Жесткий мониторинг трафика: входящий/исходящий из контейнера + через слоты nfqws2
"""

import re
import subprocess
import time
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)


class TrafficMonitor:
    """
    Жесткий мониторинг трафика контейнера и слотов nfqws2
    
    Отвечает на вопросы:
    1. Сколько трафика входит в контейнер? (SOCKS прокси)
    2. Сколько трафика выходит из контейнера?
    3. Сколько из него идет через слоты nfqws2?
    4. Сколько байпасит слоты? (непонятно куда)
    """
    
    def __init__(self, qnum_base=300):
        self.qnum_base = qnum_base
        self._prev_snapshot = None
    
    def _read_proc_net_dev(self):
        """Читать статистику интерфейсов"""
        ifaces = {}
        try:
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()
            for line in lines[2:]:
                parts = line.split(':')
                if len(parts) != 2:
                    continue
                iface = parts[0].strip()
                if iface == 'lo':
                    continue
                fields = parts[1].split()
                if len(fields) >= 16:
                    ifaces[iface] = {
                        'rx_bytes': int(fields[0]),
                        'tx_bytes': int(fields[8]),
                        'rx_pkts': int(fields[1]),
                        'tx_pkts': int(fields[9])
                    }
        except Exception as e:
            logger.error(f"Error reading /proc/net/dev: {e}")
        return ifaces
    
    def _run_ipt(self, *args):
        """Выполнить iptables"""
        try:
            r = subprocess.run(['iptables'] + list(args),
                             capture_output=True, text=True, timeout=5)
            return r.stdout
        except Exception as e:
            logger.error(f"iptables error: {e}")
            return ""
    
    def _get_postrouting_total(self):
        """Весь исходящий трафик"""
        out = self._run_ipt('-t', 'mangle', '-L', 'POSTROUTING', '-v', '-x', '-n')
        pkts, bytes = 0, 0
        for line in out.split('\n'):
            m = re.search(r'^\s*(\d+)\s+(\d+)', line)
            if m:
                p, b = int(m.group(1)), int(m.group(2))
                if p > pkts:
                    pkts, bytes = p, b
        return pkts, bytes
    
    def _get_pool_captured(self):
        """Трафик захваченный в ZAPRET_POOL"""
        out = self._run_ipt('-t', 'mangle', '-L', 'POSTROUTING', '-v', '-x', '-n')
        for line in out.split('\n'):
            if 'ZAPRET_POOL' in line:
                m = re.search(r'^\s*(\d+)\s+(\d+)', line)
                if m:
                    return int(m.group(1)), int(m.group(2))
        return 0, 0
    
    def _get_slots_traffic(self):
        """Трафик через слоты"""
        out = self._run_ipt('-t', 'mangle', '-L', 'ZAPRET_POOL', '-v', '-x', '-n')
        slots = []
        for line in out.split('\n'):
            if 'NFQUEUE' in line and 'queue-num' in line:
                qm = re.search(r'queue-num\s+(\d+)', line)
                sm = re.search(r'^\s*(\d+)\s+(\d+)', line)
                if qm and sm:
                    slots.append({
                        'qnum': int(qm.group(1)),
                        'pkts': int(sm.group(1)),
                        'bytes': int(sm.group(2))
                    })
        return slots
    
    def capture(self):
        """Захватить снимок"""
        return {
            'ts': time.time(),
            'ifaces': self._read_proc_net_dev(),
            'postrouting_pkts': self._get_postrouting_total()[0],
            'postrouting_bytes': self._get_postrouting_total()[1],
            'pool_pkts': self._get_pool_captured()[0],
            'pool_bytes': self._get_pool_captured()[1],
            'slots': self._get_slots_traffic()
        }
    
    def analyze(self):
        """ГЛАВНЫЙ МЕТОД: Анализ трафика"""
        snap = self.capture()
        
        # Суммы
        total_tx = sum(s['tx_bytes'] for s in snap['ifaces'].values())
        slots_bytes = sum(s['bytes'] for s in snap['slots'])
        
        # Bypass
        not_captured = snap['postrouting_bytes'] - snap['pool_bytes']
        captured_not_slotted = snap['pool_bytes'] - slots_bytes
        
        verdict = []
        if snap['postrouting_bytes'] > 0:
            pct = (slots_bytes / snap['postrouting_bytes'] * 100)
            if pct > 95:
                verdict.append(f"✅ {pct:.1f}% через слоты")
            elif pct > 50:
                verdict.append(f"⚠️ {pct:.1f}% через слоты, {100-pct:.1f}% байпас")
            else:
                verdict.append(f"🔴 ПРОБЛЕМА: {pct:.1f}% через слоты!")
            
            if not_captured > 0:
                verdict.append(f"  • {round(not_captured/1024/1024,2)} MB не попало в ZAPRET_POOL")
            if captured_not_slotted > 0:
                verdict.append(f"  • {round(captured_not_slotted/1024/1024,2)} MB в POOL но мимо слотов")
        
        return {
            'container_out_mb': round(total_tx/1024/1024, 2),
            'through_slots_mb': round(slots_bytes/1024/1024, 2),
            'bypassed_mb': round((not_captured + captured_not_slotted)/1024/1024, 2),
            'coverage_pct': round((slots_bytes / snap['postrouting_bytes'] * 100) if snap['postrouting_bytes'] > 0 else 0, 2),
            'slots': [{'qnum': s['qnum'], 'mb': round(s['bytes']/1024/1024, 2)} for s in snap['slots']],
            'verdict': verdict
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    m = TrafficMonitor()
    a = m.analyze()
    print("=" * 60)
    for k, v in a.items():
        if k == 'verdict':
            print("ВЕРДИКТ:")
            for line in v:
                print(f"  {line}")
        else:
            print(f"{k}: {v}")
