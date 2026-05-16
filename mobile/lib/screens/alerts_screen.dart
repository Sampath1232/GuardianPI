/// Guardian Pi — Alerts Screen
import 'package:flutter/material.dart';

class AlertsScreen extends StatelessWidget {
  const AlertsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Alert Center')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: const [
          _AlertCard(severity: 'critical', title: 'Suspicious process: mimikatz.exe', device: 'WS-001', time: '2 min ago', category: 'Malware'),
          _AlertCard(severity: 'critical', title: 'Debugger attached to agent', device: 'SRV-002', time: '8 min ago', category: 'Tamper'),
          _AlertCard(severity: 'high', title: 'File integrity: /etc/shadow', device: 'PI-003', time: '15 min ago', category: 'Integrity'),
          _AlertCard(severity: 'high', title: 'Brute-force tool: hydra', device: 'SRV-002', time: '32 min ago', category: 'Intrusion'),
          _AlertCard(severity: 'medium', title: 'Connection spike: 250', device: 'SRV-002', time: '1 hr ago', category: 'Anomaly'),
          _AlertCard(severity: 'low', title: 'Agent updated to v2.0', device: 'MAC-001', time: '6 hr ago', category: 'System'),
        ],
      ),
    );
  }
}

class _AlertCard extends StatelessWidget {
  final String severity, title, device, time, category;
  const _AlertCard({required this.severity, required this.title, required this.device, required this.time, required this.category});

  Color get _color => severity == 'critical' ? const Color(0xFFEF4444) : severity == 'high' ? const Color(0xFFF59E0B) : severity == 'medium' ? const Color(0xFF3B82F6) : const Color(0xFF10B981);

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: CircleAvatar(backgroundColor: _color.withOpacity(0.15), child: Icon(Icons.warning, color: _color, size: 20)),
        title: Text(title, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
        subtitle: Text('$device • $category • $time'),
        trailing: PopupMenuButton(itemBuilder: (_) => [
          const PopupMenuItem(value: 'ack', child: Text('Acknowledge')),
          const PopupMenuItem(value: 'investigate', child: Text('Investigate')),
        ]),
      ),
    );
  }
}
