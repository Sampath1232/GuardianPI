/// Guardian Pi — Devices Screen
import 'package:flutter/material.dart';

class DevicesScreen extends StatelessWidget {
  const DevicesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final devices = [
      {'name': 'WS-001', 'os': 'Windows 11', 'status': 'online', 'cpu': 45, 'ram': 72},
      {'name': 'PI-003', 'os': 'Raspberry Pi OS', 'status': 'online', 'cpu': 23, 'ram': 58},
      {'name': 'SRV-002', 'os': 'Ubuntu 24.04', 'status': 'online', 'cpu': 67, 'ram': 81},
      {'name': 'MAC-001', 'os': 'macOS Ventura', 'status': 'online', 'cpu': 12, 'ram': 45},
      {'name': 'WS-005', 'os': 'Windows 10', 'status': 'offline', 'cpu': 0, 'ram': 0},
      {'name': 'DRD-001', 'os': 'Android 14', 'status': 'online', 'cpu': 8, 'ram': 52},
    ];

    return Scaffold(
      appBar: AppBar(title: const Text('Device Inventory')),
      body: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: devices.length,
        itemBuilder: (_, i) {
          final d = devices[i];
          final isOnline = d['status'] == 'online';
          return Card(
            margin: const EdgeInsets.only(bottom: 12),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                  Text(d['name'] as String, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
                  Chip(
                    label: Text(d['status'] as String, style: TextStyle(fontSize: 11, color: isOnline ? const Color(0xFF10B981) : Colors.grey)),
                    backgroundColor: (isOnline ? const Color(0xFF10B981) : Colors.grey).withOpacity(0.15),
                    side: BorderSide.none, padding: EdgeInsets.zero,
                  ),
                ]),
                Text(d['os'] as String, style: Theme.of(context).textTheme.bodyMedium),
                if (isOnline) ...[
                  const SizedBox(height: 12),
                  _MetricBar(label: 'CPU', value: d['cpu'] as int),
                  const SizedBox(height: 8),
                  _MetricBar(label: 'RAM', value: d['ram'] as int),
                ],
              ]),
            ),
          );
        },
      ),
    );
  }
}

class _MetricBar extends StatelessWidget {
  final String label;
  final int value;
  const _MetricBar({required this.label, required this.value});

  Color get _color => value > 80 ? const Color(0xFFEF4444) : value > 60 ? const Color(0xFFF59E0B) : const Color(0xFF3B82F6);

  @override
  Widget build(BuildContext context) {
    return Row(children: [
      SizedBox(width: 32, child: Text('$label:', style: const TextStyle(fontSize: 12))),
      Expanded(child: LinearProgressIndicator(value: value / 100, backgroundColor: const Color(0xFF2A3150), valueColor: AlwaysStoppedAnimation(_color))),
      const SizedBox(width: 8),
      Text('$value%', style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600)),
    ]);
  }
}
