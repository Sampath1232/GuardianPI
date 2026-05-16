/// Guardian Pi — Dashboard Screen (Real-time security overview)
import 'package:flutter/material.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Security Dashboard'),
        actions: [
          IconButton(icon: const Icon(Icons.notifications), onPressed: () {}),
          IconButton(icon: const Icon(Icons.refresh), onPressed: () {}),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Security Posture
            _PostureCard(),
            const SizedBox(height: 16),
            // Stat cards
            Row(children: [
              Expanded(child: _StatCard(title: 'Devices', value: '12', icon: Icons.devices, color: const Color(0xFF3B82F6))),
              const SizedBox(width: 12),
              Expanded(child: _StatCard(title: 'Alerts', value: '7', icon: Icons.warning, color: const Color(0xFFEF4444))),
            ]),
            const SizedBox(height: 12),
            Row(children: [
              Expanded(child: _StatCard(title: 'Blocked', value: '143', icon: Icons.shield, color: const Color(0xFF10B981))),
              const SizedBox(width: 12),
              Expanded(child: _StatCard(title: 'Uptime', value: '99.9%', icon: Icons.timer, color: const Color(0xFF8B5CF6))),
            ]),
            const SizedBox(height: 24),
            Text('Recent Alerts', style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 12),
            _AlertTile(severity: 'critical', title: 'Suspicious process: mimikatz.exe', device: 'WS-001', time: '2 min'),
            _AlertTile(severity: 'high', title: 'File integrity change: /etc/shadow', device: 'PI-003', time: '15 min'),
            _AlertTile(severity: 'medium', title: 'Connection spike detected', device: 'SRV-002', time: '1 hr'),
          ],
        ),
      ),
    );
  }
}

class _PostureCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            SizedBox(
              width: 80, height: 80,
              child: Stack(alignment: Alignment.center, children: [
                CircularProgressIndicator(
                  value: 0.85, strokeWidth: 8,
                  backgroundColor: const Color(0xFF2A3150),
                  valueColor: const AlwaysStoppedAnimation(Color(0xFF10B981)),
                ),
                const Text('85', style: TextStyle(fontSize: 24, fontWeight: FontWeight.w800)),
              ]),
            ),
            const SizedBox(width: 20),
            Expanded(child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Security Posture', style: Theme.of(context).textTheme.bodyLarge),
                const SizedBox(height: 4),
                const Text('✓ Healthy — All systems operational', style: TextStyle(color: Color(0xFF10B981), fontSize: 13)),
              ],
            )),
          ],
        ),
      ),
    );
  }
}

class _StatCard extends StatelessWidget {
  final String title, value;
  final IconData icon;
  final Color color;
  const _StatCard({required this.title, required this.value, required this.icon, required this.color});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(icon, color: color, size: 24),
          const SizedBox(height: 12),
          Text(value, style: const TextStyle(fontSize: 28, fontWeight: FontWeight.w800)),
          Text(title, style: Theme.of(context).textTheme.bodyMedium),
        ]),
      ),
    );
  }
}

class _AlertTile extends StatelessWidget {
  final String severity, title, device, time;
  const _AlertTile({required this.severity, required this.title, required this.device, required this.time});

  Color get _color => severity == 'critical' ? const Color(0xFFEF4444)
      : severity == 'high' ? const Color(0xFFF59E0B)
      : const Color(0xFF3B82F6);

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        leading: Container(
          width: 4, height: 40,
          decoration: BoxDecoration(color: _color, borderRadius: BorderRadius.circular(2)),
        ),
        title: Text(title, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
        subtitle: Text('$device • $time ago', style: const TextStyle(fontSize: 12)),
        trailing: Chip(
          label: Text(severity.toUpperCase(), style: TextStyle(fontSize: 10, color: _color, fontWeight: FontWeight.w700)),
          backgroundColor: _color.withOpacity(0.15),
          side: BorderSide.none,
          padding: const EdgeInsets.symmetric(horizontal: 4),
        ),
      ),
    );
  }
}
