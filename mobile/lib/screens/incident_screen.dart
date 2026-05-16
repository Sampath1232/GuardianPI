/// Guardian Pi — Incident Investigation Screen
import 'package:flutter/material.dart';

class IncidentScreen extends StatelessWidget {
  const IncidentScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Investigations')),
      floatingActionButton: FloatingActionButton(
        onPressed: () {},
        child: const Icon(Icons.add),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: const [
          _InvestigationCard(title: 'Mimikatz detection on WS-001', status: 'in_progress', priority: 'critical', assignee: 'analyst@guardian.io'),
          _InvestigationCard(title: 'Unusual outbound traffic from SRV-002', status: 'open', priority: 'high', assignee: null),
          _InvestigationCard(title: 'Brute force attempt on SSH', status: 'closed', priority: 'medium', assignee: 'admin@guardian.io'),
        ],
      ),
    );
  }
}

class _InvestigationCard extends StatelessWidget {
  final String title, status, priority;
  final String? assignee;
  const _InvestigationCard({required this.title, required this.status, required this.priority, this.assignee});

  Color get _statusColor => status == 'in_progress' ? const Color(0xFF3B82F6) : status == 'open' ? const Color(0xFFF59E0B) : const Color(0xFF10B981);
  Color get _priorityColor => priority == 'critical' ? const Color(0xFFEF4444) : priority == 'high' ? const Color(0xFFF59E0B) : const Color(0xFF3B82F6);

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Chip(label: Text(priority.toUpperCase(), style: TextStyle(fontSize: 10, color: _priorityColor, fontWeight: FontWeight.w700)), backgroundColor: _priorityColor.withOpacity(0.15), side: BorderSide.none, padding: EdgeInsets.zero),
            const SizedBox(width: 8),
            Chip(label: Text(status.replaceAll('_', ' '), style: TextStyle(fontSize: 10, color: _statusColor)), backgroundColor: _statusColor.withOpacity(0.15), side: BorderSide.none, padding: EdgeInsets.zero),
          ]),
          const SizedBox(height: 8),
          Text(title, style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
          if (assignee != null) ...[
            const SizedBox(height: 4),
            Text('Assigned: $assignee', style: Theme.of(context).textTheme.bodyMedium),
          ],
        ]),
      ),
    );
  }
}
