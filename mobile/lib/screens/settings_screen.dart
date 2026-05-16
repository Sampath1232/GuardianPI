/// Guardian Pi — Settings Screen
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../services/auth_service.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(child: Column(children: [
            ListTile(leading: const Icon(Icons.person), title: const Text('Account'), subtitle: const Text('admin@guardian.io'), trailing: const Icon(Icons.chevron_right)),
            const Divider(height: 1),
            ListTile(leading: const Icon(Icons.fingerprint), title: const Text('Biometric Login'), trailing: Switch(value: true, onChanged: (_) {})),
            const Divider(height: 1),
            ListTile(leading: const Icon(Icons.notifications), title: const Text('Push Notifications'), trailing: Switch(value: true, onChanged: (_) {})),
          ])),
          const SizedBox(height: 16),
          Card(child: Column(children: [
            const ListTile(leading: Icon(Icons.server), title: Text('Server'), subtitle: Text('api.guardianpi.io')),
            const Divider(height: 1),
            const ListTile(leading: Icon(Icons.info), title: Text('Version'), subtitle: Text('Guardian Pi Mobile v2.0.0')),
          ])),
          const SizedBox(height: 24),
          ElevatedButton.icon(
            onPressed: () async {
              await ref.read(authServiceProvider).logout();
              if (context.mounted) context.go('/login');
            },
            icon: const Icon(Icons.logout, color: Colors.red),
            label: const Text('Sign Out', style: TextStyle(color: Colors.red)),
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFEF4444).withOpacity(0.15)),
          ),
        ],
      ),
    );
  }
}
