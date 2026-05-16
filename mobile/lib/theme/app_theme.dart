/// Guardian Pi — App Theme (Dark Mode)
import 'package:flutter/material.dart';

class AppTheme {
  static const _primaryColor = Color(0xFF3B82F6);
  static const _bgPrimary = Color(0xFF0A0E1A);
  static const _bgSecondary = Color(0xFF111827);
  static const _bgCard = Color(0xFF1A1F35);
  static const _textPrimary = Color(0xFFF1F5F9);
  static const _textSecondary = Color(0xFF94A3B8);
  static const _accentGreen = Color(0xFF10B981);
  static const _accentRed = Color(0xFFEF4444);

  static final darkTheme = ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: _bgPrimary,
    colorScheme: ColorScheme.dark(
      primary: _primaryColor,
      surface: _bgSecondary,
      error: _accentRed,
    ),
    cardTheme: CardTheme(
      color: _bgCard,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: Color(0xFF2A3150)),
      ),
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: _bgSecondary,
      foregroundColor: _textPrimary,
      elevation: 0,
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: _bgSecondary,
      indicatorColor: _primaryColor.withOpacity(0.15),
    ),
    textTheme: const TextTheme(
      headlineLarge: TextStyle(color: _textPrimary, fontWeight: FontWeight.w800),
      headlineMedium: TextStyle(color: _textPrimary, fontWeight: FontWeight.w700),
      bodyLarge: TextStyle(color: _textPrimary),
      bodyMedium: TextStyle(color: _textSecondary),
    ),
  );
}
