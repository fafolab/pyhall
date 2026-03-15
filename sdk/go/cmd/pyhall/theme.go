package main

import "github.com/charmbracelet/lipgloss"

var (
	primaryBlue   = lipgloss.NewStyle().Foreground(lipgloss.Color("#0050D4")).Bold(true)
	lightBlue     = lipgloss.NewStyle().Foreground(lipgloss.Color("#0078D4"))
	successGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("#107C10"))
	errorRed      = lipgloss.NewStyle().Foreground(lipgloss.Color("#D13438"))
	warningOrange = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8C00"))
	dimStyle      = lipgloss.NewStyle().Faint(true)
	headerStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#0050D4")).Bold(true).Underline(true)
)
