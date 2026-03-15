/**
 * theme.ts — pyhall CLI color theme
 *
 * Blue/white brand palette matching pyhall.dev
 */

import chalk from 'chalk';

export const theme = {
  /** Primary brand blue — headers, IDs, panel borders */
  primary: chalk.hex('#0050D4'),
  /** Light blue — subheadings, section labels */
  subheading: chalk.hex('#0078D4'),
  /** Success green — allowed decisions */
  success: chalk.hex('#107C10'),
  /** Error red — denied decisions, errors */
  error: chalk.hex('#D13438'),
  /** Warning orange — warnings, medium risk */
  warning: chalk.hex('#FF8C00'),
  /** Dim — metadata, timestamps, secondary info */
  dim: chalk.dim,
  /** Bold white — emphasis */
  bold: chalk.bold,
  /** Plain white */
  plain: chalk.white,
};

export const BANNER = `
  ${theme.primary.bold('██████╗ ██╗   ██╗██╗  ██╗ █████╗ ██╗     ██╗')}
  ${theme.primary.bold('██╔══██╗╚██╗ ██╔╝██║  ██║██╔══██╗██║     ██║')}
  ${theme.primary.bold('██████╔╝ ╚████╔╝ ███████║███████║██║     ██║')}
  ${theme.primary.bold('██╔═══╝   ╚██╔╝  ██╔══██║██╔══██║██║     ██║')}
  ${theme.primary.bold('██║        ██║   ██║  ██║██║  ██║███████╗███████╗')}
  ${theme.primary.bold('╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝')}
`;
